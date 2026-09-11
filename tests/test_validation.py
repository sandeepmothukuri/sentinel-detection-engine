#!/usr/bin/env python3
"""The validation ledger is the repository's honesty mechanism.

These tests exist so that the ledger cannot quietly drift away from the rules,
and so that a claim of validation without evidence fails the build rather than
being caught in review.
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from conftest import REPO, all_rules

LEDGER = REPO / "tests" / "validation" / "atomics.yaml"
SCHEMA = REPO / "tests" / "validation" / "validation-schema.yaml"
GENERATED = REPO / "tests" / "atomics.md"
EVIDENCE_DIR = REPO / "tests" / "validation" / "evidence"
ATOMIC_DATA = REPO / "scripts" / "atomic_data.json"
GENERATOR = REPO / "scripts" / "generate_atomics_ledger.py"

STATUSES = {"STATIC VALIDATION", "SIMULATED", "VALIDATED IN LIVE TENANT", "NOT YET VALIDATED"}
ROLES = {"trigger", "precondition", "partial"}


def ledger() -> dict:
    return yaml.safe_load(LEDGER.read_text(encoding="utf-8"))


def entries() -> list[dict]:
    return ledger()["rules"]


def atomic_db() -> dict:
    return json.loads(ATOMIC_DATA.read_text(encoding="utf-8"))


def rule_stems() -> set[str]:
    return {path.stem for path, _ in all_rules()}


# ------------------------------------------------------------------- structure
def test_ledger_document_keys():
    data = ledger()
    for key in ("schema_version", "last_reviewed", "source", "rules"):
        assert data.get(key), f"ledger is missing {key}"
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", str(data["last_reviewed"]))


def test_schema_file_documents_the_status_vocabulary():
    schema = yaml.safe_load(SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["validation_status"]) == STATUSES
    assert set(schema["roles"]) == ROLES
    assert schema["evidence_requirements"]["template"]
    assert schema["rejected_mappings"], "the rejected-mapping list is evidence of review"


def test_one_entry_per_rule_and_no_orphans():
    stems = rule_stems()
    recorded = [e["rule"] for e in entries()]
    assert len(recorded) == len(set(recorded)), "duplicate ledger entries"
    assert set(recorded) == stems, (
        f"missing: {sorted(stems - set(recorded))}, orphaned: {sorted(set(recorded) - stems)}"
    )


def test_every_entry_has_required_keys():
    for entry in entries():
        assert entry.get("rule"), entry
        assert entry.get("status") in STATUSES, entry
        assert entry.get("evidence"), f"{entry['rule']}: no evidence recorded"
        assert "checks" in entry, f"{entry['rule']}: checks key missing"
        assert isinstance(entry["checks"], list), entry["rule"]


def test_techniques_cited_are_declared_by_the_rule():
    rules = {path.stem: data for path, data in all_rules()}
    for entry in entries():
        declared = {str(t) for t in (rules[entry["rule"]].get("relevantTechniques") or [])}
        for check in entry["checks"]:
            assert check["technique"] in declared, (
                f"{entry['rule']}: ledger cites {check['technique']}, which the rule does not declare"
            )


# ------------------------------------------------------------------- atomics
def test_cited_atomics_exist_upstream():
    """Regression: T1218.011-23 and T1114.003-2 were both cited and neither exists."""
    db = atomic_db()
    for entry in entries():
        for check in entry["checks"]:
            technique = check["technique"]
            assert technique in db["techniques"], (
                f"{entry['rule']}: cites {technique}, for which upstream has no atomics"
            )
            valid = [t["index"] for t in db["techniques"][technique]]
            assert check.get("atomic") in valid, (
                f"{entry['rule']}: {technique}-{check.get('atomic')} does not exist upstream "
                f"(valid indices: {valid})"
            )


def test_techniques_without_atomics_are_never_cited():
    db = atomic_db()
    without = set(db["techniques_without_atomics"])
    for entry in entries():
        for check in entry["checks"]:
            assert check["technique"] not in without, (
                f"{entry['rule']}: cites {check['technique']}, which upstream has no atomic for"
            )


def test_partial_mappings_explain_their_gap():
    for entry in entries():
        for check in entry["checks"]:
            if check["role"] == "partial":
                assert len(str(check.get("note", ""))) > 30, (
                    f"{entry['rule']}: {check['technique']} is marked partial without a usable note"
                )


def test_every_rule_can_be_validated_by_someone():
    """A rule with no trigger atomic and no manual procedure is untestable, which
    means nobody can ever move it off STATIC VALIDATION."""
    for entry in entries():
        has_trigger = any(c["role"] == "trigger" for c in entry["checks"])
        assert has_trigger or entry.get("manual_procedure"), (
            f"{entry['rule']}: no trigger atomic and no manual procedure"
        )


def test_manual_procedure_rules_have_a_reason():
    for entry in entries():
        if entry["checks"]:
            continue
        assert len(str(entry.get("notes", ""))) > 60, (
            f"{entry['rule']}: manual-only mapping without an explanation of why no "
            f"atomic validates it"
        )


# ------------------------------------------------------------------- honesty
def test_no_rule_claims_validation_without_an_evidence_file():
    """The core honesty gate: a status above STATIC VALIDATION requires a dated
    evidence file containing real observed output."""
    for entry in entries():
        if entry["status"] in {"SIMULATED", "VALIDATED IN LIVE TENANT"}:
            matches = sorted(EVIDENCE_DIR.glob(f"{entry['rule']}-*.md"))
            assert matches, (
                f"{entry['rule']} claims {entry['status']} but has no evidence file in "
                f"tests/validation/evidence/"
            )
            text = matches[-1].read_text(encoding="utf-8")
            assert re.search(r"\b20\d{2}-\d{2}-\d{2}\b", text), "evidence file has no date"
            assert "Not observed" not in text or "paste here" not in text, (
                "evidence file still contains the template placeholder"
            )


def test_static_validation_entries_do_not_cite_incidents():
    for entry in entries():
        if entry["status"] == "STATIC VALIDATION":
            assert not re.search(r"INC-\d+", str(entry.get("evidence", ""))), (
                f"{entry['rule']}: static status but the evidence cites an incident number"
            )


def test_status_summary_matches_reality():
    """If every rule is static, the generated ledger must say so explicitly: that
    sentence is what stops a reader assuming the rules have been proven."""
    statuses = {e["status"] for e in entries()}
    text = GENERATED.read_text(encoding="utf-8")
    if statuses == {"STATIC VALIDATION"}:
        assert "has been executed against a live tenant by the author" in text
    else:
        assert "VALIDATED IN LIVE TENANT" in text or "SIMULATED" in text
    assert str(len(entries())) in text


# ------------------------------------------------------------------- generation
def test_generated_ledger_is_current():
    """tests/atomics.md must be exactly what the generator produces."""
    before = GENERATED.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR)], capture_output=True, text=True,
                            cwd=REPO, check=False)
    assert result.returncode == 0, result.stderr
    after = GENERATED.read_text(encoding="utf-8")
    assert before == after, "tests/atomics.md is stale: run scripts/generate_atomics_ledger.py"


def test_generated_ledger_covers_every_rule_with_its_upstream_atomic_name():
    text = GENERATED.read_text(encoding="utf-8")
    db = atomic_db()
    for entry in entries():
        assert f"`{entry['rule']}`" in text, f"{entry['rule']} missing from tests/atomics.md"
        for check in entry["checks"]:
            name = next(t["name"] for t in db["techniques"][check["technique"]]
                        if t["index"] == check["atomic"])
            assert name in text, f"upstream atomic name for {check['technique']}-{check['atomic']} missing"


# ------------------------------------------------------------------- validator
def validate(entry_list: list[dict]) -> list[str]:
    """Run the CI ledger validator against a synthetic ledger."""
    import ci_validate

    monkeypatch_target = ci_validate.load_ledger
    ci_validate.load_ledger = lambda: {"schema_version": "1.0", "last_reviewed": "2026-01-01",
                                       "source": "test", "rules": entry_list}
    try:
        rules = {
            path.stem: {
                "name": data.get("name", ""),
                "techniques": [str(t) for t in (data.get("relevantTechniques") or [])],
                "is_detection": "Hunting Queries" not in path.as_posix(),
            }
            for path, data in all_rules()
        }
        failures = ci_validate.validate_ledger(ci_validate.load_attack_dataset(), atomic_db(), rules)
    finally:
        ci_validate.load_ledger = monkeypatch_target
    return [f"{rel} {e}" for rel, errs in failures for e in errs]


def test_validator_accepts_the_real_ledger():
    assert validate(copy.deepcopy(entries())) == []


def test_validator_rejects_an_unknown_status():
    bad = copy.deepcopy(entries())
    bad[0]["status"] = "PROBABLY FINE"
    assert any("outside the closed vocabulary" in e for e in validate(bad))


def test_validator_rejects_live_claim_without_dated_evidence():
    bad = copy.deepcopy(entries())
    bad[0]["status"] = "VALIDATED IN LIVE TENANT"
    bad[0]["evidence"] = "looks good"
    errors = validate(bad)
    assert any("dated evidence reference" in e for e in errors), errors


def test_validator_rejects_a_nonexistent_atomic():
    bad = copy.deepcopy(entries())
    target = next(e for e in bad if e["checks"])
    target["checks"][0]["atomic"] = 999
    assert any("does not exist upstream" in e for e in validate(bad))


def test_validator_rejects_an_undeclared_technique():
    bad = copy.deepcopy(entries())
    target = next(e for e in bad if e["checks"])
    target["checks"][0]["technique"] = "T1490" if target["checks"][0]["technique"] != "T1490" else "T1486"
    assert any("not declared by this rule" in e for e in validate(bad))


def test_validator_rejects_a_rule_with_no_validation_route():
    bad = copy.deepcopy(entries())
    target = next(e for e in bad if e["checks"])
    target["checks"] = [{"technique": target["checks"][0]["technique"], "role": "precondition"}]
    target.pop("manual_procedure", None)
    assert any("no trigger-role atomic and no manual procedure" in e for e in validate(bad))


def test_validator_rejects_a_missing_entry():
    bad = [e for e in copy.deepcopy(entries())][:-1]
    assert any("no ledger entry" in e for e in validate(bad))


def test_validator_rejects_a_partial_without_a_note():
    bad = copy.deepcopy(entries())
    target = next(e for e in bad if e["checks"])
    target["checks"][0]["role"] = "partial"
    target["checks"][0].pop("note", None)
    assert any("must state what it does not cover" in e for e in validate(bad))
