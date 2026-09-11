"""Rule-level tests: schema, uniqueness, scheduling, ATT&CK, telemetry,
entity mapping, alert details, and the tuning metadata quality bar.

These run the same validation logic CI uses (scripts/ci_validate.py) so that
`pytest` locally reproduces the GitHub Actions verdict. Register-level checks
live here; tests/test_validation_ledger.py covers the validation ledger and
tests/test_validator_negative.py proves the validator actually rejects bad input.
"""
from __future__ import annotations

import re

import ci_validate
import pytest
import yaml
from conftest import REPO, all_rules, load_rules

ATTACK_DB = ci_validate.load_attack_dataset()
ATOMIC_DB = ci_validate.load_atomic_dataset()

# Counts are asserted so that a rule silently disappearing (or a new one landing
# without its ledger entry) fails loudly. Update these deliberately.
EXPECTED_DETECTIONS = 18
EXPECTED_HUNTS = 10


def test_all_rules_pass_ci_validation():
    """Single integration assertion: the same check CI runs on every push."""
    for d, is_det in ci_validate.RULE_DIRS:
        for path in sorted(d.glob("*.yaml")):
            errs, _ = ci_validate.validate_file(path, is_det, ATTACK_DB)
            assert not errs, f"{path.relative_to(REPO)}: {errs}"


def test_detection_counts():
    assert len(load_rules("Detections")) == EXPECTED_DETECTIONS
    assert len(load_rules("Hunting Queries")) == EXPECTED_HUNTS


def test_ids_and_names_unique():
    ids, names = set(), set()
    for path, data in all_rules():
        rid, name = str(data.get("id")), str(data.get("name"))
        assert rid not in ids, f"duplicate id: {rid} ({path.name})"
        assert name not in names, f"duplicate name: {name} ({path.name})"
        ids.add(rid)
        names.add(name)


def test_detections_declare_kind():
    """`kind` is mandatory on a Sentinel analytics rule; omitting it blocks import."""
    for path, data in load_rules("Detections"):
        assert data.get("kind") == "Scheduled", f"{path.name}: kind is {data.get('kind')!r}"


def test_every_detection_has_an_alert_details_override():
    """Without an override every alert in an incident carries the same verbatim
    rule name, which makes the incident queue unreadable. Each override must
    reference columns the rule actually produces."""
    for path, data in load_rules("Detections"):
        override = data.get("alertDetailsOverride") or {}
        assert override.get("alertDisplayNameFormat"), f"{path.name}: no alertDisplayNameFormat"
        query = data["query"]
        for field in ("alertDisplayNameFormat", "alertDescriptionFormat"):
            text = override.get(field) or ""
            for placeholder in re.findall(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", text):
                assert placeholder in query, (
                    f"{path.name}: {field} placeholder {{{{{placeholder}}}}} is not "
                    f"produced by the query"
                )


def test_scheduling_is_within_platform_limits():
    """Sentinel rejects a queryPeriod above 14d, a frequency above the period,
    and a sub-hourly frequency on a multi-day lookback."""
    for path, data in load_rules("Detections"):
        freq = ci_validate.timespan_to_seconds(data["queryFrequency"])
        period = ci_validate.timespan_to_seconds(data["queryPeriod"])
        assert freq is not None, f"{path.name}: unparsable queryFrequency"
        assert period is not None, f"{path.name}: unparsable queryPeriod"
        assert freq >= 5 * 60, f"{path.name}: queryFrequency below the 5m minimum"
        assert period <= 14 * 24 * 3600, f"{path.name}: queryPeriod exceeds the 14d maximum"
        assert freq <= period, f"{path.name}: queryFrequency longer than queryPeriod"
        if period >= 2 * 24 * 3600:
            assert freq >= 3600, f"{path.name}: sub-hourly frequency on a >=2d lookback"


def test_no_invalid_techniques():
    """Every referenced technique must exist in the vendored ATT&CK dataset."""
    for path, data in all_rules():
        for t in data.get("relevantTechniques") or []:
            assert str(t) in ATTACK_DB, f"{path.name}: technique {t} unknown or deprecated"


def test_tactics_match_technique_phases():
    for path, data in all_rules():
        tactics = {ci_validate.normalize_attack_tactic(t) for t in data.get("tactics") or []}
        covered: set[str] = set()
        for t in data.get("relevantTechniques") or []:
            covered |= {ci_validate.normalize_attack_tactic(x) for x in ATTACK_DB[str(t)]["tactics"]}
        assert tactics & covered, f"{path.name}: none of {sorted(tactics)} map to {sorted(covered)}"


def test_query_tables_match_declared_connectors():
    for path, data in all_rules():
        tables = ci_validate.used_tables(data.get("query") or "")
        assert tables, f"{path.name}: no catalogued table found"
        declared = {c.get("connectorId") for c in data.get("requiredDataConnectors") or []}
        for table in tables:
            connectors, _ = ci_validate.TABLE_CATALOG[table]
            assert declared & set(connectors), (
                f"{path.name}: table {table} needs connector {connectors}, declared {declared}"
            )


def test_detections_declare_incident_and_grouping():
    for path, data in load_rules("Detections"):
        assert data.get("incidentConfiguration", {}).get("createIncident") is True, path.name
        assert "groupingConfiguration" in data.get("incidentConfiguration", {}), path.name
        assert "aggregationKind" in data.get("eventGroupingSettings", {}), path.name


def test_detections_have_tuning_metadata():
    required = {"validationStatus", "falsePositives", "tuningGuidance", "suppression", "expectedVolume"}
    for path, data in load_rules("Detections"):
        meta = data.get("metadata") or {}
        missing = required - meta.keys()
        assert not missing, f"{path.name}: metadata missing {missing}"
        for field in ("falsePositives", "tuningGuidance"):
            assert len(str(meta[field])) > 40, f"{path.name}: metadata.{field} is too thin"


def test_rule_metadata_has_a_human_author():
    """No AI/bot attribution: every rule names the maintaining engineer."""
    for path, data in all_rules():
        author = str((data.get("metadata") or {}).get("author", "")).strip()
        assert author, f"{path.name}: no metadata.author"
        assert not re.search(r"@|claude|gpt|copilot|openai|anthropic|\bai\b", author, re.I), (
            f"{path.name}: author {author!r} is not an individual"
        )


def test_validation_status_is_honest():
    """Rule YAML may only use the documented vocabulary, and a rule cannot claim
    tenant validation from the rule file alone — evidence lives in the ledger."""
    allowed = {"static-validation", "simulated", "validated-live-tenant", "not-yet-validated"}
    for path, data in all_rules():
        status = (data.get("metadata") or {}).get("validationStatus") or "not-yet-validated"
        assert status in allowed, f"{path.name}: invalid validationStatus {status!r}"
        if status in {"validated-live-tenant", "simulated"}:
            assert (data.get("metadata") or {}).get("evidenceReference"), (
                f"{path.name}: claims {status} without metadata.evidenceReference"
            )


def test_hunts_have_full_hunt_metadata():
    required = {"hypothesis", "requiredTelemetry", "expectedFindings",
                "investigationSteps", "escalation", "limitations"}
    for path, data in load_rules("Hunting Queries"):
        missing = required - data.keys()
        assert not missing, f"{path.name}: hunt metadata missing {missing}"


def test_no_invalid_set_operators_anywhere():
    """Regression: `endswith_cs any` etc. are not valid KQL."""
    for path, data in all_rules():
        q = (data.get("query") or "").lower()
        for op in ("endswith any", "endswith_cs any", "startswith any",
                   "startswith_cs any", "contains any", "contains_cs any"):
            assert op not in q, f"{path.name}: invalid set operator '{op}'"


def strip_kql_comments(query: str) -> str:
    """Remove // comments so assertions test the query, not the commentary."""
    return "\n".join(line.split("//", 1)[0] for line in query.splitlines())


def test_inbox_rule_reads_capitalised_parameters():
    """Regression: OfficeActivity.Parameters uses capitalised Name/Value keys.

    Reading p.name / p.value returns null on every row and silently disables the
    rule — it deploys, validates, and can never fire. This test exists because
    that exact defect shipped.
    """
    for path, data in load_rules("Detections"):
        if path.name == "M365_InboxRuleExfil.yaml":
            q = strip_kql_comments(data["query"])
            assert "mv-expand p = Parameters" in q
            assert "tostring(p.Name)" in q and "tostring(p.Value)" in q
            # The lower-case keys are the defect; they must not appear in code.
            assert "p.name" not in q and "p.value" not in q


def test_boolean_numeric_guards_use_isnotnull():
    """Regression: isnotempty() on a todouble() is always false, because a failed
    numeric cast yields null rather than an empty value. Using the wrong guard
    made the impossible-travel rule permanently silent."""
    for path, data in load_rules("Detections"):
        for m in re.finditer(r"isnotempty\s*\(\s*(?:to(?:double|int|long|real|decimal|datetime))\s*\(", data["query"]):
            pytest.fail(f"{path.name}: isnotempty() applied to a numeric cast at "
                        f"offset {m.start()} — use isnotnull()")


def test_array_columns_are_never_entity_mapped():
    """Sentinel cannot entity-map a make_set/make_list column; the mapping is
    dropped and the incident loses the entity."""
    for path, data in load_rules("Detections"):
        arrays = ci_validate.array_valued_columns(data["query"])
        for em in data.get("entityMappings") or []:
            for fm in em.get("fieldMappings", []):
                assert fm.get("columnName") not in arrays, (
                    f"{path.name}: entity column {fm['columnName']!r} is array-valued"
                )


def test_entity_identifiers_are_valid_for_their_type():
    for path, data in load_rules("Detections"):
        for em in data.get("entityMappings") or []:
            etype = em.get("entityType")
            assert etype in ci_validate.ENTITY_IDENTIFIERS, f"{path.name}: bad entity type {etype}"
            for fm in em.get("fieldMappings", []):
                ident = fm.get("identifier")
                assert ident in ci_validate.ENTITY_IDENTIFIERS[etype], (
                    f"{path.name}: {ident!r} is not a valid identifier for {etype}"
                )


def test_no_now_in_scheduled_rules():
    for path, data in load_rules("Detections"):
        assert "now()" not in data["query"], f"{path.name}: now() is unstable in scheduled rules"


def test_queries_are_time_bounded_and_return_timegenerated():
    for path, data in all_rules():
        q = data["query"]
        assert re.search(r"\bago\s*\(", q), f"{path.name}: no explicit ago() time bound"
        assert "TimeGenerated" in q, f"{path.name}: query does not surface TimeGenerated"


def test_entity_mappings_reference_projected_columns():
    """Every entity-mapped column must be present in the query text."""
    for path, data in load_rules("Detections"):
        q = data.get("query") or ""
        for em in data.get("entityMappings") or []:
            for fm in em.get("fieldMappings", []):
                col = fm.get("columnName")
                assert col and col in q, f"{path.name}: entity column {col!r} not found in query"


def test_coverage_document_agrees_with_the_rule_files():
    """coverage.md is generated; these numbers are the ones the README quotes."""
    text = (REPO / "coverage.md").read_text(encoding="utf-8")
    detections = len(load_rules("Detections"))
    hunts = len(load_rules("Hunting Queries"))
    techniques = set()
    for _, data in all_rules():
        techniques |= {str(t) for t in (data.get("relevantTechniques") or [])}
    assert f"**Rules:** {detections} detections + {hunts} hunts" in text
    assert f"**Unique techniques:** {len(techniques)}" in text
    assert "**Tactics covered:** 12 of 14" in text
    # The uncovered tactics must be stated, not omitted.
    assert "| Reconnaissance | none |" in text
    assert "| ResourceDevelopment | none |" in text


def test_attack_dataset_integrity():
    assert len(ATTACK_DB) > 600
    assert ATTACK_DB["T1059.001"]["name"] == "PowerShell"
    assert "credential-access" in ATTACK_DB["T1110.003"]["tactics"]


def test_atomic_dataset_integrity():
    assert ATOMIC_DB["techniques"]["T1218.011"][0]["name"].startswith("Rundll32")
    assert len(ATOMIC_DB["techniques"]["T1490"]) >= 10
    assert "T1686.001" in ATOMIC_DB["techniques_without_atomics"]


def test_workbook_and_layer_json_parse():
    import json

    workbook = json.loads((REPO / "Workbooks" / "L3-Triage-Dashboard.json").read_text(encoding="utf-8"))
    assert workbook["version"] == "Notebook/1.0"
    assert any(i.get("name") == "IncidentKPIs" for i in workbook["items"])

    layer = json.loads((REPO / "attack-navigator" / "layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    # The layer's declared version must match the vendored CTI snapshot, otherwise
    # the tactics rendered in the Navigator come from a different matrix than the
    # one the validator checks techniques against.
    assert layer["versions"]["attack"] == "19", (
        "layer declares an ATT&CK version that does not match scripts/attack_data.json; "
        "v19 retired Defense Evasion into Stealth and Defense Impairment"
    )


def test_workbook_queries_use_real_securityincident_columns():
    """Regression: the workbook referenced CloseReason and Owner.principalName,
    neither of which exists on SecurityIncident, so those panels returned an
    empty result on every workspace.

    The check is deliberately explicit rather than a fuzzy token scan: a bare
    identifier in KQL may legitimately be a query-local alias, so only columns
    known not to exist and dynamic-property paths with a known schema are
    asserted.
    """
    import json

    # Columns this repo previously used that the SecurityIncident table does not
    # expose. Add to this list, never remove from it.
    nonexistent_columns = {
        "CloseReason",       # real field is Classification / ClassificationReason
        "ResolvedBy",        # owner resolution is tracked in Comments/Tasks
        "Resolution",        # real field is Classification
        "RootCause",         # not a SecurityIncident column
        "AlertTitle",        # alerts carry AlertName; incidents carry Title
    }
    # Owner is a dynamic object whose documented properties are these four.
    valid_owner_properties = {"userPrincipalName", "email", "assignedTo", "objectId"}

    workbook = json.loads((REPO / "Workbooks" / "L3-Triage-Dashboard.json").read_text(encoding="utf-8"))
    queries = [i["content"]["query"] for i in workbook["items"]
               if i.get("type") == 3 and "query" in i.get("content", {})]
    assert queries, "workbook has no queries"

    for query in queries:
        code = strip_kql_comments(query)
        for bad in nonexistent_columns:
            assert not re.search(rf"\b{bad}\b", code), (
                f"workbook references {bad}, which does not exist on SecurityIncident"
            )
        for prop in re.findall(r"\bOwner\.([A-Za-z][A-Za-z0-9_]*)", code):
            assert prop in valid_owner_properties, (
                f"workbook reads Owner.{prop}; Owner exposes only "
                f"{sorted(valid_owner_properties)}"
            )


def test_workbook_panels_declare_their_data_source():
    """Every panel must be traceable to a table an analyst can go and query, and
    the connector-backed panels must say which table they read."""
    import json

    workbook = json.loads((REPO / "Workbooks" / "L3-Triage-Dashboard.json").read_text(encoding="utf-8"))
    for item in workbook["items"]:
        content = item.get("content") or {}
        if "query" not in content:
            continue
        query = content["query"]
        assert re.search(r"\b(SecurityIncident|SecurityAlert|union isfuzzy=true)\b", query), (
            f"panel {item.get('name')} does not read a documented table"
        )
        assert content.get("title"), f"panel {item.get('name')} has no title"
