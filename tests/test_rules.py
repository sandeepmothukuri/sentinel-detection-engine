"""Rule-level tests: schema, uniqueness, ATT&CK, telemetry, metadata, KQL lint.

These run the same validation logic CI uses (scripts/ci_validate.py) so that
`pytest` locally reproduces the GitHub Actions verdict.
"""
from __future__ import annotations

import pytest
import yaml

import ci_validate
from conftest import REPO, all_rules

ATTACK_DB = ci_validate.load_attack_dataset()


def test_all_rules_pass_ci_validation():
    """Single integration assertion: the same check CI runs on every push."""
    for d, is_det in ci_validate.RULE_DIRS:
        for path in sorted(d.glob("*.yaml")):
            errs = ci_validate.validate_file(path, is_det, ATTACK_DB)
            assert not errs, f"{path.relative_to(REPO)}: {errs}"


def test_ids_and_names_unique():
    ids, names = set(), set()
    for path, data in all_rules():
        rid, name = str(data.get("id")), str(data.get("name"))
        assert rid not in ids, f"duplicate id: {rid}"
        assert name not in names, f"duplicate name: {name}"
        ids.add(rid)
        names.add(name)


def test_detection_counts():
    detections = load("Detections")
    hunts = load("Hunting Queries")
    assert len(detections) == 12
    assert len(hunts) == 10


def load(subdir):
    from conftest import load_rules
    return load_rules(subdir)


def test_no_invalid_techniques():
    """Every referenced technique must exist in the vendored ATT&CK dataset."""
    for path, data in all_rules():
        for t in data.get("relevantTechniques") or []:
            assert str(t) in ATTACK_DB, f"{path.name}: technique {t} unknown or deprecated"


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
    for path, data in load("Detections"):
        assert data.get("incidentConfiguration", {}).get("createIncident") is True, path.name
        assert "groupingConfiguration" in data.get("incidentConfiguration", {}), path.name
        assert "aggregationKind" in data.get("eventGroupingSettings", {}), path.name


def test_detections_have_tuning_metadata():
    required = {"validationStatus", "falsePositives", "tuningGuidance", "suppression", "expectedVolume"}
    for path, data in load("Detections"):
        meta = data.get("metadata") or {}
        missing = required - meta.keys()
        assert not missing, f"{path.name}: metadata missing {missing}"


def test_validation_status_is_honest():
    """Only the four documented statuses may be used; nothing may claim live
    tenant validation without evidence recorded in docs/testing.md."""
    allowed = {"static-validation", "simulated", "validated-live-tenant", "not-yet-validated"}
    for path, data in all_rules():
        status = (data.get("metadata") or {}).get("validationStatus") or "not-yet-validated"
        assert status in allowed, f"{path.name}: invalid validationStatus {status!r}"


def test_hunts_have_full_hunt_metadata():
    required = {"hypothesis", "requiredTelemetry", "expectedFindings",
                "investigationSteps", "escalation", "limitations"}
    for path, data in load("Hunting Queries"):
        missing = required - data.keys()
        assert not missing, f"{path.name}: hunt metadata missing {missing}"


def test_no_invalid_set_operators_anywhere():
    """Regression: `endswith_cs any` etc. are not valid KQL."""
    for path, data in all_rules():
        q = (data.get("query") or "").lower()
        for op in ("endswith any", "endswith_cs any", "startswith any",
                   "startswith_cs any", "contains any", "contains_cs any"):
            assert op not in q, f"{path.name}: invalid set operator '{op}'"


def test_inbox_rule_uses_mv_expand_parameters():
    """Regression: Parameters is a dynamic array; naive regex extraction on
    tostring(Parameters) misses values. The query must mv-expand it."""
    for path, data in load("Detections"):
        if path.name == "M365_InboxRuleExfil.yaml":
            q = data["query"]
            assert "mv-expand p = Parameters" in q
            assert "extract(@\"ForwardTo" not in q


def test_no_now_in_scheduled_rules():
    for path, data in load("Detections"):
        q = data["query"]
        assert "now()" not in q, f"{path.name}: now() is unstable in scheduled rules"


def test_entity_mappings_reference_projected_columns():
    """Every entity-mapped column must be present in the query text."""
    for path, data in load("Detections"):
        q = data.get("query") or ""
        for em in data.get("entityMappings") or []:
            for fm in em.get("fieldMappings", []):
                col = fm.get("columnName")
                assert col and col in q, f"{path.name}: entity column {col!r} not found in query"


def test_attack_dataset_integrity():
    assert len(ATTACK_DB) > 600
    assert ATTACK_DB["T1059.001"]["name"] == "PowerShell"
    assert "credential-access" in ATTACK_DB["T1110.003"]["tactics"]


def test_workbook_and_layer_json_parse():
    import json
    json.loads((REPO / "Workbooks" / "L3-Triage-Dashboard.json").read_text(encoding="utf-8"))
    layer = json.loads((REPO / "attack-navigator" / "layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
