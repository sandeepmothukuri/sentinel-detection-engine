"""Negative tests: prove the validator, the KQL linter and the Sigma converter
actually reject bad input.

A validator that only passes on the current repository is untested. Every test
here feeds a known defect in and asserts the specific failure comes back out —
so a future refactor that silently stops checking something fails the suite.
"""
from __future__ import annotations

import re

import ci_validate
import pytest
import yaml
from conftest import REPO

ATTACK_DB = ci_validate.load_attack_dataset()

VALID_RULE = """
id: 8a9d3f0c-1b2e-4d6a-9c11-7f4e0c2b8aff
name: Test - A Synthetic Detection For Negative Testing
description: |
  A rule used only by the negative test suite. It must validate cleanly so that
  each test below can introduce exactly one defect and attribute the failure.
severity: High
status: Available
kind: Scheduled
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
relevantTechniques:
  - T1078.004
query: |
  let threshold = 1;
  SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultType == 0
  | summarize Attempts = count() by UserPrincipalName, IPAddress, TimeGenerated
  | where Attempts >= threshold
  | project TimeGenerated, UserPrincipalName, IPAddress, Attempts
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false
    lookbackDuration: PT5H
    matchingMethod: Selected
    groupByEntities:
      - Account
eventGroupingSettings:
  aggregationKind: SingleAlert
alertDetailsOverride:
  alertDisplayNameFormat: Sign-in anomaly for {{UserPrincipalName}}
  alertDescriptionFormat: Activity from {{IPAddress}} in the review window.
metadata:
  author: Sandeep Mothukuri
  validationStatus: static-validation
  testMapping: tests/atomics.md
  telemetryDependency: SigninLogs via the Entra ID connector.
  falsePositives: |
    Nothing in this rule is real; it is fixture text long enough to satisfy the
    quality bar that the validator enforces on false-positive analysis.
  tuningGuidance: |
    Fixture text long enough to satisfy the tuning-guidance quality bar, naming
    the threshold an analyst would change.
  suppression: No static suppression.
  expectedVolume: Not applicable; test fixture.
version: 1.0.0
"""


def write_rule(tmp_path, text: str):
    path = tmp_path / "Test_Rule.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def errors_for(tmp_path, text: str) -> list[str]:
    path = write_rule(tmp_path, text)
    errs, _ = ci_validate.validate_file(path, True, ATTACK_DB)
    return errs


def assert_error(errs: list[str], field: str, fragment: str) -> None:
    joined = "\n".join(errs)
    assert any(field in e and fragment.lower() in e.lower() for e in errs), (
        f"expected an error on {field!r} mentioning {fragment!r}; got:\n{joined}"
    )


def test_fixture_is_valid_to_begin_with(tmp_path):
    """Guard: if the fixture itself is broken every negative test is meaningless."""
    assert errors_for(tmp_path, VALID_RULE) == []


def test_rejects_missing_kind(tmp_path):
    text = VALID_RULE.replace("kind: Scheduled\n", "")
    assert_error(errors_for(tmp_path, text), "kind", "Sentinel requires")


def test_rejects_query_period_over_platform_maximum(tmp_path):
    text = VALID_RULE.replace("queryPeriod: 1h", "queryPeriod: 30d")
    assert_error(errors_for(tmp_path, text), "queryPeriod", "exceeds the platform maximum")


def test_rejects_frequency_longer_than_period(tmp_path):
    text = VALID_RULE.replace("queryFrequency: 1h", "queryFrequency: 4h")
    assert_error(errors_for(tmp_path, text), "queryFrequency", "leaves gaps")


def test_rejects_sub_hourly_frequency_on_long_lookback(tmp_path):
    text = (VALID_RULE.replace("queryPeriod: 1h", "queryPeriod: 14d")
                       .replace("queryFrequency: 1h", "queryFrequency: 30m"))
    assert_error(errors_for(tmp_path, text), "queryFrequency", "too frequent")


def test_rejects_invalid_uuid(tmp_path):
    text = VALID_RULE.replace("8a9d3f0c-1b2e-4d6a-9c11-7f4e0c2b8aff", "not-a-uuid")
    assert_error(errors_for(tmp_path, text), "id", "not a valid UUID")


def test_rejects_unknown_technique(tmp_path):
    text = VALID_RULE.replace("  - T1078.004", "  - T9999.999")
    assert_error(errors_for(tmp_path, text), "relevantTechniques", "does not exist")


def test_rejects_tactic_technique_mismatch(tmp_path):
    text = VALID_RULE.replace("  - InitialAccess\n", "  - Impact\n")
    assert_error(errors_for(tmp_path, text), "tactics", "covers")


def test_rejects_undeclared_connector(tmp_path):
    text = VALID_RULE.replace("connectorId: AzureActiveDirectory", "connectorId: Office365")
    assert_error(errors_for(tmp_path, text), "requiredDataConnectors", "no connector")


def test_rejects_entity_column_not_in_query(tmp_path):
    text = VALID_RULE.replace("columnName: IPAddress", "columnName: SourceIpAddress")
    assert_error(errors_for(tmp_path, text), "columnName", "not produced by the query")


def test_rejects_invalid_entity_identifier(tmp_path):
    text = VALID_RULE.replace("identifier: Address", "identifier: SourceAddress")
    assert_error(errors_for(tmp_path, text), "identifier", "not a valid identifier")


def test_rejects_entity_mapping_of_an_array_column(tmp_path):
    text = VALID_RULE.replace(
        "  | project TimeGenerated, UserPrincipalName, IPAddress, Attempts",
        "  | summarize Attempts = count(), IPs = make_set(IPAddress) by UserPrincipalName, TimeGenerated"
        "\n  | project TimeGenerated, UserPrincipalName, IPs, Attempts",
    ).replace("columnName: IPAddress", "columnName: IPs")
    assert_error(errors_for(tmp_path, text), "columnName", "cannot entity-map arrays")


def test_rejects_alert_placeholder_not_in_query(tmp_path):
    text = VALID_RULE.replace("{{IPAddress}}", "{{SourceGeo}}")
    assert_error(errors_for(tmp_path, text), "alertDetailsOverride", "not a column")


def test_rejects_missing_tuning_metadata(tmp_path):
    text = re.sub(r"  tuningGuidance: \|.*?(?=  suppression:)", "", VALID_RULE, flags=re.S)
    assert_error(errors_for(tmp_path, text), "metadata", "tuningGuidance")


def test_rejects_thin_false_positive_analysis(tmp_path):
    text = VALID_RULE.replace(
        """  falsePositives: |
    Nothing in this rule is real; it is fixture text long enough to satisfy the
    quality bar that the validator enforces on false-positive analysis.""",
        "  falsePositives: few",
    )
    assert_error(errors_for(tmp_path, text), "falsePositives", "too thin")


def test_rejects_ai_or_role_author_attribution(tmp_path):
    for bad in ("Claude", "AI <ai@example.com>", "copilot"):
        text = VALID_RULE.replace("author: Sandeep Mothukuri", f"author: {bad}")
        assert_error(errors_for(tmp_path, text), "author", "not an individual")


def test_rejects_invalid_version(tmp_path):
    text = VALID_RULE.replace("version: 1.0.0", "version: v1")
    assert_error(errors_for(tmp_path, text), "version", "not a semantic version")


def test_rejects_missing_query_time_bound(tmp_path):
    text = VALID_RULE.replace("  | where TimeGenerated > ago(1h)\n", "")
    assert_error(errors_for(tmp_path, text), "query", "ago(")


def test_rejects_now_in_a_scheduled_rule(tmp_path):
    text = VALID_RULE.replace("ago(1h)", "ago(1h) and TimeGenerated < now()")
    assert_error(errors_for(tmp_path, text), "query", "now()")


def test_rejects_invalid_set_operator(tmp_path):
    text = VALID_RULE.replace(
        "  | where ResultType == 0",
        '  | where UserPrincipalName endswith_cs any ("a", "b")',
    )
    assert_error(errors_for(tmp_path, text), "query", "invalid KQL set operator")


def test_rejects_unbalanced_brackets(tmp_path):
    text = VALID_RULE.replace("  | where Attempts >= threshold", "  | where Attempts >= threshold(")
    assert_error(errors_for(tmp_path, text), "query", "unclosed brackets")


def test_rejects_placeholder_text(tmp_path):
    text = VALID_RULE.replace("A Synthetic Detection For Negative Testing",
                              "TODO Detection")
    assert_error(errors_for(tmp_path, text), "content", "placeholder text")


def test_placeholder_scan_does_not_flag_todouble(tmp_path):
    """Regression: a substring scan flagged the KQL function todouble() as TODO."""
    text = VALID_RULE.replace(
        "  | summarize Attempts = count() by UserPrincipalName, IPAddress, TimeGenerated",
        "  | extend Score = todouble(Attempts)\n"
        "  | summarize Attempts = count() by UserPrincipalName, IPAddress, TimeGenerated",
    )
    errs = errors_for(tmp_path, text)
    assert not any("placeholder" in e for e in errs), errs


def test_rejects_invalid_severity(tmp_path):
    text = VALID_RULE.replace("severity: High", "severity: Critical")
    assert_error(errors_for(tmp_path, text), "severity", "not a Sentinel severity")


def test_rejects_error_message_shape(tmp_path):
    """Every error must name the rule, the field, the problem and the expectation
    so that a CI annotation is actionable on its own."""
    errs = errors_for(tmp_path, VALID_RULE.replace("severity: High", "severity: Urgent"))
    assert errs, "expected a failure"
    assert all(e.count("|") >= 3 for e in errs), errs
    assert all("expected:" in e for e in errs), errs


# --------------------------------------------------------------------- ledger
def ledger_failures(monkeypatch, ledger: dict, rules: dict) -> list[str]:
    """Run the ledger validator against a synthetic ledger."""
    monkeypatch.setattr(ci_validate, "load_ledger", lambda: ledger, raising=False)
    failures = ci_validate.validate_ledger(
        ci_validate.load_attack_dataset(), ci_validate.load_atomic_dataset(), rules
    )
    return [e for _, es in failures for e in es]


def test_ledger_rejects_atomic_that_does_not_exist(monkeypatch):
    rules = {"Some_Rule": {"name": "Some Rule", "techniques": ["T1490"], "is_detection": True}}
    ledger = {
        "rules": [{
            "rule": "Some_Rule",
            "status": "STATIC VALIDATION",
            "evidence": "CI schema/KQL/ATT&CK pass",
            "checks": [{"technique": "T1490", "atomic": 99, "role": "trigger"}],
        }]
    }
    errs = ledger_failures(monkeypatch, ledger, rules)
    assert any("does not exist upstream" in e for e in errs), errs


def test_ledger_rejects_atomic_technique_the_rule_does_not_declare(monkeypatch):
    rules = {"Some_Rule": {"name": "Some Rule", "techniques": ["T1490"], "is_detection": True}}
    ledger = {
        "rules": [{
            "rule": "Some_Rule",
            "status": "STATIC VALIDATION",
            "evidence": "CI pass",
            "checks": [{"technique": "T1486", "atomic": 1, "role": "trigger"}],
        }]
    }
    errs = ledger_failures(monkeypatch, ledger, rules)
    assert any("does not declare" in e or "not declared" in e for e in errs), errs


def test_ledger_rejects_status_without_evidence_shape(monkeypatch):
    rules = {"Some_Rule": {"name": "Some Rule", "techniques": ["T1490"], "is_detection": True}}
    ledger = {
        "rules": [{
            "rule": "Some_Rule",
            "status": "VALIDATED IN LIVE TENANT",
            "evidence": "done",
            "checks": [{"technique": "T1490", "atomic": 1, "role": "trigger"}],
        }]
    }
    errs = ledger_failures(monkeypatch, ledger, rules)
    assert any("dated evidence reference" in e for e in errs), errs
    assert any("incident reference" in e for e in errs), errs


def test_ledger_rejects_status_claiming_incident_while_static(monkeypatch):
    rules = {"Some_Rule": {"name": "Some Rule", "techniques": ["T1490"], "is_detection": True}}
    ledger = {
        "rules": [{
            "rule": "Some_Rule",
            "status": "STATIC VALIDATION",
            "evidence": "Confirmed by INC-1042 on 2026-01-01",
            "checks": [{"technique": "T1490", "atomic": 1, "role": "trigger"}],
        }]
    }
    errs = ledger_failures(monkeypatch, ledger, rules)
    assert any("incident" in e.lower() for e in errs), errs


def test_ledger_rejects_rule_with_no_way_to_validate(monkeypatch):
    rules = {"Some_Rule": {"name": "Some Rule", "techniques": ["T1490"], "is_detection": True}}
    ledger = {
        "rules": [{
            "rule": "Some_Rule",
            "status": "STATIC VALIDATION",
            "evidence": "CI pass",
            "checks": [{"technique": "T1490", "atomic": 1, "role": "precondition"}],
        }]
    }
    errs = ledger_failures(monkeypatch, ledger, rules)
    assert any("manual" in e.lower() for e in errs), errs


# ------------------------------------------------------------------ sigma
def test_sigma_converter_never_emits_invalid_set_operators():
    import kql_lint
    from sigma_to_kql import convert

    sigma = {
        "title": "Multi-value suffix selection",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": ["\\a.exe", "\\b.exe", "\\c.exe"],
                          "CommandLine|startswith": ["C:\\Temp", "D:\\Temp"]},
            "condition": "selection",
        },
    }
    out = convert(sigma)
    issues = kql_lint.lint(out)
    assert not issues, f"converter emitted KQL the repo's own linter rejects: {issues}"
    assert "endswith_cs any" not in out
    assert out.count("endswith_cs") == 3
    assert out.count("startswith_cs") == 2


def test_sigma_converter_brackets_multi_value_or_chains():
    from sigma_to_kql import convert

    sigma = {
        "title": "Bracketing",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image|endswith": ["\\a.exe", "\\b.exe"], "User": "SYSTEM"},
            "condition": "selection",
        },
    }
    out = convert(sigma)
    # The OR chain must be bracketed before it is ANDed with the next predicate.
    assert re.search(r"\(.*endswith_cs.*or.*endswith_cs.*\)\s+and\s+AccountName", out), out


def test_sigma_converter_does_not_widen_prefix_to_substring():
    """has_any() is term-based; using it for a prefix match would change semantics."""
    from sigma_to_kql import _render_value

    rendered = _render_value("Image|startswith", ["C:\\Windows", "C:\\Temp"],
                             {"Image": "FolderPath"})
    assert "has_any" not in rendered
    assert "startswith_cs" in rendered
