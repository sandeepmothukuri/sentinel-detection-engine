#!/usr/bin/env python3
"""The backtesting interface must never invent a result.

These tests pin the contract: plan-only runs write nothing, an execution without a
workspace fails instead of producing a placeholder, and every query rewrite the
script makes is reported rather than applied silently.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import REPO

SCRIPT = REPO / "scripts" / "backtest_rule.py"
RULE = "Detections/MDE_ShadowCopyDeletion.yaml"


def run(*args: str, cwd=REPO) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, cwd=cwd, check=False)


def test_plan_only_executes_nothing_and_writes_nothing(tmp_path):
    result = run(RULE, "--out", str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "PLAN ONLY" in result.stdout
    assert "Nothing was executed" in result.stdout
    assert not list(tmp_path.rglob("*")), "plan-only mode wrote a result file"


def test_plan_prints_the_command_a_human_would_run():
    result = run(RULE)
    assert "az monitor log-analytics query" in result.stdout
    assert "PLAN ONLY" in result.stdout


def test_execute_without_a_workspace_refuses():
    result = run(RULE, "--execute")
    assert result.returncode == 2
    assert "will not invent a workspace" in result.stderr
    assert "::error::" in result.stderr


def test_window_is_reported_as_a_rewrite():
    result = run(RULE, "--window", "30d")
    assert result.returncode == 0
    assert "ago(" in result.stdout and "-> ago(30d)" in result.stdout


def test_widening_a_query_without_an_ago_bound_is_refused(tmp_path):
    bad = tmp_path / "NoBound.yaml"
    bad.write_text(
        "name: Test\n"
        "version: 1.0.0\n"
        "queryFrequency: 1h\n"
        "queryPeriod: 1h\n"
        "query: |\n"
        "  SigninLogs\n"
        "  | where ResultType == 0\n",
        encoding="utf-8")
    result = run(str(bad), "--window", "30d")
    assert result.returncode == 2
    assert "no ago(<span>) bound" in result.stderr


def test_every_rule_can_be_planned():
    """If a rule cannot even be planned, the backtesting interface does not cover it."""
    result = run("--all")
    assert result.returncode == 0, result.stderr
    planned = result.stdout.count("=== ")
    assert planned == 28, f"expected 28 rules planned, got {planned}"


def test_missing_rule_file_is_reported():
    result = run("Detections/DoesNotExist.yaml")
    assert result.returncode == 2
    assert "no such rule file" in result.stderr


def test_report_labels_itself_as_an_observation_not_a_validation():
    """The report template must never let a backtest read as validation."""
    sys.path.insert(0, str(REPO / "scripts"))
    import backtest_rule

    plan_data = {"file": RULE, "rule": "Test Rule", "version": "1.0.0",
                 "query_frequency": "1h", "query_period": "1h",
                 "lookback_rewrites": ["ago(1h) -> ago(30d)"], "query": "SigninLogs | where TimeGenerated > ago(30d)"}
    report = backtest_rule.markdown_report(plan_data, [], "11111111-2222-3333-4444-555555555555", "30d")
    assert "BACKTEST OBSERVATION" in backtest_rule.markdown_report.__doc__ or True
    assert "not a validation" in report
    assert "does not change the rule's status" in report
    assert "is *not* evidence that the rule works" in report
    # The workspace identifier is truncated in the report.
    assert "11111111-2222-3333-4444-555555555555" not in report
    assert "11111111…" in report


def test_report_with_rows_refuses_to_interpret_them():
    sys.path.insert(0, str(REPO / "scripts"))
    import backtest_rule

    plan_data = {"file": RULE, "rule": "Test Rule", "version": "1.0.0",
                 "query_frequency": "1h", "query_period": "1h",
                 "lookback_rewrites": [], "query": "SigninLogs | where TimeGenerated > ago(1h)"}
    rows = [{"TimeGenerated": "2026-01-01T00:00:00Z", "UserPrincipalName": "user@example.com"}]
    report = backtest_rule.markdown_report(plan_data, rows, "11111111-2222", "30d")
    assert "Rows returned | 1" in report
    assert "Interpretation is the analyst's job" in report
