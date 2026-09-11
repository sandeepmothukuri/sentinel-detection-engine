#!/usr/bin/env python3
"""The workflow files must be runnable by GitHub, not merely valid YAML.

Why this file exists: on 2026-09-11 `.github/workflows/validate.yml` declared
`GITHUB_TOKEN` under `workflow_call.secrets`. GitHub rejects that — the name
collides with a system-reserved secret — and it rejects the **whole file**, so
every run failed at startup with zero jobs: the push to `main`, the pull
requests, and all five Dependabot PRs. Nothing local noticed: yamllint was happy,
actionlint was happy, `pytest` was happy. The repository looked green and CI was
dead for hours.

The checks below are the GitHub rules that no local linter in this toolchain
enforces. They are written against the parsed YAML, and they fail loudly with the
reason, because a silent CI is worse than a red one.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys

import yaml
from conftest import REPO

WORKFLOW_DIR = REPO / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml"))

# GitHub reserves GITHUB_* secret names. Declaring one in workflow_call.secrets is a
# startup error; referencing one is fine.
RESERVED_SECRET_PREFIX = "github_"
USES_RE = re.compile(r"uses:\s*([\w.-]+/[\w.-]+)@(\S+?)(?:\s+#\s*(\S+))?\s*$", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load(path: pathlib.Path) -> dict:
    """Parse a workflow. YAML reads the bare key `on` as the boolean True, so the
    mapping is normalised before anything looks at the triggers — otherwise every
    check silently inspects None."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} is not a YAML mapping"
    for key in list(data):
        if key is True or key == "on":
            data["on"] = data.pop(key)
    return data


def test_every_workflow_parses_and_declares_triggers() -> None:
    assert WORKFLOWS, "no workflow files found — the directory moved?"
    for path in WORKFLOWS:
        data = load(path)
        assert "on" in data, f"{path.name} declares no triggers"
        assert data.get("jobs"), f"{path.name} declares no jobs"
        assert "runs-on" in yaml.safe_dump(data["jobs"]), f"{path.name} has a job with no runner"


def test_no_reserved_secret_name_is_declared_in_workflow_call() -> None:
    """The exact defect that broke CI. GitHub refuses to start the run at all."""
    offenders = []
    for path in WORKFLOWS:
        triggers = load(path).get("on") or {}
        if not isinstance(triggers, dict) or "workflow_call" not in triggers:
            continue
        declared = ((triggers["workflow_call"] or {}).get("secrets") or {})
        for name in declared:
            if str(name).lower().startswith(RESERVED_SECRET_PREFIX):
                offenders.append(f"{path.name}: workflow_call.secrets declares {name!r}")
    assert not offenders, (
        "GitHub rejects the entire workflow file when workflow_call declares a reserved "
        "secret name, so every run fails at startup with zero jobs. Remove the "
        "declaration and read the value from the `github.token` context instead "
        f"(it is defined in every trigger): {offenders}")


def test_actions_are_pinned_to_a_commit_sha() -> None:
    """A tag is mutable: `@v4` can be repointed at new code without review. Every
    third-party action is pinned to an immutable commit, and the comment records
    which release that commit is, so a reader can still tell what is running."""
    offenders = []
    for path in WORKFLOWS:
        for action, ref, comment in USES_RE.findall(path.read_text(encoding="utf-8")):
            if not SHA_RE.match(ref):
                offenders.append(f"{path.name}: {action}@{ref} is a tag, not a commit SHA")
            elif not comment or not comment.startswith("v"):
                offenders.append(f"{path.name}: {action}@{ref[:8]} pins a commit but the "
                                 f"comment does not name the release, so a reviewer cannot "
                                 f"tell what is running")
    assert not offenders, f"unpinned or unlabelled action references: {offenders}"


def test_no_privileged_trigger_pull_request_target_or_workflow_run() -> None:
    """`pull_request_target` and `workflow_run` run with a writable token in the
    context of the base repository. Neither is used here, and that is a claim the
    README and the audit make, so it is checked rather than asserted in prose."""
    offenders = [p.name for p in WORKFLOWS
                 if any(trigger in load(p).get("on") or {}
                        for trigger in ("pull_request_target", "workflow_run"))]
    assert not offenders, f"these workflows use a privileged trigger: {offenders}"


def test_every_script_a_workflow_runs_exists() -> None:
    """A `run:` line naming a script that is not in the repository fails the run —
    and it is the kind of breakage that only shows up in CI, after a push."""
    missing = []
    for path in WORKFLOWS:
        for script in re.findall(r"python(?:3)?\s+(scripts/[\w/.-]+\.py)", path.read_text(encoding="utf-8")):
            if not (REPO / script).exists():
                missing.append(f"{path.name} runs {script}, which does not exist")
    assert not missing, missing


def test_the_validation_workflow_runs_every_gate_the_repository_claims() -> None:
    """The README, the evidence register and the audit report list the gates CI runs.
    If a gate is dropped from the workflow, those claims become false."""
    workflow = (WORKFLOW_DIR / "validate.yml").read_text(encoding="utf-8")
    required = {
        "gitleaks": "gitleaks/gitleaks-action",
        "yamllint": "yamllint ",
        "rule validation": "python scripts/ci_validate.py",
        "tests": "pytest tests",
        "link check": "python scripts/check_links.py",
        "workflow lint": "actionlint",
        "coverage drift": "python scripts/generate_coverage.py",
        "ledger drift": "python scripts/generate_atomics_ledger.py",
        "ARM templates": "generate_arm_templates.py --check",
        "quality matrix": "python scripts/generate_metrics_matrix.py",
        "preview digest": "render_design_preview.py --check",
        "chart data and digest": "render_project_charts.py --check",
        "packaging": "python scripts/package_rules.py",
    }
    missing = [name for name, needle in required.items() if needle not in workflow]
    assert not missing, (
        f"validate.yml no longer runs these gates, so the documentation's claims about CI "
        f"are false: {missing}")


def test_actionlint_reports_no_errors() -> None:
    """actionlint catches what YAML validation cannot: bad `${{ }}` expressions,
    mistyped action inputs, shell mistakes. It is a declared dependency, so a
    missing binary is a broken environment rather than a reason to skip."""
    binary = shutil.which("actionlint") or shutil.which("actionlint.exe")
    assert binary, ("actionlint is not on PATH. It is declared in requirements.txt: run "
                   "`pip install -r requirements.txt`")
    proc = subprocess.run([binary, "-oneline", *[str(p) for p in WORKFLOWS]],
                          capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 0, (
        f"actionlint found problems in the workflow files:\n{proc.stdout}{proc.stderr}")

def test_a_workflow_that_scans_commits_checks_out_with_history() -> None:
    """gitleaks scans the *commits* a change adds, so it needs the parent commit.

    On 2026-09-11 both `main` and the Dependabot pull request failed at the secrets
    step with `fatal: ambiguous argument '<sha>^..<sha>': unknown revision` — the
    default `fetch-depth: 1` clone has no parent to diff against, so the scan errors
    out instead of scanning. The two workflows that do not scan secrets already set
    `fetch-depth: 0`; the one that does, did not. This check is the reason it cannot
    drift back, and it is written against the parsed YAML so a comment or a rename
    cannot satisfy it by accident.
    """
    offenders = []
    for path in WORKFLOWS:
        data = load(path)
        text = path.read_text(encoding="utf-8")
        if "gitleaks" not in text:
            continue
        checkouts = [step for job in data["jobs"].values() for step in job.get("steps", [])
                     if str(step.get("uses", "")).startswith("actions/checkout")]
        if not checkouts:
            offenders.append(f"{path.name}: runs a secrets scan with no checkout")
            continue
        for step in checkouts:
            if (step.get("with") or {}).get("fetch-depth") != 0:
                offenders.append(
                    f"{path.name}: the checkout feeding the secrets scan does not set "
                    f"fetch-depth: 0, so gitleaks cannot resolve its commit range")
    assert not offenders, "\n  ".join(offenders)
