#!/usr/bin/env python3
"""
Produce a Markdown summary of detection changes in a PR for the PR-comment bot.

For each changed rule under Detections/ and Hunting Queries/:
  - mark as added / modified / deleted
  - on modification, diff tactics + relevantTechniques + severity
  - flag rules where the KQL changed but the version field didn't bump
  - flag rules whose query references tables/columns not in the curated allow-list

Outputs Markdown to stdout. Designed for `gh pr comment --body-file`.

Stdlib + pyyaml only. Reads diff via `git diff --name-status <base>...<head>`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
RULE_PREFIXES = ("Detections/", "Hunting Queries/")
KNOWN_TABLES = {
    "SigninLogs", "AuditLogs", "OfficeActivity", "AzureActivity",
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceImageLoadEvents",
    "DeviceRegistryEvents", "DeviceInfo", "DeviceFileEvents", "DeviceLogonEvents",
    "AzureDiagnostics", "SecurityIncident", "SecurityAlert",
    "EmailEvents", "EmailUrlInfo", "IdentityLogonEvents",
}


def sh(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, cwd=REPO, text=True)


def changed_files(base: str, head: str) -> list[tuple[str, str]]:
    raw = sh(["git", "diff", "--name-status", f"{base}...{head}"])
    out = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if not path.startswith(RULE_PREFIXES):
            continue
        out.append((status, path))
    return out


def read_at(rev: str, path: str) -> dict | None:
    try:
        raw = sh(["git", "show", f"{rev}:{path}"])
    except subprocess.CalledProcessError:
        return None
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        return None


def diff_field(name: str, old, new) -> str | None:
    if old == new:
        return None
    return f"  - `{name}`: `{old}` → `{new}`"


def diff_list_field(name: str, old, new) -> str | None:
    a = set(old or [])
    b = set(new or [])
    if a == b:
        return None
    added = sorted(b - a)
    removed = sorted(a - b)
    bits = []
    if added:
        bits.append(f"added {added}")
    if removed:
        bits.append(f"removed {removed}")
    return f"  - `{name}`: " + "; ".join(bits)


def lint_query(rule: dict) -> list[str]:
    issues = []
    q = (rule.get("query") or "").strip()
    if not q:
        issues.append("query is empty")
        return issues
    first = q.splitlines()[0].strip()
    table = first.split()[0].strip("|;")
    if table not in KNOWN_TABLES and not table.startswith("let "):
        issues.append(f"query starts with `{table}` (not in known-tables allow-list — confirm this table exists)")
    return issues


def main() -> int:
    base = os.environ.get("BASE_SHA") or "origin/main"
    head = os.environ.get("HEAD_SHA") or "HEAD"
    files = changed_files(base, head)
    if not files:
        print("_No rule changes in this PR._")
        return 0

    added, modified, deleted = [], [], []
    for status, path in files:
        if status.startswith("A"):
            added.append(path)
        elif status.startswith("D"):
            deleted.append(path)
        else:
            modified.append(path)

    out = ["## 🛡️ Detection diff report", ""]
    out.append(f"- **Added:** {len(added)}")
    out.append(f"- **Modified:** {len(modified)}")
    out.append(f"- **Deleted:** {len(deleted)}")
    out.append("")

    if added:
        out.append("### Added")
        for path in added:
            rule = read_at(head, path) or {}
            out.append(f"- `{path}` — **{rule.get('name','(no name)')}** "
                       f"[{rule.get('severity','—')}] · "
                       f"tactics: {rule.get('tactics',[])} · "
                       f"techniques: {rule.get('relevantTechniques',[])}")
            for issue in lint_query(rule):
                out.append(f"  - ⚠️ {issue}")
        out.append("")

    if modified:
        out.append("### Modified")
        for path in modified:
            old = read_at(base, path) or {}
            new = read_at(head, path) or {}
            out.append(f"- `{path}` — **{new.get('name','(no name)')}**")
            for line in filter(None, [
                diff_field("severity", old.get("severity"), new.get("severity")),
                diff_field("queryFrequency", old.get("queryFrequency"), new.get("queryFrequency")),
                diff_field("triggerThreshold", old.get("triggerThreshold"), new.get("triggerThreshold")),
                diff_list_field("tactics", old.get("tactics"), new.get("tactics")),
                diff_list_field("relevantTechniques", old.get("relevantTechniques"), new.get("relevantTechniques")),
            ]):
                out.append(line)
            if (old.get("query") or "").strip() != (new.get("query") or "").strip():
                out.append("  - `query`: **changed**")
                if old.get("version") == new.get("version"):
                    out.append(f"    - ⚠️ `version` not bumped (still `{new.get('version')}`)")
            for issue in lint_query(new):
                out.append(f"  - ⚠️ {issue}")
        out.append("")

    if deleted:
        out.append("### Deleted")
        for path in deleted:
            out.append(f"- `{path}`")
        out.append("")

    out.append("---")
    out.append("_Auto-generated by `scripts/pr_diff_report.py` — see `.github/workflows/pr-detection-report.yml`._")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
