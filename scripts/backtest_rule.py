#!/usr/bin/env python3
"""Backtest a rule's query against a real workspace over a historical window.

What this is
------------
A backtest answers one question: *if this rule had been deployed N days ago, what
would it have produced?* It runs the rule's own query against a Log Analytics
workspace over a window of your choosing and reports what came back.

What this is not
----------------
It is not validation, and it never produces numbers on its own. A backtest run
against a workspace is an observation about that workspace's data; it says nothing
about whether the rule would fire on the behaviour it describes. The output is
labelled accordingly, and `tests/validation/atomics.yaml` is not touched by it.

Two hard rules are built into the script:

1. **No execution, no numbers.** Without `--execute` it prints the plan and exits.
   With `--execute` but no reachable workspace it exits non-zero and writes
   nothing. It never emits a placeholder, an estimate, or a sample result.
2. **Every transformation is reported.** Widening the rule's lookback for a longer
   backtest rewrites `ago()` bounds in the query text. The script prints each
   rewrite it made, and refuses to guess when the pattern is not found.

Usage
-----
    # See what would run, and the exact command to run it by hand
    python scripts/backtest_rule.py Detections/MDE_ShadowCopyDeletion.yaml

    # Run it against a workspace you have access to (requires the az CLI, logged in)
    python scripts/backtest_rule.py Detections/MDE_ShadowCopyDeletion.yaml \
        --execute --workspace <log-analytics-workspace-guid> --window 30d

    # Backtest every rule and summarise which ones returned rows
    python scripts/backtest_rule.py --all --execute --workspace <guid> --window 30d

Authentication is delegated to the Azure CLI (`az login`). The script never
handles, stores or logs a credential.

Exit codes
----------
0  plan printed, or every requested query executed
1  a query executed and failed
2  the request could not be executed as configured (bad path, no workspace, a
   query with no explicit lookback to widen)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import shutil
import subprocess
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "tests" / "validation" / "backtests"
RULE_GLOBS = ("Detections/*.yaml", "Hunting Queries/*.yaml")

AGO_RE = re.compile(r"ago\(\s*([0-9]+\s*[smhdw])\s*\)")


class BacktestError(RuntimeError):
    pass


def display_path(path: pathlib.Path) -> str:
    """Repo-relative when possible, so reports read cleanly; absolute otherwise, so a
    rule file outside the repository still works."""
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return str(path)


def rule_paths(targets: list[str], run_all: bool) -> list[pathlib.Path]:
    if run_all:
        paths: list[pathlib.Path] = []
        for glob in RULE_GLOBS:
            paths.extend(sorted(REPO.glob(glob)))
        return paths
    paths = []
    for target in targets:
        path = (REPO / target).resolve()
        if not path.exists():
            raise BacktestError(f"no such rule file: {target}")
        paths.append(path)
    return paths


def load_rule(path: pathlib.Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "query" not in data:
        raise BacktestError(f"{path.name} has no 'query' key")
    return data


def widen_lookback(query: str, window: str) -> tuple[str, list[str]]:
    """Rewrite every ago(<span>) in the query to ago(<window>).

    Returns the rewritten query and a human-readable list of the changes, so the
    transformation is visible in the report rather than silent.
    """
    changes: list[str] = []
    seen: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        original = match.group(1).replace(" ", "")
        if original not in seen:
            seen.add(original)
        changes.append(f"ago({original}) -> ago({window})")
        return f"ago({window})"

    rewritten = AGO_RE.sub(repl, query)
    if not changes:
        raise BacktestError(
            "the query contains no ago(<span>) bound, so there is nothing to widen. "
            "Backtesting a query with an implicit window is not supported: the rule "
            "should have an explicit ago() bound (scripts/ci_validate.py enforces this)."
        )
    return rewritten, changes


def az_available() -> bool:
    return shutil.which("az") is not None


def run_query(workspace: str, query: str, timespan: str) -> list[dict]:
    """Execute the query through the Azure CLI. Raises on any failure."""
    if not az_available():
        raise BacktestError(
            "the Azure CLI ('az') is not installed. Install it and run 'az login', or run "
            "the query by hand in the workspace's Logs blade. This script will not "
            "substitute a result it did not observe."
        )
    cmd = [
        "az", "monitor", "log-analytics", "query",
        "--workspace", workspace,
        "--analytics-query", query,
        "--timespan", timespan,
        "-o", "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise BacktestError(
            f"query failed (exit {proc.returncode}). The Azure CLI said:\n{proc.stderr.strip()[:2000]}"
        )
    try:
        payload = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise BacktestError(f"could not parse the query response: {exc}") from exc
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and "tables" in payload:
        tables = payload["tables"]
        rows: list[dict] = []
        for table in tables:
            columns = [c["name"] for c in table.get("columns", [])]
            for row in table.get("rows", []):
                rows.append(dict(zip(columns, row)))
        return rows
    return []


def plan(path: pathlib.Path, window: str | None) -> dict:
    """Everything the script intends to do, printed before anything runs."""
    rule = load_rule(path)
    query = rule["query"]
    changes: list[str] = []
    if window:
        query, changes = widen_lookback(query, window)
    return {
        "file": display_path(path),
        "rule": rule.get("name", path.stem),
        "version": rule.get("version", "unversioned"),
        "query_frequency": rule.get("queryFrequency", "n/a"),
        "query_period": rule.get("queryPeriod", "n/a"),
        "lookback_rewrites": changes,
        "query": query.strip(),
    }


def markdown_report(plan_data: dict, rows: list[dict], workspace: str, window: str) -> str:
    """Report of an observation that actually happened."""
    columns = sorted({key for row in rows for key in row})
    lines = [
        f"# Backtest observation — {plan_data['rule']}",
        "",
        "> **This is a backtest observation, not a validation.** It records what a query returned",
        "> against one workspace over one historical window. It does not prove the rule detects the",
        "> behaviour it describes, and it does not change the rule's status in",
        "> `tests/validation/atomics.yaml`.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Rule file | `{plan_data['file']}` |",
        f"| Rule version | {plan_data['version']} |",
        f"| Rule schedule | {plan_data['query_frequency']} frequency, {plan_data['query_period']} period |",
        f"| Workspace | `{workspace[:8]}…` (identifier truncated deliberately) |",
        f"| Window | {window} |",
        f"| Executed at | {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Rows returned | {len(rows)} |",
        "",
    ]
    if plan_data["lookback_rewrites"]:
        lines += ["## Lookback rewrites applied to the query", ""]
        lines += [f"- `{c}`" for c in plan_data["lookback_rewrites"]]
        lines += ["", "These rewrites mean the query you ran is not byte-identical to the deployed rule.",
                  "Read the results with that in mind.", ""]
    lines += ["## Result", ""]
    if not rows:
        lines += [
            "The query returned **no rows** over this window. That is an observation about this",
            "workspace and this window only. It is *not* evidence that the rule works, and it is not",
            "evidence that it is broken: the behaviour may simply not have occurred here, or the",
            "telemetry the rule reads may not be present. Check telemetry freshness before drawing",
            "any conclusion — see `docs/workflows/../validation/live-validation-guide.md`.",
            "",
        ]
    else:
        lines += [
            f"The query returned **{len(rows)} rows**. Columns present: "
            f"{', '.join('`' + c + '`' for c in columns) or 'none'}.",
            "",
            "Interpretation is the analyst's job, not the script's. For each row, ask: is this the",
            "behaviour the rule describes, an artefact of the widened window, or a false positive?",
            "Only the first answer is a detection result.",
            "",
        ]
        preview = rows[:10]
        lines += ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
        for row in preview:
            cells = [str(row.get(c, ""))[:40].replace("|", "\\|") for c in columns]
            lines.append("| " + " | ".join(cells) + " |")
        if len(rows) > len(preview):
            lines += ["", f"_Showing the first {len(preview)} of {len(rows)} rows; the full result is in the JSON._"]
        lines += [""]
    lines += [
        "## Raw query executed",
        "",
        "```kusto",
        plan_data["query"],
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rules", nargs="*", help="rule YAML paths, relative to the repository root")
    parser.add_argument("--all", action="store_true", help="backtest every rule in the repository")
    parser.add_argument("--execute", action="store_true",
                        help="actually run the queries (requires --workspace and a logged-in az CLI)")
    parser.add_argument("--workspace", default="",
                        help="Log Analytics workspace GUID to query")
    parser.add_argument("--window", default="",
                        help="backtest window, e.g. 30d. Widens every ago() bound in the query.")
    parser.add_argument("--timespan", default="",
                        help="timespan passed to the query API; defaults to --window")
    parser.add_argument("--out", default="", help="directory for reports (default tests/validation/backtests)")
    args = parser.parse_args(argv)

    try:
        paths = rule_paths(args.rules, args.all)
    except BacktestError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2
    if not paths:
        parser.error("give at least one rule file, or --all")

    if args.execute and not args.workspace:
        print("::error::--execute needs --workspace <guid>. This script will not invent a "
              "workspace, a result, or a row count.", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.out).resolve() if args.out else OUT_DIR
    failures = 0
    for path in paths:
        try:
            plan_data = plan(path, args.window or None)
        except BacktestError as exc:
            print(f"::error file={display_path(path)}::{exc}", file=sys.stderr)
            failures += 1
            continue

        header = f"=== {plan_data['rule']}  ({plan_data['file']}) ==="
        print(header)
        print(f"    schedule      : {plan_data['query_frequency']} / {plan_data['query_period']}")
        if plan_data["lookback_rewrites"]:
            print("    lookback      : " + "; ".join(sorted(set(plan_data["lookback_rewrites"]))))
        else:
            print("    lookback      : unchanged (no --window given)")

        if not args.execute:
            print("    mode          : PLAN ONLY. Nothing was executed, so there is nothing to report.")
            print("    to run it     : az monitor log-analytics query -w <workspace-guid> \\")
            print("                      --timespan " + (args.timespan or args.window or plan_data["query_period"]))
            print("                      --analytics-query \"<query above>\" -o json")
            print()
            continue

        timespan = args.timespan or args.window or plan_data["query_period"]
        try:
            rows = run_query(args.workspace, plan_data["query"], timespan)
        except BacktestError as exc:
            print(f"::error file={plan_data['file']}::{exc}", file=sys.stderr)
            failures += 1
            continue

        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        stem = pathlib.Path(plan_data["file"]).stem
        report = markdown_report(plan_data, rows, args.workspace, timespan)
        (out_dir / f"{stem}-{stamp}.md").write_text(report, encoding="utf-8")
        (out_dir / f"{stem}-{stamp}.json").write_text(json.dumps({
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "rule_file": plan_data["file"],
            "rule_version": plan_data["version"],
            "workspace_id_prefix": args.workspace[:8],
            "window": timespan,
            "lookback_rewrites": plan_data["lookback_rewrites"],
            "query": plan_data["query"],
            "row_count": len(rows),
            "rows": rows,
            "status": "BACKTEST OBSERVATION — not validation",
        }, indent=2, default=str), encoding="utf-8")
        print(f"    executed      : {len(rows)} rows -> {out_dir.relative_to(REPO)}/{stem}-{stamp}.md")
        print()

    if not args.execute:
        print("Plan complete. No query was executed and no result file was written: a backtest "
              "without a workspace has no result to report.")
        # A rule that cannot even be planned is an input problem, not a query
        # failure: exit 2 distinguishes it from a query that ran and errored.
        return 2 if failures else 0

    print("Backtests are observations about one workspace, not validation. Record the interpretation "
          "in the rule's evidence file only if you also executed the behaviour itself.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
