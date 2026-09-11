#!/usr/bin/env python3
"""Build scripts/atomic_data.json — the vendored Atomic Red Team index.

Why vendor it: CI must be able to reject a ledger entry that cites an Atomic
Test that does not exist upstream ("T1218.011-23"), and CI must not depend on
github.com being reachable or on upstream content changing under a green build.
A refresh is therefore a deliberate, reviewable commit.

    python scripts/build_atomic_data.py            # refresh (requires network)
    python scripts/build_atomic_data.py --check    # compare vendored data to upstream

The output is a technique -> [ {index, name, platforms} ] map, plus an explicit
list of techniques for which upstream has no atomics at all, so that a rule
mapped to one of those is a visible gap rather than a silent one.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "scripts" / "atomic_data.json"
RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{tid}/{tid}.yaml"
UA = {"User-Agent": "sentinel-detection-engine-atomic-index-builder/1.0"}


def repo_techniques() -> list[str]:
    """Every technique referenced by a rule or by the validation ledger."""
    found: set[str] = set()
    for folder in ("Detections", "Hunting Queries"):
        for path in sorted((REPO / folder).glob("*.yaml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for technique in rule.get("relevantTechniques") or []:
                found.add(str(technique))
    ledger = REPO / "tests" / "validation" / "atomics.yaml"
    if ledger.exists():
        data = yaml.safe_load(ledger.read_text(encoding="utf-8")) or {}
        for entry in data.get("rules") or []:
            for check in entry.get("checks") or []:
                if check.get("technique"):
                    found.add(str(check["technique"]))
    return sorted(found)


def fetch(tid: str, attempts: int = 3) -> dict | None:
    url = RAW.format(tid=tid)
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=45) as resp:
                return yaml.safe_load(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None          # upstream has no atomics for this technique
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"could not fetch {url} after {attempts} attempts")


def build() -> dict:
    techniques: dict[str, list[dict]] = {}
    without: list[str] = []
    for tid in repo_techniques():
        doc = fetch(tid)
        if not doc:
            without.append(tid)
            continue
        tests = []
        for index, test in enumerate(doc.get("atomic_tests") or [], start=1):
            tests.append({
                "index": index,
                "name": re.sub(r"\s+", " ", str(test.get("name") or "")).strip(),
                "platforms": sorted(test.get("supported_platforms") or []),
            })
        if tests:
            techniques[tid] = tests
        else:
            without.append(tid)
    return {
        "source": "github.com/redcanaryco/atomic-red-team",
        "source_path": RAW,
        "techniques": techniques,
        "techniques_without_atomics": sorted(without),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="compare the vendored index with upstream and report differences")
    args = parser.parse_args()

    fresh = build()
    rendered = json.dumps(fresh, indent=1, sort_keys=True) + "\n"

    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if not current:
            print("::error::scripts/atomic_data.json is missing", file=sys.stderr)
            return 1
        if json.loads(current) == fresh:
            print("vendored atomic index matches upstream")
            return 0
        print("::warning::the vendored atomic index differs from upstream. This is not a "
              "failure: upstream adds and renumbers atomics continuously. Review the diff and "
              "refresh deliberately with scripts/build_atomic_data.py.", file=sys.stderr)
        return 0

    OUT.write_text(rendered, encoding="utf-8")
    with_atomics = len(fresh["techniques"])
    total_tests = sum(len(v) for v in fresh["techniques"].values())
    print(f"wrote {OUT.relative_to(REPO)}: {with_atomics} techniques with atomics "
          f"({total_tests} tests), {len(fresh['techniques_without_atomics'])} without")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
