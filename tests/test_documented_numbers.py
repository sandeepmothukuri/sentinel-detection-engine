#!/usr/bin/env python3
"""Documented numbers must match the repository.

Every count quoted in the README and in docs/testing.md is derived here from the
actual files — pytest collection, rule files, hunt files, ledger entries — and
compared against the text. Nothing is hard-coded except the shape of each claim,
so the comparison cannot drift in step with the thing it is checking.

Why a test rather than a generator: the same number appears in prose in several
files, and a hand-edited number is exactly the defect this catches. The cost is
that adding a test or a rule requires updating the documents in the same commit,
which is the intended pressure.
"""
from __future__ import annotations

import re
import subprocess
import sys

import pytest
import yaml
from conftest import REPO

README = REPO / "README.md"
TESTING_DOC = REPO / "docs" / "testing.md"
SUITE = REPO / "tests"


def collect(path: str) -> int:
    """Ask pytest how many tests live in one module or in the whole suite."""
    proc = subprocess.run([sys.executable, "-m", "pytest", path, "--collect-only", "-q"],
                          capture_output=True, text=True, cwd=REPO, check=False)
    match = re.search(r"(\d+) tests? collected", proc.stdout + proc.stderr)
    if not match:
        pytest.fail(f"could not collect {path}:\n{proc.stdout[-800:]}\n{proc.stderr[-800:]}")
    return int(match.group(1))


def documented_modules() -> list[str]:
    """Every test module in the suite. Named without a test_ prefix so pytest does
    not collect this helper as a test."""
    return sorted(p.name for p in SUITE.glob("test_*.py"))


def test_readme_headline_counts_match_the_repository():
    text = README.read_text(encoding="utf-8")
    rules = len(list((REPO / "Detections").glob("*.yaml")))
    hunts = len(list((REPO / "Hunting Queries").glob("*.yaml")))
    ledger = yaml.safe_load(
        (REPO / "tests" / "validation" / "atomics.yaml").read_text(encoding="utf-8"))
    entries = len(ledger["rules"])
    images = sorted((REPO / "docs" / "images").rglob("*.png"))

    assert f"| **Detections** | {rules} scheduled analytics rules" in text, (
        f"README does not state {rules} analytics rules as its detection total")
    assert f"| **Hunting queries** | {hunts}" in text, (
        f"README does not state {hunts} hunting queries")
    assert f"{entries} ledger entries" in text, (
        f"README does not state {entries} ledger entries")
    assert f"The repository contains {len(images)} images" in text, (
        f"README states a different image count than the {len(images)} committed PNGs")


def test_readme_and_testing_doc_state_the_real_test_total():
    total = collect("tests")
    readme = README.read_text(encoding="utf-8")
    testing = TESTING_DOC.read_text(encoding="utf-8")
    assert f"{total} tests" in readme, (
        f"README does not state the real test total ({total})")
    assert f"`pytest tests/` ({total} tests)" in testing, (
        f"docs/testing.md does not state the real test total ({total})")


def test_every_test_module_is_documented_with_its_real_count():
    """Each module needs a row in docs/testing.md, and the row must be right."""
    testing = TESTING_DOC.read_text(encoding="utf-8")
    missing, wrong = [], []
    for name in documented_modules():
        row = re.search(rf"\| `tests/{re.escape(name)}` \| (\d+) \|", testing)
        if not row:
            missing.append(name)
            continue
        actual = collect(f"tests/{name}")
        if int(row.group(1)) != actual:
            wrong.append(f"{name}: documented {row.group(1)}, actual {actual}")
    assert not missing, f"docs/testing.md has no row for: {missing}"
    assert not wrong, f"docs/testing.md test counts are stale: {wrong}"


def test_component_table_counts_match_the_repository():
    """docs/architecture.md lists the inventory with counts in parentheses. Those
    were stale once already (12 rules after the pack grew to 18); this pins them."""
    text = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    detections = len(list((REPO / "Detections").glob("*.yaml")))
    hunts = len(list((REPO / "Hunting Queries").glob("*.yaml")))
    playbooks = len(list((REPO / "Playbooks").glob("*/azuredeploy.json")))
    for label, actual in (("Scheduled analytics rules", detections),
                          ("Hunting queries", hunts),
                          ("SOAR playbooks", playbooks)):
        match = re.search(rf"\| {re.escape(label)} \((\d+)\) \|", text)
        assert match, f"docs/architecture.md has no '{label} (<n>)' row"
        assert int(match.group(1)) == actual, (
            f"docs/architecture.md says {label} = {match.group(1)}, repository has {actual}")


def test_documents_do_not_carry_stale_counts():
    """Guards the class of defect found twice during review: a number that was
    true before the last rules and tests were added, and stayed in the prose."""
    text = README.read_text(encoding="utf-8") + "\n".join(
        p.read_text(encoding="utf-8") for p in sorted((REPO / "docs").rglob("*.md")))
    # Phrasings that were true before the pack grew and stayed in the prose
    # afterwards. Scoped to claims about scheduled rules: a hunting query may
    # legitimately look back 30 days, because a hunt is run on demand, so the
    # bare phrase "30-day baseline" is not a defect on its own.
    stale = ["12 analytic rules", "12 analytics rules", "31 techniques", "11 tactics",
             "22 tests", "91 tests", "24 tests", "27 negative tests",
             "three drift gates", "Scheduled analytics rules (12)",
             "30-day `queryPeriod`", "30d baseline", "30-day baseline self-adjusts"]
    # Word boundaries: "24 tests" must not match inside "124 tests".
    found = [s for s in stale if re.search(rf"(?<![0-9]){re.escape(s)}", text)]
    assert not found, f"stale counts still documented: {found}"
