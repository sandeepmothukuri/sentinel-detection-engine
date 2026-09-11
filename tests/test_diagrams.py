#!/usr/bin/env python3
"""Numbers inside diagram sources must match the rule files.

The connector-coverage diagram states how many rules read each table. Those
counts are written in the `.mmd` source, which means they can drift from the
rules the moment a rule starts or stops reading a table — and a stale number in a
picture is harder to notice than a stale number in prose. This test recomputes
them from `requiredDataConnectors` and fails on any disagreement, so the claim
printed inside the diagram ("checked against the rule files") is true.

Only the diagram that carries counts is checked here; the other diagrams are
structural and CI validates them by parsing the Mermaid source in
`tests/test_rules.py`.
"""
from __future__ import annotations

import re
from collections import Counter

import yaml
from conftest import REPO

DIAGRAM = REPO / "docs" / "diagrams" / "sentinel" / "01-connector-table-coverage.mmd"
RULE_GLOBS = ("Detections/*.yaml", "Hunting Queries/*.yaml")
COUNT_RE = re.compile(r'"([A-Za-z][A-Za-z0-9_]*) · (\d+) rules?"')


def table_counts() -> Counter:
    counts: Counter = Counter()
    for pattern in RULE_GLOBS:
        for path in sorted(REPO.glob(pattern)):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            tables = set()
            for connector in rule.get("requiredDataConnectors") or []:
                tables.update(connector.get("dataTypes") or [])
            counts.update(tables)
    return counts


def diagram_counts() -> dict[str, int]:
    text = DIAGRAM.read_text(encoding="utf-8")
    found = COUNT_RE.findall(text)
    assert found, "the connector-coverage diagram no longer states any rule counts"
    return {table: int(count) for table, count in found}


def test_diagram_counts_match_the_rule_files():
    actual, drawn = table_counts(), diagram_counts()
    assert drawn == dict(actual), (
        "docs/diagrams/sentinel/01-connector-table-coverage.mmd disagrees with the rule files.\n"
        f"  drawn:  {drawn}\n  actual: {dict(actual)}\n"
        "Update the .mmd source and re-render: python scripts/render_diagrams.py --only sentinel"
    )


def test_architecture_diagram_rule_counts_match_the_repository():
    """The architecture diagram states the size of the detection inventory; if a
    rule is added and the diagram is not re-rendered, the picture lies."""
    text = (REPO / "docs" / "diagrams" / "architecture" / "01-logical-architecture.mmd").read_text(
        encoding="utf-8")
    detections = len(list((REPO / "Detections").glob("*.yaml")))
    hunts = len(list((REPO / "Hunting Queries").glob("*.yaml")))
    stated_rules = re.search(r"(\d+) scheduled analytics rules", text)
    stated_hunts = re.search(r"(\d+) hunting queries", text)
    assert stated_rules, "the architecture diagram no longer states the analytics-rule count"
    assert stated_hunts, "the architecture diagram no longer states the hunting-query count"
    assert int(stated_rules.group(1)) == detections, (
        f"architecture diagram says {stated_rules.group(1)} analytics rules, repository has {detections}. "
        "Update the .mmd source and re-render: python scripts/render_diagrams.py --only architecture")
    assert int(stated_hunts.group(1)) == hunts, (
        f"architecture diagram says {stated_hunts.group(1)} hunting queries, repository has {hunts}")


def test_diagram_says_how_the_counts_are_kept_honest():
    text = DIAGRAM.read_text(encoding="utf-8")
    assert "rule files" in text, (
        "the diagram must state where its counts come from, so a reader knows they are not decorative")
