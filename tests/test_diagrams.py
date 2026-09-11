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

import json
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


def test_every_image_is_registered_in_the_evidence_file():
    """An image without a provenance entry is an image nobody can trust. The
    register is the contract; this makes forgetting a row a build failure."""
    images = sorted(p.name for p in (REPO / "docs" / "images").rglob("*.png"))
    assert images, "no images found — the layout moved?"
    evidence = (REPO / "docs" / "evidence.md").read_text(encoding="utf-8")
    unregistered = [name for name in images if name not in evidence]
    assert not unregistered, (
        f"these images have no entry in docs/evidence.md: {unregistered}\n"
        "Record purpose, source, environment, date, what it demonstrates and any redactions.")


def test_evidence_register_reproduction_block_covers_every_generator():
    """The register tells a reader how to rebuild the artefacts. If a generator is
    missing from it, the artefact it produces looks un-reproducible."""
    evidence = (REPO / "docs" / "evidence.md").read_text(encoding="utf-8")
    generators = sorted(p.name for p in (REPO / "scripts").glob("render_*.py"))
    generators += ["generate_coverage.py", "generate_atomics_ledger.py", "generate_arm_templates.py"]
    missing = [g for g in generators if g not in evidence]
    assert not missing, f"docs/evidence.md does not name these generators: {missing}"


def workbook_query_panels() -> list[str]:
    workbook = json.loads((REPO / "Workbooks" / "L3-Triage-Dashboard.json").read_text(encoding="utf-8"))
    items = list(workbook["items"].values()) if isinstance(workbook["items"], dict) else workbook["items"]
    return [item["name"] for item in items if "query" in (item.get("content") or {})]


def test_workbook_preview_is_bound_to_every_workbook_panel():
    """The HTML wireframe claims to show the panels defined in the workbook. That
    claim is only true if every panel is on the page — one panel was missing when
    the workbook grew, which is the defect this pins."""
    html = (REPO / "docs" / "dashboard-preview.html").read_text(encoding="utf-8")
    bound = set(re.findall(r'data-panel="([A-Za-z_]+)"', html))
    panels = set(workbook_query_panels())
    assert bound, "the preview page binds no panels — did the markup change?"
    assert bound == panels, (
        f"preview/workbook panel mismatch.\n  missing from the page: {sorted(panels - bound)}"
        f"\n  on the page but not in the workbook: {sorted(bound - panels)}")


def test_workbook_preview_shows_no_invented_values():
    """A wireframe that carries numbers reads as a measurement. Every value on the
    page must be the em dash placeholder, and the banner must be present."""
    html = (REPO / "docs" / "dashboard-preview.html").read_text(encoding="utf-8")
    assert "DESIGN PREVIEW — REQUIRES DEPLOYMENT TO DISPLAY LIVE TELEMETRY" in html, (
        "the design-preview banner was removed; without it the page reads as a screenshot")
    fabricated = re.findall(r'class="(?:v|n|num)">\s*([0-9][^<]*)<', html)
    assert not fabricated, f"the preview page shows numeric values instead of placeholders: {fabricated}"
    assert 'class="v">—<' in html or 'class="n">—<' in html, (
        "the preview page no longer uses the em dash placeholder")


def test_architecture_table_list_matches_declared_tables():
    """docs/architecture.md maps tables to connectors. The mapping must name every
    table the rules actually declare — no more (a table nothing reads) and no less
    (a rule whose table is undocumented)."""
    declared = set()
    for pattern in RULE_GLOBS:
        for path in sorted(REPO.glob(pattern)):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for connector in rule.get("requiredDataConnectors") or []:
                declared.update(connector.get("dataTypes") or [])

    text = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    section = text.split("## Data source coverage", 1)[1].split("\n## ", 1)[0]
    # Table rows only: the surrounding prose mentions field names in backticks too.
    rows = [line for line in section.splitlines() if line.startswith("|")]
    documented = set(re.findall(r"`([A-Za-z][A-Za-z0-9_]+)`", "\n".join(rows)))
    workbook_only = {"SecurityIncident", "SecurityAlert"}  # native, no connector

    undocumented = declared - documented
    phantom = documented - declared - workbook_only
    assert not undocumented, (
        f"these tables are declared by rules but absent from the architecture table: {sorted(undocumented)}")
    assert not phantom, (
        f"the architecture table names tables no rule declares: {sorted(phantom)}")


def test_diagram_says_how_the_counts_are_kept_honest():
    text = DIAGRAM.read_text(encoding="utf-8")
    assert "rule files" in text, (
        "the diagram must state where its counts come from, so a reader knows they are not decorative")
