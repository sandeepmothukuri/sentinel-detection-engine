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
import subprocess
import sys
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


# ------------------------------------------------------------------ charts
CHART_GENERATOR = REPO / "scripts" / "render_project_charts.py"
VALIDATE_WORKFLOW = REPO / ".github" / "workflows" / "validate.yml"


def test_generated_charts_match_their_recorded_numbers_and_digest():
    """The charts are pictures of counts. If a rule or a ledger entry changes and the
    charts are not redrawn, the pictures keep asserting the old numbers — and unlike
    prose, nobody greps a PNG. The generator redraws in memory and compares the
    numbers against docs/images/generated-charts.json, then checks each committed
    PNG against its digest."""
    assert CHART_GENERATOR.exists(), "scripts/render_project_charts.py is missing"
    proc = subprocess.run([sys.executable, str(CHART_GENERATOR), "--check"],
                          capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 0, (
        "the generated charts no longer match the repository data.\n"
        f"{proc.stdout}{proc.stderr}\n"
        "Re-run scripts/render_project_charts.py and commit the images and "
        "docs/images/generated-charts.json."
    )


def test_the_chart_gate_runs_in_ci():
    workflow = VALIDATE_WORKFLOW.read_text(encoding="utf-8")
    assert "render_project_charts.py --check" in workflow, (
        "the chart drift gate is not invoked by .github/workflows/validate.yml, so the "
        "repository would ship charts nobody verifies"
    )


def test_the_social_card_states_the_same_numbers_as_the_rule_files():
    """The card is the first thing a reader sees on GitHub. Its stat row is derived at
    draw time, but the numbers are also in the README and the coverage document, and a
    preview image that contradicts them is worse than no preview image."""
    manifest = json.loads((REPO / "docs" / "images" / "generated-charts.json").read_text(
        encoding="utf-8"))["images"]
    card = manifest["social/01-social-preview-card.png"]["data"]
    rules = len(list((REPO / "Detections").glob("*.yaml")))
    hunts = len(list((REPO / "Hunting Queries").glob("*.yaml")))
    layer = json.loads((REPO / "attack-navigator" / "layer.json").read_text(encoding="utf-8"))
    assert card["rules"] == rules
    assert card["hunting_queries"] == hunts
    assert card["attack_techniques"] == len(layer["techniques"])


def test_the_coverage_chart_states_the_numbers_the_documents_state():
    """The coverage chart is a picture of a claim the repository makes in words.

    It had no number gate at all, and it was wrong: this script keyed its data by
    `tactic.lower()` and looked the result up in its own kebab-case label table, so
    `CredentialAccess` became `credentialaccess`, matched nothing, and the chart drew
    "no coverage" for six tactics that had rules — a coverage chart that understated
    coverage, for as long as it existed. Nothing could see it, because the only check
    on the file was a digest, and a digest only proves the bytes have not changed.

    The numbers are now recomputed from the same sources the chart draws from — the
    rule files and the vendored ATT&CK dataset — and held to `coverage.md` and
    `attack-navigator/layer.json`, so the picture and the documents cannot disagree.
    """
    sys.path.insert(0, str(REPO / "scripts"))
    from render_coverage_chart import tactic_rows  # noqa: PLC0415

    rows, techniques, covered = tactic_rows()
    layer = json.loads((REPO / "attack-navigator" / "layer.json").read_text(encoding="utf-8"))
    coverage = (REPO / "coverage.md").read_text(encoding="utf-8")

    assert techniques == len(layer["techniques"]), (
        f"the chart counts {techniques} techniques; the Navigator layer has "
        f"{len(layer['techniques'])}")
    stated = re.search(r"Tactics covered:\*\* (\d+) of (\d+)", coverage)
    assert stated, "coverage.md no longer states a tactic coverage total"
    assert covered == int(stated.group(1)), (
        f"the chart covers {covered} tactics; coverage.md says {stated.group(1)}")
    assert len(rows) == int(stated.group(2)), (
        f"the chart draws {len(rows)} tactics; coverage.md counts {stated.group(2)}")

    # The specific defect: a tactic with rules can never be drawn as uncovered.
    rule_tactics = set()
    for folder in ("Detections", "Hunting Queries"):
        for path in sorted((REPO / folder).glob("*.yaml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            rule_tactics.update(t.replace("-", "").lower() for t in (rule.get("tactics") or []))
    drawn_as_empty = {name.replace("-", "").lower() for name, d, h in rows if d + h == 0}
    assert not (drawn_as_empty & rule_tactics), (
        "the chart draws these tactics as having no coverage while rules declare them: "
        f"{sorted(drawn_as_empty & rule_tactics)}")


def test_the_gallery_shows_every_image_exactly_once():
    """docs/images/gallery.md is the page a reader lands on, so it has to be the
    complete set: not a selection, and not a list with an image the repository does
    not have. Both directions are checked against the disk."""
    gallery = (REPO / "docs" / "images" / "gallery.md").read_text(encoding="utf-8")
    committed = sorted(p.relative_to(REPO / "docs" / "images").as_posix()
                       for p in (REPO / "docs" / "images").rglob("*.png"))
    linked = re.findall(r"^!\[[^\]]*\]\(([^)]+\.png)\)$", gallery, re.MULTILINE)
    assert sorted(linked) == committed, (
        "docs/images/gallery.md does not show exactly the committed images.\n"
        f"  missing from the gallery: {sorted(set(committed) - set(linked))}\n"
        f"  listed but not committed: {sorted(set(linked) - set(committed))}\n"
        f"  duplicated in the gallery: "
        f"{sorted({x for x in linked if linked.count(x) > 1})}")


def test_every_image_reaches_a_reader():
    """An image that no document embeds is invisible: it survives `git push`, but
    nothing renders it. Renaming a file and missing one reference is exactly how that
    happens, so this asserts the other direction from the gallery test — every picture
    is embedded by path somewhere a reader will actually look.

    The social preview card is the one deliberate exception: GitHub takes that image
    from repository settings, so no page can reference it. Any second exception has to
    be added here on purpose."""
    settings_only = {"social/01-social-preview-card.png"}
    images = sorted(p.relative_to(REPO / "docs" / "images").as_posix()
                    for p in (REPO / "docs" / "images").rglob("*.png"))
    docs = [p for p in REPO.rglob("*.md") if ".git" not in p.parts]
    bodies = {p: p.read_text(encoding="utf-8", errors="ignore") for p in docs}

    gallery = REPO / "docs" / "images" / "gallery.md"
    embed = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")

    orphans, broken = [], []
    for image in images:
        if image in settings_only:
            continue
        embeds = [(d, target) for d, body in bodies.items() if d != gallery
                  for target in embed.findall(body) if target.endswith(image)]
        if not embeds:
            orphans.append(image)
        # a reference that does not resolve from its own file is worse than none:
        # it renders as a broken image, which is what an upload would show.
        broken += [f"{d.relative_to(REPO)} embeds '{target}' for {image}, which "
                   f"does not resolve from that file"
                   for d, target in embeds if not (d.parent / target).resolve().exists()]

    assert not broken, (
        "these image references would render broken after upload:\n  "
        + "\n  ".join(broken))

    assert not orphans, (
        "these images are committed but no document embeds them, so nothing renders "
        "them:\n  " + "\n  ".join(orphans))


def test_the_gallery_is_generated_from_the_register():
    """docs/images/gallery.md copies its descriptions out of docs/evidence.md and
    its pending table out of the capture manifest, so it is generated rather than
    typed. This asserts the committed file is what the generator produces right
    now: if the register's wording changes and the gallery is not regenerated, the
    page that shows the evidence describes it differently from the register.

    Determinism is asserted by building twice — a generator that reorders its
    output between runs would fail in CI for no reason."""
    sys.path.insert(0, str(REPO / "scripts"))
    import generate_image_gallery as gallery

    first, second = gallery.build(), gallery.build()
    assert first == second, "the gallery generator is not deterministic"
    committed = gallery.GALLERY.read_text(encoding="utf-8")
    assert committed == first, (
        "docs/images/gallery.md is stale: run scripts/generate_image_gallery.py "
        "and commit the result")

    # And the generator refuses to describe an image the register does not.
    assert "Not yet captured" in committed
    pending = gallery.read_pending()
    assert all(f"| `{shot['id']}` |" in committed for shot in pending), (
        "a shot pending in capture-manifest.yaml is missing from the gallery's "
        "uncaptured table")
