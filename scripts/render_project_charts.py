#!/usr/bin/env python3
"""Draw the repository's own numbers as charts, and the social preview card.

Every value on every chart is computed from committed files at draw time:

    coverage redundancy    attack-navigator/layer.json + Detections/*.yaml
    detection inventory    Detections/*.yaml + Hunting Queries/*.yaml
    validation status      tests/validation/atomics.yaml
    social card            the same counts, drawn once

No telemetry, no tenant, no placeholder numbers: a chart that cannot be derived
from a file in this repository does not belong here.

Alongside each PNG the generator records the numbers it drew, in
docs/images/generated-charts.json. `--check` recomputes those numbers from the
rule files and the ledger and compares them with the recording, then checks each
committed PNG against its recorded digest. Numbers are compared rather than
pixels on purpose: re-rasterising the same chart under a different matplotlib
release can change bytes without changing a single value, and a gate that fails
on a picture nobody changed is a gate people learn to ignore.

Usage
-----
    python scripts/render_project_charts.py
    python scripts/render_project_charts.py --check
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")

import yaml  # noqa: E402
from matplotlib import patches  # noqa: E402
from matplotlib import pyplot as plt  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from render_coverage_chart import save_without_metadata  # noqa: E402  (shared, metadata-free PNG writer)

REPO = pathlib.Path(__file__).resolve().parent.parent
IMAGES = REPO / "docs" / "images"
LAYER = REPO / "attack-navigator" / "layer.json"
LEDGER = REPO / "tests" / "validation" / "atomics.yaml"
ATTACK_DATA = REPO / "scripts" / "attack_data.json"

MANIFEST = IMAGES / "generated-charts.json"
CHART_DATA: dict[str, dict] = {}


class State:
    """False in --check mode: draw into memory, write nothing to disk."""

    save = True


INK = "#1f2937"
MUTED = "#6b7280"
GRID = "#d7dbe0"
BG = "#ffffff"
ACCENT = "#1f6feb"
SEV_COLOURS = {"High": "#b42318", "Medium": "#b54708", "Low": "#175cd3", "Informational": "#475467"}

# One typography stack and one greys scale for every chart in the repository, so
# the coverage chart and the inventory panels read as pages from the same report.
# The font list mirrors the Mermaid theme in render_diagrams.py; matplotlib falls
# through to whatever is installed, so this stays deterministic inside a container.
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Segoe UI", "Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "axes.titlesize": 12,
    "axes.titleweight": "semibold",
    "axes.labelcolor": MUTED,
    "text.color": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "xtick.major.size": 0,
    "ytick.major.size": 0,
    "axes.edgecolor": GRID,
    "figure.facecolor": BG,
    "savefig.facecolor": BG,
})

# Rendered at 200 dpi. At 100 the text was visibly soft the moment anyone opened
# the PNG at full size or dropped it into a slide, which is where these images are
# actually read. Doubling the resolution of a vector source costs nothing in
# fidelity and nothing in determinism - the gate recomputes the numbers, it does
# not compare bytes.
CHART_DPI = 200
TACTIC_ORDER_FALLBACK = [
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "CommandAndControl", "Exfiltration", "Impact",
]
DISPLAY = {"DefenseEvasion": "Defense Evasion", "LateralMovement": "Lateral Movement",
           "CommandAndControl": "Command and Control", "PrivilegeEscalation": "Privilege Escalation",
           "InitialAccess": "Initial Access", "ResourceDevelopment": "Resource Development"}


def display(name: str) -> str:
    return DISPLAY.get(name, " ".join(part.title() for part in _split_camel(name)))


def _split_camel(name: str) -> list[str]:
    out, current = [], ""
    for char in name:
        if char.isupper() and current:
            out.append(current)
            current = char
        else:
            current += char
    if current:
        out.append(current)
    return out


def telemetry_tables() -> collections.Counter:
    """Every Log Analytics table named in requiredDataConnectors, across the rules
    and the hunting queries — the same population docs/data-sources.md summarises.
    Detections alone would undercount: DeviceInfo arrives with a hunt."""
    counts: collections.Counter = collections.Counter()
    for folder in ("Detections", "Hunting Queries"):
        for path in sorted((REPO / folder).glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for connector in doc.get("requiredDataConnectors") or []:
                counts.update(connector.get("dataTypes") or [])
    return counts


def emit(fig, rel: str, data: dict, **kwargs) -> pathlib.Path:
    """Record what was drawn, optionally write the PNG, and close the figure."""
    CHART_DATA[rel] = json.loads(json.dumps(data, sort_keys=True))  # plain, comparable types
    path = IMAGES / rel
    kwargs.setdefault("facecolor", BG)
    # dpi defaults to the data-chart resolution but a caller may pin it: the social
    # preview must stay at GitHub's exact 1280x640, which is dpi=100 for its figure.
    kwargs.setdefault("dpi", CHART_DPI)
    if State.save:
        path.parent.mkdir(parents=True, exist_ok=True)
        save_without_metadata(fig, path, **kwargs)
    plt.close(fig)
    return path


def rules() -> list[dict]:
    out = []
    for path in sorted((REPO / "Detections").glob("*.yaml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule["_stem"] = path.stem
        rule["_tables"] = sorted({t for c in rule.get("requiredDataConnectors") or []
                                  for t in (c.get("dataTypes") or [])})
        out.append(rule)
    return out


def hunts() -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8"))
            for p in sorted((REPO / "Hunting Queries").glob("*.yaml"))]


def technique_severity() -> dict[str, str]:
    """Technique -> highest severity of any rule that maps it."""
    rank = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
    out: dict[str, str] = {}
    for rule in rules():
        for technique in rule.get("relevantTechniques") or []:
            current = out.get(technique)
            if current is None or rank[rule["severity"]] > rank[current]:
                out[technique] = rule["severity"]
    return out


# --------------------------------------------------------------------------- charts

def chart_coverage_redundancy() -> pathlib.Path:
    """How many scheduled rules stand behind each technique the repository covers.

    Deliberately not a severity split of the coverage: `attack/01` already draws
    coverage per tactic, and a second view of the same counts with a different
    colour key would be two pictures of one fact. This one answers a question the
    other chart does not — how much slack the coverage has if a rule is disabled.
    """
    layer = json.loads(LAYER.read_text(encoding="utf-8"))
    covered = {entry["techniqueID"] for entry in layer["techniques"]}
    rules_by_technique: collections.Counter = collections.Counter()
    for rule in rules():
        for technique in rule.get("relevantTechniques") or []:
            rules_by_technique[technique] += 1

    hunt_only = sorted(covered - set(rules_by_technique))
    depth = collections.Counter(rules_by_technique.values())
    bars = [
        ("No scheduled rule\n(hunting query only)", len(hunt_only), "#b54708"),
        ("Backed by exactly one rule", depth.get(1, 0), ACCENT),
        ("Backed by two or more rules", sum(n for d, n in depth.items() if d >= 2), "#087443"),
    ]
    # Assert rather than trust: every covered technique lands in exactly one bucket.
    assert sum(value for _, value, _ in bars) == len(covered), "buckets must partition the coverage"

    fig, ax = plt.subplots(figsize=(11.5, 3.6), dpi=CHART_DPI)
    fig.patch.set_facecolor(BG)
    for index, (label, value, colour) in enumerate(bars):
        ax.barh([label], [value], height=0.5, color=colour, edgecolor="white")
        ax.text(value + 0.2, index, f"{value} of {len(covered)}", va="center",
                fontsize=10.5, weight="bold", color=INK)

    ax.set_xlim(0, max(value for _, value, _ in bars) + 6)
    ax.set_title(f"What stands behind each of the {len(covered)} covered ATT&CK techniques",
                 fontsize=13, weight="bold", color=INK, pad=12)
    ax.grid(axis="x", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(colors=INK, labelsize=9.5)

    most = max(depth) if depth else 0
    caption = [
        f"At most {most} scheduled rules back any single technique: disabling one rule removes the "
        "scheduled coverage for the techniques it alone maps.",
        "The repository does not manufacture redundancy by duplicating rules. Hunt-only techniques "
        "have no scheduled rule: they surface when an analyst runs the hunt, not automatically.",
        "Counted from attack-navigator/layer.json and Detections/*.yaml at draw time — regenerate "
        "with scripts/render_project_charts.py.",
    ]
    for index, line in enumerate(caption):
        fig.text(0.012, 0.20 - index * 0.062, line, fontsize=8.8, color=MUTED, va="center")
    fig.tight_layout(rect=(0, 0.28, 1, 1))
    return emit(fig, "attack/04-coverage-redundancy.png", {
        "covered_techniques": len(covered),
        "hunting_query_only": bars[0][1],
        "backed_by_one_rule": bars[1][1],
        "backed_by_two_or_more_rules": bars[2][1],
        "rules_per_technique": dict(sorted(rules_by_technique.items())),
    })


def chart_inventory() -> pathlib.Path:
    detections, hunting = rules(), hunts()
    tables = telemetry_tables()
    severities = collections.Counter(rule["severity"] for rule in detections)
    frequencies = collections.Counter(rule["queryFrequency"] for rule in detections)
    connectors: collections.Counter = collections.Counter()
    for folder in ("Detections", "Hunting Queries"):
        for path in sorted((REPO / folder).glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            connectors.update(c.get("connectorId") for c in doc.get("requiredDataConnectors") or [])

    fig, axes = plt.subplots(2, 2, figsize=(12.2, 7.2), dpi=CHART_DPI)
    fig.patch.set_facecolor(BG)
    fig.suptitle(f"Detection inventory — {len(detections)} scheduled rules, {len(hunting)} hunting queries",
                 fontsize=14, weight="bold", color=INK, y=0.98)

    def style(ax):
        ax.grid(axis="x", color=GRID, linewidth=0.7)
        ax.set_axisbelow(True)
        for spine in ("top", "right", "left"):
            ax.spines[spine].set_visible(False)
        ax.tick_params(colors=INK, labelsize=9)

    ax = axes[0][0]
    order = [s for s in ("High", "Medium", "Low", "Informational") if severities.get(s)]
    ax.barh(order, [severities[s] for s in order], height=0.6,
            color=[SEV_COLOURS[s] for s in order], edgecolor="white")
    for i, s in enumerate(order):
        ax.text(severities[s] + 0.1, i, str(severities[s]), va="center", fontsize=9.5, color=INK)
    ax.set_title("Rules by severity", fontsize=11.5, color=INK, loc="left")
    style(ax)

    ax = axes[0][1]
    top = tables.most_common()
    ax.barh([t for t, _ in top][::-1], [c for _, c in top][::-1], height=0.6,
            color=ACCENT, edgecolor="white")
    for i, (_, count) in enumerate(top[::-1]):
        ax.text(count + 0.1, i, str(count), va="center", fontsize=9.5, color=INK)
    ax.set_title("Rules per telemetry table", fontsize=11.5, color=INK, loc="left")
    style(ax)

    ax = axes[1][0]
    freq_order = sorted(frequencies, key=lambda f: int(f.rstrip("mhd")) * {"m": 1, "h": 60, "d": 1440}[f[-1]])
    ax.bar(freq_order, [frequencies[f] for f in freq_order], width=0.55,
           color="#6941c6", edgecolor="white")
    for i, f in enumerate(freq_order):
        ax.text(i, frequencies[f] + 0.08, str(frequencies[f]), ha="center", fontsize=9.5, color=INK)
    ax.set_title("Rule scheduling frequency", fontsize=11.5, color=INK, loc="left")
    ax.set_ylabel("rules", fontsize=9, color=MUTED)
    style(ax)

    ax = axes[1][1]
    # Connectors rather than "techniques per rule": the latter was two bars showing
    # 1 and 2, which tells a reader nothing the ATT&CK chart does not already say.
    connector_order = connectors.most_common()[::-1]
    ax.barh([name for name, _ in connector_order], [count for _, count in connector_order],
            height=0.6, color="#087443", edgecolor="white")
    for i, (_, count) in enumerate(connector_order):
        ax.text(count + 0.1, i, str(count), va="center", fontsize=9.5, color=INK)
    ax.set_title("Content per data connector (rules and hunts)", fontsize=11.5, color=INK, loc="left")
    style(ax)

    fig.text(0.01, 0.015,
             "Every value counted from Detections/*.yaml and Hunting Queries/*.yaml "
             "(tested rules) at draw time. "
             "Regenerate with scripts/render_project_charts.py; CI fails if this image is stale.",
             fontsize=8.6, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    return emit(fig, "detections/04-inventory-overview.png", {
        "rules": len(detections),
        "hunting_queries": len(hunting),
        "rules_by_severity": dict(sorted(severities.items())),
        "rules_by_frequency": dict(sorted(frequencies.items())),
        "content_per_table": dict(sorted(tables.items())),
        "content_per_connector": dict(sorted(connectors.items())),
    })


def chart_validation_status() -> pathlib.Path:
    """How each ledger entry is validated today. The three buckets are mutually
    exclusive and derived, not asserted: a reader should be able to re-count them
    from tests/validation/atomics.yaml."""
    ledger = yaml.safe_load(LEDGER.read_text(encoding="utf-8"))
    entries = ledger["rules"]

    def roles(entry: dict) -> set[str]:
        return {c.get("role") for c in (entry.get("checks") or []) if c.get("atomic")}

    with_trigger = sum(1 for e in entries if "trigger" in roles(e))
    contextual = [e for e in entries if "trigger" not in roles(e) and roles(e)]
    manual_only = sum(1 for e in entries if not roles(e))
    with_partial = len(contextual)
    context_roles = collections.Counter(role for e in contextual for role in roles(e))
    assert with_trigger + with_partial + manual_only == len(entries)
    citations = sum(len([c for c in (e.get("checks") or []) if c.get("atomic")]) for e in entries)
    statuses = collections.Counter(e["status"] for e in entries)

    fig, ax = plt.subplots(figsize=(11.5, 4.8), dpi=CHART_DPI)
    fig.patch.set_facecolor(BG)

    bars = [
        ("Trigger atomic cited\n(a runnable test exists upstream)", with_trigger, "#087443"),
        ("Cited for context only\n("
         + ", ".join(f"{n} {role}" for role, n in sorted(context_roles.items()))
         + "; none drives this rule)", with_partial, ACCENT),
        ("Manual procedure only\n(upstream has no atomic)", manual_only, "#b54708"),
    ]
    for i, (label, value, colour) in enumerate(bars):
        ax.barh([label], [value], height=0.52, color=colour, edgecolor="white")
        ax.text(value + 0.2, i, f"{value} of {len(entries)}", va="center", fontsize=10.5,
                weight="bold", color=INK)

    ax.set_xlim(0, max(v for _, v, _ in bars) + 5)
    ax.set_title(f"Validation ledger — {len(entries)} entries, {citations} atomic citations",
                 fontsize=13, weight="bold", color=INK, pad=12)
    ax.grid(axis="x", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(colors=INK, labelsize=9.5)

    status_line = (next(iter(statuses)) if len(statuses) == 1
                   else ", ".join(f"{count} {name}" for name, count in statuses.items()))
    # fig.text with figure coordinates: ax.text would place this in data units,
    # which put the column under the first tick and ran the longest line off the
    # right edge.
    caption = [
        f"All {len(entries)} entries stand at {status_line}: a mapping is a plan, not a result.",
        "Citations resolve against the vendored Atomic Red Team index (scripts/atomic_data.json);",
        "refreshing that index against upstream is a deliberate, reviewed commit.",
        "No atomic has been executed against a tenant and no rule has fired, here or anywhere else.",
        "Counted from tests/validation/atomics.yaml at draw time — regenerate with "
        "scripts/render_project_charts.py.",
    ]
    for index, line in enumerate(caption):
        fig.text(0.012, 0.225 - index * 0.043, line, fontsize=8.8, color=MUTED, va="center")
    fig.tight_layout(rect=(0, 0.24, 1, 1))
    return emit(fig, "sentinel/03-validation-status.png", {
        "entries": len(entries),
        "atomic_citations": citations,
        "trigger_atomic_cited": with_trigger,
        "context_only_atomic": with_partial,
        "manual_procedure_only": manual_only,
        "statuses": dict(sorted(statuses.items())),
    })


def chart_social_card() -> pathlib.Path:
    """The GitHub social preview. A card drawn from the repository's own counts —
    not a mockup of a console, and not a screenshot of anything."""
    detections, hunting = rules(), hunts()
    ledger = yaml.safe_load(LEDGER.read_text(encoding="utf-8"))
    layer = json.loads(LAYER.read_text(encoding="utf-8"))
    tables = telemetry_tables()
    playbooks = sorted(p.name for p in (REPO / "Playbooks").glob("*") if p.is_dir())
    citations = sum(len([c for c in (entry.get("checks") or []) if c.get("atomic")])
                    for entry in ledger["rules"])
    licence = (REPO / "LICENSE").read_text(encoding="utf-8").strip().split("\n")[0] \
        .replace(" License", "")

    fig = plt.figure(figsize=(12.8, 6.4), dpi=100)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1280)
    ax.set_ylim(0, 640)
    ax.axis("off")
    ax.add_patch(patches.Rectangle((0, 0), 1280, 640, facecolor="#0b1220", edgecolor="none"))
    ax.add_patch(patches.Rectangle((0, 0), 10, 640, facecolor=ACCENT, edgecolor="none"))

    ax.text(70, 540, "sentinel-detection-engine", fontsize=34, weight="bold", color="white")
    ax.text(70, 496, "Detection-as-code for Microsoft Sentinel and Microsoft Defender XDR",
            fontsize=15, color="#c9d3e0")
    ax.text(70, 466, "analytics rules · hunting queries · SOAR playbooks · L3 triage workbook · "
                     "CI gates · generated ATT&CK coverage",
            fontsize=11.5, color="#8fa2bb")

    stats = [
        (f"{len(detections)}", "scheduled rules"),
        (f"{len(hunting)}", "hunting queries"),
        (f"{len(layer['techniques'])}", "ATT&CK techniques"),
        (f"{len(ledger['rules'])}", "ledger entries"),
        (f"{len(tables)}", "telemetry tables"),
    ]
    for index, (value, label) in enumerate(stats):
        x = 70 + index * 236
        ax.text(x, 350, value, fontsize=40, weight="bold", color="white")
        ax.text(x, 315, label, fontsize=11.5, color="#8fa2bb")

    ax.add_patch(patches.Rectangle((70, 178), 1140, 100, facecolor="#172033", edgecolor="#2b3a55"))
    # Each line is placed explicitly: matplotlib's linespacing is in points, which
    # does not map to these axis units, and a guess-based layout overlapped here.
    ax.text(94, 254, "Static validation only.", fontsize=14, weight="bold",
            color="#ffd166", va="center")
    for offset, line in enumerate((
            "Nothing in this repository has been executed against a live tenant. Every rule is at",
            "STATIC VALIDATION and every unmeasured metric reads 'Not yet measured'.",
            "The gaps are documented, not simulated.")):
        ax.text(94, 230 - offset * 20, line, fontsize=11, color="#c9d3e0", va="center")

    ax.text(70, 120,
            f"{len(detections)} scheduled rules · {len(hunting)} hunting queries · "
            f"{len(playbooks)} SOAR playbooks · {len(ledger['rules'])} ledger entries "
            f"pinning {citations} atomic citations",
            fontsize=11, color="#8fa2bb")
    ax.text(70, 76, "Sandeep Mothukuri", fontsize=13, weight="bold", color="white")
    ax.text(70, 52, f"{licence} licensed · generated artefacts drift-gated in CI",
            fontsize=10.5, color="#8fa2bb")

    # GitHub renders the social preview at exactly 1280x640 and crops anything
    # else, so this figure keeps dpi=100 while the data charts moved to 200: the
    # card must be the size GitHub expects, not the size that looks best zoomed in.
    return emit(fig, "social/01-social-preview-card.png", {
        "rules": len(detections),
        "hunting_queries": len(hunting),
        "attack_techniques": len(layer["techniques"]),
        "ledger_entries": len(ledger["rules"]),
        "telemetry_tables": len(tables),
        "playbooks": len(playbooks),
        "atomic_citations": citations,
    }, facecolor="#0b1220", dpi=100)


BUILDERS = {
    "attack/04-coverage-redundancy.png": chart_coverage_redundancy,
    "detections/04-inventory-overview.png": chart_inventory,
    "sentinel/03-validation-status.png": chart_validation_status,
    "social/01-social-preview-card.png": chart_social_card,
}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def draw_all() -> dict[str, dict]:
    """Run every builder, in a stable order. Returns {image: {sha256, data}}."""
    recorded: dict[str, dict] = {}
    for rel, builder in BUILDERS.items():
        path = builder()
        recorded[rel] = {
            "sha256": digest(path) if path.exists() else None,
            "data": CHART_DATA[rel],
        }
    return recorded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="draw nothing; fail if a chart's data or digest no longer matches "
                             "docs/images/generated-charts.json")
    args = parser.parse_args(argv)

    if not args.check:
        recorded = draw_all()
        MANIFEST.write_text(json.dumps({"images": recorded}, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
        for rel in BUILDERS:
            print(f"wrote docs/images/{rel}")
        print(f"wrote docs/images/{MANIFEST.name} — {len(recorded)} images recorded")
        return 0

    if not MANIFEST.exists():
        print(f"::error::docs/images/{MANIFEST.name} is missing — run "
              "scripts/render_project_charts.py", file=sys.stderr)
        return 1
    try:
        recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))["images"]
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"::error::docs/images/{MANIFEST.name} is not readable: {exc}", file=sys.stderr)
        return 1

    State.save = False
    fresh = draw_all()
    problems: list[str] = []
    for rel in BUILDERS:
        path = IMAGES / rel
        if not path.exists():
            problems.append(f"{rel} is missing from docs/images/")
            continue
        if recorded.get(rel, {}).get("sha256") != digest(path):
            problems.append(f"{rel} does not match the digest recorded in {MANIFEST.name}")
        if recorded.get(rel, {}).get("data") != fresh[rel]["data"]:
            before, after = recorded.get(rel, {}).get("data") or {}, fresh[rel]["data"]
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            problems.append(f"{rel} is stale: the numbers changed in {', '.join(changed)} "
                            f"(recorded {[before.get(k) for k in changed]} -> "
                            f"now {[after.get(k) for k in changed]})")
    for rel in set(recorded) - set(BUILDERS):
        problems.append(f"{rel} is recorded but no longer built")

    if problems:
        for line in problems:
            print(f"::error::{line}", file=sys.stderr)
        print(f"Run scripts/render_project_charts.py and commit the images and "
              f"{MANIFEST.name}.", file=sys.stderr)
        return 1
    print(f"charts: {len(BUILDERS)} images match their recorded data and digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
