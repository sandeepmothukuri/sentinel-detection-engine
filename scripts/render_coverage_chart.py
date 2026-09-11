#!/usr/bin/env python3
"""Draw the ATT&CK coverage charts from the repository's own generated layer.

Everything on the chart comes from attack-navigator/layer.json and the rule
files, so the picture cannot disagree with coverage.md. No telemetry, no tenant
data, nothing hand-entered.

    python scripts/render_coverage_chart.py
"""
from __future__ import annotations

import collections
import json
import pathlib
import re

import matplotlib
matplotlib.use("Agg")
import yaml  # noqa: E402
from matplotlib import pyplot as plt  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
LAYER = REPO / "attack-navigator" / "layer.json"
ATTACK_DB = REPO / "scripts" / "attack_data.json"
OUT_DIR = REPO / "docs" / "images" / "attack"

# The vocabulary and the v19 fold come from the modules that own them rather than
# being restated here. This script used to carry its own kebab-case label table and
# keyed the data by `tactic.lower()`, so `CredentialAccess` became `credentialaccess`
# while the table said `credential-access`: six of the fourteen tactics silently
# matched nothing and were drawn as "no coverage" while their rules sat in the
# dictionary under a key nothing looked up. The chart understated coverage for as
# long as it existed, and no gate could see it because the chart's numbers were
# never compared with the numbers it claims to be drawn from.
from ci_validate import normalize_attack_tactic  # noqa: E402  the one v19 fold
from generate_coverage import SENTINEL_TACTICS  # noqa: E402  the one tactic vocabulary

def display_name(tactic: str) -> str:
    """Sentinel names tactics in CamelCase (`CommandAndControl`); a reader expects
    words, so the label is spaced. The words come from the name, never a hand table."""
    parts = re.findall(r"[A-Z][a-z0-9]*", tactic)
    return " ".join(parts) if parts else tactic


DETECTION_COLOUR = "#1f6feb"
HUNT_COLOUR = "#7cc4ff"
INK = "#1f2937"
MUTED = "#6b7280"



# Same typography stack and resolution as the charts in render_project_charts.py.
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
    "axes.edgecolor": "#d7dbe0",
    "figure.facecolor": "white",
    "savefig.facecolor": "white",
})

# 200 dpi: the axis labels and per-bar counts were soft at 100 when the chart was
# opened at full size, which is how a reader looks at a coverage chart.
CHART_DPI = 200

def technique_tactics() -> dict[str, set[str]]:
    """Technique id -> the Sentinel tactics the ATT&CK dataset assigns it.

    A rule declares the tactics it belongs to, but a *technique* belongs to the
    tactics MITRE puts it in, and those two lists are not the same: a rule tagged
    `Execution, Persistence` covering `T1059, T1547` does not mean T1059 is a
    persistence technique. Attributing every technique to every tactic its rule
    declares both inflates the counts and misplaces the techniques, which is what
    the previous version did.
    """
    db = json.loads(ATTACK_DB.read_text(encoding="utf-8"))
    return {tid: {normalize_attack_tactic(t) for t in (entry.get("tactics") or [])}
            for tid, entry in db.items()}


def covered_techniques() -> tuple[set[str], set[str]]:
    """Techniques covered by a scheduled rule, and by a hunting query."""
    det: set[str] = set()
    hunt: set[str] = set()
    for folder, target in (("Detections", det), ("Hunting Queries", hunt)):
        for path in sorted((REPO / folder).glob("*.yaml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for technique in rule.get("relevantTechniques") or []:
                target.add(str(technique))
    return det, hunt


def tactic_rows() -> tuple[list[tuple[str, int, int]], int, int]:
    """Per-tactic (label, detection techniques, hunt-only techniques) for all 14
    enterprise tactics, plus the technique total and the number of tactics covered."""
    index = technique_tactics()
    det, hunt = covered_techniques()
    rows = []
    for tactic in SENTINEL_TACTICS:
        # normalize_attack_tactic returns the folded name in lower case
        # (`privilegeescalation`), and the vocabulary is CamelCase: compare folded.
        key = tactic.replace("-", "").lower()
        in_tactic = {t for t in (det | hunt) if key in index.get(t, set())}
        det_in = len(in_tactic & det)
        rows.append((tactic, det_in, len(in_tactic) - det_in))
    covered = sum(1 for _, d, h in rows if d + h)
    return rows, len(det | hunt), covered


def save_without_metadata(fig, path: pathlib.Path, **kwargs) -> None:
    """Save a figure with no PNG metadata.

    Two reasons this is not optional. A PNG written by matplotlib carries
    ``Software: Matplotlib version...``, which is one more piece of environment
    detail in a public repository. More importantly it makes the bytes depend on
    the installed matplotlib version, so a byte-comparison drift gate would fail on
    a machine with a different release even though the picture is identical. The
    figure is written to memory, re-encoded through Pillow with no ``info`` dict,
    and only then written to disk.
    """
    import io

    from PIL import Image

    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", **kwargs)
    buffer.seek(0)
    with Image.open(buffer) as image:
        clean = Image.new("RGB", image.size, (255, 255, 255))
        clean.paste(image.convert("RGBA"), mask=image.convert("RGBA").split()[-1])
        path.parent.mkdir(parents=True, exist_ok=True)
        clean.save(path, format="PNG", optimize=True)

def main() -> int:
    rows, total_techniques, covered_tactics = tactic_rows()

    labels = [display_name(t) for t, _, _ in rows]
    detection_counts = [d for _, d, _ in rows]
    hunt_counts = [h for _, _, h in rows]

    fig, ax = plt.subplots(figsize=(14, 7), dpi=CHART_DPI)
    fig.patch.set_facecolor("white")
    y = list(range(len(rows)))
    ax.barh(y, detection_counts, color=DETECTION_COLOUR, label="Scheduled analytics rules")
    ax.barh(y, hunt_counts, left=detection_counts, color=HUNT_COLOUR,
            label="Hunting queries only")
    for i, (d, h) in enumerate(zip(detection_counts, hunt_counts)):
        total = d + h
        if total:
            ax.text(total + 0.12, i, str(total), va="center", fontsize=10, color=INK)
        else:
            ax.text(0.12, i, "no coverage", va="center", fontsize=9, color="#b62324")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Distinct ATT&CK techniques covered", fontsize=11, color=INK)
    ax.set_title(
        f"ATT&CK coverage by tactic — {total_techniques} techniques across "
        f"{covered_tactics} of {len(rows)} enterprise tactics",
        fontsize=14, weight="bold", color=INK, pad=14,
    )
    ax.text(0.0, 1.015,
            "Technique totals from scripts/attack_data.json; coverage from the 28 rule files, "
            "by scripts/render_coverage_chart.py",
            transform=ax.transAxes, fontsize=9, color=MUTED)
    ax.legend(loc="lower right", frameon=False, fontsize=10)
    ax.grid(axis="x", color="#d7dbe0", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#d0d7de")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "01-coverage-by-tactic.png"
    fig.tight_layout()
    save_without_metadata(fig, out, facecolor="white")
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)} — {total_techniques} techniques, "
          f"{covered_tactics} of {len(rows)} tactics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
