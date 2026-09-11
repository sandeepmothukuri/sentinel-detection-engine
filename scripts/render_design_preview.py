#!/usr/bin/env python3
"""Draw the L3 Triage Dashboard design preview.

Why a script and not a screenshot: this repository has no tenant to screenshot.
The honest artefact is a layout drawing that (a) is visibly labelled as a design
preview, (b) carries no telemetry numbers at all, and (c) is generated from the
deployable workbook definition so the preview cannot drift from the workbook.

    python scripts/render_design_preview.py            # writes the PNG
    python scripts/render_design_preview.py --check    # verify it is up to date

The panel titles and data sources are read from Workbooks/L3-Triage-Dashboard.json.
Every tile shows "—" where a value would appear once the workbook is deployed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import textwrap

import matplotlib
matplotlib.use("Agg")
from matplotlib import patches  # noqa: E402
from matplotlib import pyplot as plt  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKBOOK = REPO / "Workbooks" / "L3-Triage-Dashboard.json"
OUTPUT = REPO / "docs" / "images" / "workbooks" / "01-triage-dashboard-design-preview.png"
HASH_FILE = REPO / "docs" / "images" / "workbooks" / "01-triage-dashboard-design-preview.sha256"

# The banner is a hard requirement of this repository's image policy: a mockup
# must never be mistakable for a screenshot of a live workspace.
BANNER = "DESIGN PREVIEW — REQUIRES DEPLOYMENT TO DISPLAY LIVE TELEMETRY"
SUBTITLE = ("Panel layout only. Contains no tenant data, no incident numbers and no metrics. "
            "Generated from Workbooks/L3-Triage-Dashboard.json.")

W, H = 1600, 1000
BG = "#ffffff"
INK = "#1f2328"
MUTED = "#57606a"
BORDER = "#d0d7de"
TILE = "#f6f8fa"
TILE_ACCENT = "#ddf4ff"
BANNER_BG = "#fff8c5"
BANNER_EDGE = "#d4a72c"

FONT = {"family": "DejaVu Sans"}


def load_panels() -> list[dict]:
    """Panel title, table and query type, taken from the workbook itself."""
    workbook = json.loads(WORKBOOK.read_text(encoding="utf-8"))
    panels: list[dict] = []
    for item in workbook["items"]:
        content = item.get("content") or {}
        if "query" in content:
            query = content["query"]
            tables = re.findall(r"\b(SecurityIncident|SecurityAlert)\b", query)
            panels.append({
                "name": item.get("name", ""),
                "title": content.get("title", ""),
                "source": " + ".join(sorted(set(tables))) if tables else "union of log tables",
            })
    return panels


def shorten(text: str, width: int = 30) -> str:
    return "\n".join(textwrap.wrap(text, width))


def draw() -> None:
    panels = load_panels()
    if not panels:
        raise SystemExit("no panels found in the workbook — nothing to preview")

    fig = plt.figure(figsize=(W / 100, H / 100), dpi=100)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")
    ax.add_patch(patches.Rectangle((0, 0), W, H, facecolor=BG, edgecolor="none"))

    # --- banner -----------------------------------------------------------
    ax.add_patch(patches.Rectangle((30, H - 96), W - 60, 66, facecolor=BANNER_BG,
                                   edgecolor=BANNER_EDGE, linewidth=2))
    ax.text(50, H - 52, BANNER, fontsize=19, weight="bold", color="#7a4f01", **FONT)
    ax.text(50, H - 78, shorten(SUBTITLE, 150), fontsize=10.5, color="#7a4f01", **FONT)

    ax.text(30, H - 122, "L3 Triage Dashboard", fontsize=17, weight="bold", color=INK, **FONT)
    ax.text(W - 30, H - 122, "sentinel-detection-engine · author: Sandeep Mothukuri",
            fontsize=10.5, color=MUTED, ha="right", **FONT)

    # --- time range control ----------------------------------------------
    ax.add_patch(patches.FancyBboxPatch((30, H - 168), 520, 32,
                                        boxstyle="round,pad=0,rounding_size=16",
                                        facecolor="#eaeef2", edgecolor=BORDER))
    ax.text(46, H - 147, "Time range:   1h    4h    24h    7d    30d",
            fontsize=11, color=INK, **FONT)
    ax.text(570, H - 147, "← parameter, resolves to {TimeRange} in every panel",
            fontsize=10, color=MUTED, **FONT)

    # --- panel grid -------------------------------------------------------
    cols = 4
    rows = max(1, -(-len(panels) // cols))
    top = H - 190
    bottom = 78
    grid_h = top - bottom
    tile_w = (W - 60 - (cols - 1) * 14) / cols
    tile_h = (grid_h - (rows - 1) * 14) / rows

    for i, panel in enumerate(panels):
        r, c = divmod(i, cols)
        x = 30 + c * (tile_w + 14)
        y = top - (r + 1) * tile_h - r * 14
        ax.add_patch(patches.Rectangle((x, y), tile_w, tile_h, facecolor=TILE,
                                       edgecolor=BORDER, linewidth=1.2))
        ax.add_patch(patches.Rectangle((x, y + tile_h - 4), tile_w, 4,
                                       facecolor=TILE_ACCENT, edgecolor="none"))
        ax.text(x + 10, y + tile_h - 26, shorten(panel["title"], 34),
                fontsize=10, weight="bold", color=INK, va="top", **FONT)
        ax.text(x + 10, y + 26, f"source: {panel['source']}", fontsize=8.5, color=MUTED, **FONT)
        ax.text(x + tile_w - 10, y + 26, "—", fontsize=13, color=MUTED, ha="right", **FONT)

    # --- footer -----------------------------------------------------------
    ax.add_patch(patches.Rectangle((0, 0), W, 46, facecolor="white", edgecolor="none"))
    ax.text(30, 24, "Not a screenshot. Regenerate with scripts/render_design_preview.py after "
                    "changing the workbook.",
            fontsize=9.5, color=MUTED, **FONT)
    ax.text(W - 30, 24, f"{len(panels)} panels · layout preview", fontsize=9.5,
            color=MUTED, ha="right", **FONT)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT, dpi=100, facecolor=BG)
    plt.close(fig)


def digest() -> str:
    return hashlib.sha256(OUTPUT.read_bytes()).hexdigest() if OUTPUT.exists() else ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the documented digest does not match the image on disk")
    args = parser.parse_args()

    if args.check:
        recorded = HASH_FILE.read_text(encoding="utf-8").split()[0] if HASH_FILE.exists() else ""
        actual = digest()
        if not actual:
            print("::error::design preview image is missing", file=sys.stderr)
            return 1
        if recorded != actual:
            print(f"::error::design preview digest mismatch: recorded {recorded[:16]} "
                  f"actual {actual[:16]}. Re-run scripts/render_design_preview.py and commit.",
                  file=sys.stderr)
            return 1
        print(f"design preview matches its recorded digest ({actual[:16]})")
        return 0

    draw()
    HASH_FILE.write_text(f"{digest()}  {OUTPUT.name}\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO)} and its digest")


if __name__ == "__main__":
    raise SystemExit(main())
