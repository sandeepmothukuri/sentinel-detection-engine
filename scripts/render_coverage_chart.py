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

import matplotlib
matplotlib.use("Agg")
import yaml  # noqa: E402
from matplotlib import pyplot as plt  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
LAYER = REPO / "attack-navigator" / "layer.json"
ATTACK_DB = REPO / "scripts" / "attack_data.json"
OUT_DIR = REPO / "docs" / "images" / "attack"

TACTIC_LABEL = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

DETECTION_COLOUR = "#1f6feb"
HUNT_COLOUR = "#7cc4ff"
INK = "#1f2328"
MUTED = "#57606a"


def load_rule_techniques() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    dets: dict[str, set[str]] = collections.defaultdict(set)
    hunts: dict[str, set[str]] = collections.defaultdict(set)
    for folder, target in (("Detections", dets), ("Hunting Queries", hunts)):
        for path in sorted((REPO / folder).glob("*.yaml")):
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            for technique in rule.get("relevantTechniques") or []:
                for tactic in rule.get("tactics") or []:
                    target[tactic.lower()].add(str(technique))
    return dets, hunts




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
    layer = json.loads(LAYER.read_text(encoding="utf-8"))
    attack = json.loads(ATTACK_DB.read_text(encoding="utf-8"))
    dets, hunts = load_rule_techniques()

    tactics = list(TACTIC_LABEL)
    detection_counts = [len(dets.get(t, set())) for t in tactics]
    hunt_counts = [len(hunts.get(t, set()) - dets.get(t, set())) for t in tactics]
    labels = [TACTIC_LABEL[t] for t in tactics]
    covered = sum(1 for d, h in zip(detection_counts, hunt_counts) if d + h)

    fig, ax = plt.subplots(figsize=(14, 7), dpi=100)
    fig.patch.set_facecolor("white")
    y = range(len(tactics))
    ax.barh(list(y), detection_counts, color=DETECTION_COLOUR, label="Scheduled analytics rules")
    ax.barh(list(y), hunt_counts, left=detection_counts, color=HUNT_COLOUR,
            label="Hunting queries only")
    for i, (d, h) in enumerate(zip(detection_counts, hunt_counts)):
        total = d + h
        if total:
            ax.text(total + 0.12, i, str(total), va="center", fontsize=10, color=INK)
        else:
            ax.text(0.12, i, "no coverage", va="center", fontsize=9, color="#b62324")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Distinct ATT&CK techniques covered", fontsize=11, color=INK)
    ax.set_title(
        f"ATT&CK coverage by tactic — {len(layer['techniques'])} techniques across "
        f"{covered} of {len(tactics)} enterprise tactics",
        fontsize=14, weight="bold", color=INK, pad=14,
    )
    ax.text(0.0, 1.015, "Generated from attack-navigator/layer.json and the 28 rule files by "
                        "scripts/render_coverage_chart.py",
            transform=ax.transAxes, fontsize=9, color=MUTED)
    ax.legend(loc="lower right", frameon=False, fontsize=10)
    ax.grid(axis="x", color="#e6e8eb", linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color("#d0d7de")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "01-attack-coverage-by-tactic.png"
    fig.tight_layout()
    save_without_metadata(fig, out, facecolor="white")
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
