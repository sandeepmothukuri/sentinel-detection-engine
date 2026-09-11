#!/usr/bin/env python3
"""Render the Mermaid diagram sources in docs/diagrams/ to PNG under docs/images/.

Every image under docs/images/ that is not a captured screenshot is produced by
this script, so the diagram in the documentation and the diagram in the image
cannot drift: both come from the .mmd file committed next to it.

    python scripts/render_diagrams.py            # render missing or stale images
    python scripts/render_diagrams.py --force    # re-render everything
    python scripts/render_diagrams.py --check    # list what is stale, change nothing

The workbook design preview is not a Mermaid diagram: it is drawn by
scripts/render_design_preview.py so that its "design preview" banner is part of
the image and cannot be cropped away or missed.

Rendering goes through the public mermaid.ink renderer, so this script needs
network access and is deliberately NOT part of the CI pipeline: CI validates the
repository, it does not depend on a third-party rendering service being up. The
PNGs are committed, and docs/evidence.md records, per image, which diagram source
produced it.

Widths are chosen per diagram so that text stays legible without the image
becoming enormous. Override with --width.
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE_ROOT = REPO / "docs" / "diagrams"
IMAGE_ROOT = REPO / "docs" / "images"
RENDERER = "https://mermaid.ink/img/"

# Diagram source (relative to docs/diagrams) -> (image path relative to
# docs/images, width in pixels).
LAYOUT: dict[str, tuple[str, int]] = {
    "architecture/01-logical-architecture.mmd": ("architecture/01-logical-architecture.png", 0),
    "architecture/02-telemetry-to-detection-flow.mmd": ("architecture/02-telemetry-to-detection-flow.png", 0),
    "architecture/03-deployment-paths.mmd": ("architecture/03-deployment-paths.png", 0),
    "sentinel/01-connector-table-coverage.mmd": ("sentinel/01-connector-table-coverage.png", 0),
    "sentinel/02-evidence-and-validation-model.mmd": ("sentinel/02-evidence-and-validation-model.png", 0),
    "detections/01-rule-development-lifecycle.mmd": ("detections/01-rule-development-lifecycle.png", 0),
    "detections/02-analytics-rule-anatomy.mmd": ("detections/02-analytics-rule-anatomy.png", 0),
    "detections/03-tuning-and-feedback-loop.mmd": ("detections/03-tuning-and-feedback-loop.png", 0),
    "hunting/01-hunt-to-detection-workflow.mmd": ("hunting/01-hunt-to-detection-workflow.png", 0),
    "soar/01-soar-safety-gate-flow.mmd": ("soar/01-soar-safety-gate-flow.png", 0),
    "soar/02-ir-lifecycle.mmd": ("soar/02-ir-lifecycle.png", 0),
    "attack/04-attack-v19-domain-change.mmd": ("attack/04-attack-v19-domain-change.png", 0),
    "ci-cd/01-validation-pipeline.mmd": ("ci-cd/01-validation-pipeline.png", 0),
    "ci-cd/02-release-and-pr-automation.mmd": ("ci-cd/02-release-and-pr-automation.png", 0),
}

USER_AGENT = "sentinel-detection-engine-diagram-renderer/1.0"

# One palette for every diagram in the repository, sent to the renderer as Mermaid
# configuration rather than hand-styled per figure. Mermaid's stock themes are
# functional but inconsistent: `neutral` renders diagrams in flat grey, `default`
# in saturated purple-blue, and either way two diagrams drawn a month apart do not
# look like they came from the same document. This is Mermaid's `base` theme with
# the variables pinned to the palette used across the documentation — navy for
# structure, slate for edges, a very light blue fill — so a reader moving between
# the architecture diagram and the SOAR gate diagram is not re-learning the
# visual language each time. It also sets the spacing outright, because the default
# node packing is tight enough that edge labels collide on wider flows.
MERMAID_THEME: dict = {
    "theme": "base",
    "themeVariables": {
        "fontFamily": "Segoe UI, Helvetica, Arial, sans-serif",
        "fontSize": "14px",
        "primaryColor": "#eaf1fa",
        "primaryTextColor": "#12161c",
        "primaryBorderColor": "#1f4e79",
        "secondaryColor": "#f4f6f9",
        "tertiaryColor": "#ffffff",
        "lineColor": "#5a6472",
        "textColor": "#12161c",
        "mainBkg": "#eaf1fa",
        "nodeBorder": "#1f4e79",
        "clusterBkg": "#f7f9fc",
        "clusterBorder": "#c8d3e0",
        "edgeLabelBackground": "#ffffff",
    },
    "flowchart": {
        "curve": "basis",
        "nodeSpacing": 45,
        "rankSpacing": 60,
        "padding": 12,
        "useMaxWidth": False,
    },
}


class RenderError(RuntimeError):
    pass


def source_body(path: pathlib.Path) -> str:
    """The full .mmd source, front-matter included.

    The front-matter carries the diagram title and Mermaid renders it into the
    image, so it is deliberately kept: an image whose title says "design preview"
    cannot be mistaken for a screenshot of a live system.
    """
    return path.read_text(encoding="utf-8").strip()


def render(code: str, width: int, timeout: int = 60) -> bytes:
    payload = base64.urlsafe_b64encode(
        json.dumps({"code": code, "mermaid": MERMAID_THEME}).encode("utf-8")
    ).decode("ascii")
    size = f"&width={width}" if width else ""
    url = f"{RENDERER}{payload}?type=png{size}&bgColor=FFFFFF"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in (1, 2, 3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if not data.startswith(b"\x89PNG"):
                raise RenderError("renderer did not return a PNG")
            return data
        except (urllib.error.URLError, urllib.error.HTTPError, RenderError) as exc:
            if attempt == 3:
                raise RenderError(f"{exc}") from exc
    raise RenderError("unreachable")  # pragma: no cover


def is_stale(source: pathlib.Path, image: pathlib.Path) -> bool:
    if not image.exists():
        return True
    return source.stat().st_mtime > image.stat().st_mtime


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-render every diagram")
    parser.add_argument("--check", action="store_true",
                        help="report stale images and exit non-zero; render nothing")
    parser.add_argument("--width", type=int, default=0, help="override the width for every diagram")
    parser.add_argument("--only", default="", help="render diagrams whose path contains this string")
    args = parser.parse_args()

    missing_sources = [s for s in LAYOUT if not (SOURCE_ROOT / s).exists()]
    if missing_sources:
        for s in missing_sources:
            print(f"::error::diagram source missing: docs/diagrams/{s}", file=sys.stderr)
        return 1

    stale: list[str] = []
    failures: list[str] = []
    for rel_source, (rel_image, width) in sorted(LAYOUT.items()):
        if args.only and args.only not in rel_source and args.only not in rel_image:
            continue
        source = SOURCE_ROOT / rel_source
        image = IMAGE_ROOT / rel_image
        if not args.force and not is_stale(source, image):
            print(f"current  {rel_image}")
            continue
        stale.append(rel_image)
        if args.check:
            print(f"STALE    {rel_image}")
            continue
        image.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = render(source_body(source), args.width or width)
        except RenderError as exc:
            failures.append(f"{rel_image}: {exc}")
            print(f"::error::render failed for {rel_image}: {exc}", file=sys.stderr)
            continue
        image.write_bytes(data)
        print(f"rendered {rel_image} ({len(data) // 1024} KiB)")

    if args.check:
        if stale:
            print(f"\n{len(stale)} image(s) are older than their diagram source. "
                  f"Run: python scripts/render_diagrams.py")
            return 1
        print("\nAll rendered images are newer than their diagram sources.")
        return 0

    if failures:
        print(f"\n{len(failures)} diagram(s) failed to render. The .mmd source is still "
              f"committed and is the canonical diagram; re-run when the renderer is "
              f"reachable.", file=sys.stderr)
        return 1
    print(f"\n{len(stale)} image(s) rendered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
