#!/usr/bin/env python3
"""Generate `docs/images/gallery.md` — every image, in order, described once.

The gallery is a *derived* document: the headline of each entry (its provenance
class and what it demonstrates) is copied out of `docs/evidence.md`, and the
"not yet captured" table is copied out of `docs/images/capture-manifest.yaml`.
Typing it by hand is how a gallery starts disagreeing with the register it is
supposed to mirror, so it is generated and CI fails on drift:

    python scripts/generate_image_gallery.py            # write the file
    python scripts/generate_image_gallery.py --check    # fail if it is stale

What is *not* derived: the area headings and their one-line blurbs, and the two
intro paragraphs. Those are editorial and live in this file, because no other
file states them. Everything a second file already states is read from that file.

An image with no entry in the register, or a register entry with no image on
disk, is an error rather than something to render around — that disagreement is
the defect this script exists to make impossible, not to paper over.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
IMAGES = REPO / "docs" / "images"
GALLERY = IMAGES / "gallery.md"
EVIDENCE = REPO / "docs" / "evidence.md"
MANIFEST = IMAGES / "capture-manifest.yaml"

# Area order is the order a reviewer should meet them: the architecture, then the
# workspace it lands in, then what it detects and hunts, then what acts on it,
# then the coverage, the dashboards, the pipeline, and finally the card.
AREAS: list[tuple[str, str, str]] = [
    ("architecture", "Architecture",
     "How the pieces fit: sources, workspace, rule pipeline, response automation."),
    ("sentinel", "Sentinel workspace",
     "Connectors and tables, the evidence model, and where validation actually stands."),
    ("detections", "Detections",
     "The rule lifecycle, the anatomy of a rule, and the tuning loop."),
    ("hunting", "Hunting", "How a hunt becomes a detection."),
    ("soar", "SOAR",
     "The safety gate that stands between an alert and a destructive action."),
    ("attack", "ATT&CK",
     "Coverage by tactic, the Navigator export, and the v19 domain change."),
    ("workbooks", "Workbooks",
     "The L3 triage dashboard: a data-free wireframe and a labelled sample-data preview."),
    ("ci-cd", "CI/CD", "What runs on every commit, and what happens on a release."),
    ("social", "Social preview", "The card GitHub shows when the repository is linked."),
]

INTRO = """# Image gallery

Every image in the repository, in order. Each one is described in full — purpose, source, environment, date, redactions — in [`../evidence.md`](../evidence.md).

One image is a capture of a real environment (the ATT&CK Navigator export). The rest are diagrams and charts generated from this repository's own files, or the two labelled workbook previews. There is no AI-generated imagery and no mock-up of a system that does not exist.

Captures that are still missing are listed at the end rather than filled in with a drawing.
"""

# Bullets in an evidence.md entry: "- **Field:** value", value continuing on
# wrapped lines indented by two spaces.
ENTRY_RE = re.compile(r"^### `([^`]+\.png)`\s*$", re.MULTILINE)
FIELD_RE = re.compile(r"^- \*\*(?P<field>[A-Za-z ]+):\*\* (?P<value>.*)$", re.MULTILINE)


def read_evidence() -> dict[str, dict[str, str]]:
    """`{ 'area/file.png': {'class': ..., 'demonstrates': ...} }` from the register."""
    text = EVIDENCE.read_text(encoding="utf-8")
    entries: dict[str, dict[str, str]] = {}

    # Split on the entry headings, keeping each entry's body with its path.
    heads = list(ENTRY_RE.finditer(text))
    for i, head in enumerate(heads):
        body_end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[head.end():body_end]
        fields = {}
        for m in FIELD_RE.finditer(body):
            value = m.group("value")
            # Wrapped continuation lines belong to the same field.
            rest = body[m.end():]
            for line in rest.split("\n"):
                if line.startswith("  ") and line.strip():
                    value += " " + line.strip()
                elif line.strip():
                    break
            fields[m.group("field").strip().lower()] = " ".join(value.split())
        if "provenance class" not in fields or "demonstrates" not in fields:
            raise SystemExit(
                f"{head.group(1)} is in docs/evidence.md without a provenance class or a "
                f"`Demonstrates` line; the gallery cannot describe an image the register "
                f"does not.")
        entries[head.group(1)] = {
            "class": fields["provenance class"],
            "demonstrates": fields["demonstrates"],
        }
    return entries


LINK_RE = re.compile(r"\]\((?P<target>[^)#\s]+)(?P<tail>#[^)]*)?\)")


def relink(text: str) -> str:
    """Rewrite relative links so they resolve from `docs/images/`, not `docs/`.

    A `Demonstrates` line is written in the register, which lives in `docs/`, so
    it links to `metrics-matrix.md` and `data-sources.md` by their names there.
    Copied into the gallery verbatim those links break, because the gallery is one
    directory deeper. Only links that resolve from `docs/` **and not** from
    `docs/images/` are rewritten — a link that already resolves from the gallery's
    own directory (a sibling image, `capture-guide.md`) is left exactly as it is.
    Getting this backwards is how a bulk rewrite breaks every link in a file.
    """
    here = IMAGES

    def fix(match: re.Match[str]) -> str:
        target, tail = match.group("target"), match.group("tail") or ""
        if target.startswith(("http://", "https://", "mailto:", "/", "#")):
            return match.group(0)
        if (here / target).exists():
            return match.group(0)
        if (REPO / "docs" / target).exists():
            return f"](../{target}{tail})"
        if (REPO / target).exists():
            return f"]({'../' * 2}{target}{tail})"
        # Not resolvable from anywhere: leave it visible rather than hiding it,
        # and let scripts/check_links.py report it as broken.
        return match.group(0)

    return LINK_RE.sub(fix, text)


def read_pending() -> list[dict]:
    """Shots listed in the capture manifest that have no image yet."""
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    return [s for s in manifest["shots"] if s["status"] != "captured"]


def build() -> str:
    entries = read_evidence()
    on_disk = {p.relative_to(IMAGES).as_posix() for p in IMAGES.rglob("*.png")}

    missing_from_register = sorted(on_disk - set(entries))
    if missing_from_register:
        raise SystemExit(
            "these images are committed but have no entry in docs/evidence.md, so the "
            "gallery would show them with no provenance:\n  "
            + "\n  ".join(missing_from_register))
    missing_from_disk = sorted(set(entries) - on_disk)
    if missing_from_disk:
        raise SystemExit(
            "docs/evidence.md describes images that are not on disk:\n  "
            + "\n  ".join(missing_from_disk))

    out: list[str] = [INTRO]
    for area, title, blurb in AREAS:
        area_images = sorted((e for e in entries if e.startswith(f"{area}/")))
        if not area_images:
            # An empty area is dropped rather than rendered as a heading over
            # nothing: the heading claims there is something to show.
            continue
        out.append(f"\n---\n\n## {title}\n\n{blurb}\n")
        for path in area_images:
            entry = entries[path]
            alt = pathlib.PurePosixPath(path).stem.replace("-", " ")
            out.append(f"\n### `{path}`\n\n![{alt}]({path})\n\n"
                       f"*{entry['class']}* — {relink(entry['demonstrates'])}\n")

    pending = read_pending()
    out.append(
        f"\n---\n\n## Not yet captured\n\nThese {len(pending)} shots are on the list and have "
        f"**no image**. Each needs a live Sentinel tenant, a portal session and the redaction "
        f"list in [`capture-guide.md`](capture-guide.md) — the guide gives the portal path and "
        f"the intake command for every one of them.\n\n"
        f"| Shot | Area | Priority | What it would prove |\n|---|---|:-:|---|\n")
    for shot in sorted(pending, key=lambda s: s["priority"]):
        out.append(f"| `{shot['id']}` | `{shot['area']}` | {shot['priority']} | "
                   f"{shot['proves']} |\n")
    out.append("\nAn empty panel is honest; a drawn one is not.\n")

    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed gallery differs from a fresh build")
    args = parser.parse_args()

    generated = build()
    if args.check:
        current = GALLERY.read_text(encoding="utf-8") if GALLERY.exists() else ""
        if current != generated:
            print("::error::docs/images/gallery.md is stale. Run "
                  "scripts/generate_image_gallery.py and commit the result.",
                  file=sys.stderr)
            return 1
        print("gallery: docs/images/gallery.md matches the register and the manifest")
        return 0

    GALLERY.write_text(generated, encoding="utf-8")
    images = sum(generated.count(f"### `{area}/") for area, _, _ in AREAS)
    print(f"gallery: wrote {GALLERY.relative_to(REPO)} — {images} images, "
          f"{len(read_pending())} pending")
    return 0


if __name__ == "__main__":
    sys.exit(main())
