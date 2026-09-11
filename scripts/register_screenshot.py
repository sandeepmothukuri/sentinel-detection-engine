#!/usr/bin/env python3
"""File a real screenshot into docs/images/ and register it in docs/evidence.md.

The repository ships no screenshot of a live tenant, and cannot: a repository
cannot capture a workspace. This script is the way one gets in — it does the four
things that are easy to get wrong, so the only thing left for you is to actually
capture it.

What it does
------------
1. **Strips metadata.** A screen capture carries EXIF and PNG text chunks:
   device make and model, capture timestamp, sometimes GPS, often the operating
   system username in the encoder field. Re-encoding through Pillow drops all of
   it. `tests/test_evidence.py` fails the build if any committed image still
   carries metadata, so this is enforced and not merely offered.
2. **Places and names it** per the convention the walkthrough uses:
   `docs/images/<area>/<NN>-lab-<slug>.png`.
3. **Writes a register entry** into `docs/evidence.md` in the same format as every
   other entry, with an empty `Demonstrates` line for you to fill in — the script
   will not write that for you, because only you saw the screen.
4. **Records a checksum**, so a later reader can tell whether the file changed.
5. **Flips the shot's status** in `docs/images/capture-manifest.yaml` when you pass
   `--manifest-id`, so the checklist in that file cannot drift away from what is on
   disk. `tests/test_evidence.py` fails on the drift either way.

What it refuses to do
---------------------
* It will not invent an environment, a date or a redaction list. Those are
  required arguments: they are your assertion about what you captured, and the
  register entry is worthless without them.
* It will not overwrite an existing image or register entry without `--force`.
* It will not accept an image that is too small to be a screenshot of a console,
  or a file that is not an image at all.

Before you run it, redact the picture itself
--------------------------------------------
The script removes file metadata. It cannot remove what is *in* the pixels.
Blur or paint over subscription ids, tenant ids, workspace ids, user principal
names, e-mail addresses, IP addresses, organisation names, hostnames, tokens and
secrets — in the browser, before you save, or in an image editor afterwards. Then
list what you redacted in `--redactions`, which is published verbatim.

Usage
-----
    python scripts/register_screenshot.py capture.png \\
        --area sentinel \\
        --slug workspace-overview \\
        --purpose "The lab workspace with Sentinel enabled and the connectors connected" \\
        --environment "Single-author lab: Azure free tier, one Log Analytics workspace, E5 developer tenant" \\
        --redactions "Subscription id and workspace id painted over; tenant domain cropped" \\
        --manifest-id sentinel-workspace-overview

The shot list, the portal path for each capture and the redaction checklist live in
`docs/images/capture-guide.md`.

Then open docs/evidence.md and complete the `Demonstrates` line.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import pathlib
import re
import sys

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    print("::error::Pillow is required: pip install pillow", file=sys.stderr)
    raise SystemExit(2)

REPO = pathlib.Path(__file__).resolve().parent.parent
IMAGES = REPO / "docs" / "images"
EVIDENCE = REPO / "docs" / "evidence.md"
CAPTURE_MANIFEST = REPO / "docs" / "images" / "capture-manifest.yaml"

AREAS = ["architecture", "sentinel", "detections", "hunting", "soar", "workbooks", "attack", "ci-cd"]

# A console screenshot is never this small. Below it, the file is probably an
# icon, a cropped fragment, or not what the argument says it is.
MIN_WIDTH, MIN_HEIGHT = 600, 320

NAME_RE = re.compile(r"^(\d{2})-lab-([a-z0-9-]+)\.png$")


class IntakeError(RuntimeError):
    pass


def next_number(area: str) -> str:
    """Two-digit prefix, continuing the area's sequence (generated images use 01+)."""
    used = set()
    for path in (IMAGES / area).glob("*.png"):
        m = re.match(r"^(\d{2})-", path.name)
        if m:
            used.add(int(m.group(1)))
    n = 10  # lab captures start at 10 so they never collide with generated diagrams
    while n in used:
        n += 1
    if n > 99:
        raise IntakeError(f"{area} has run out of two-digit numbers")
    return f"{n:02d}"


def load_and_strip(source: pathlib.Path) -> tuple[Image.Image, dict]:
    """Open the capture and report what metadata is being discarded."""
    try:
        image = Image.open(source)
        image.load()
    except Exception as exc:
        raise IntakeError(f"{source} is not an image Pillow can read: {exc}") from exc

    found = {}
    exif = getattr(image, "getexif", lambda: None)()
    if exif:
        from PIL.ExifTags import TAGS
        found["exif"] = [TAGS.get(k, str(k)) for k in exif.keys()]
    for key in ("Software", "Author", "Comment", "Copyright", "Creation Time", "Source", "Title"):
        value = image.info.get(key)
        if value:
            found.setdefault("text", []).append(f"{key}={str(value)[:40]}")
    if "icc_profile" in image.info:
        found["color profile"] = ["kept (not identifying)"]

    rgba = image.convert("RGBA")
    return rgba, found


def write_image(image: Image.Image, destination: pathlib.Path) -> str:
    """Re-encode as PNG with no metadata, and return the file's SHA-256."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    clean = Image.new("RGB", image.size, (255, 255, 255))
    clean.paste(image, mask=image.split()[-1])
    clean.save(destination, format="PNG", optimize=True)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    (destination.with_suffix(".png.sha256")).write_text(
        f"{digest}  {destination.name}\n", encoding="utf-8")
    return digest


def register_entry(rel: str, area: str, purpose: str, environment: str,
                   redactions: str, date: str, digest: str, notes: str) -> str:
    entry = [
        f"### `{rel}`",
        "- **Provenance class:** Screenshot",
        "- **Source:** Captured by the repository owner in the environment described below and filed "
        "with `scripts/register_screenshot.py`.",
        f"- **Environment:** {environment}",
        f"- **Date:** {date}",
        f"- **Demonstrates:** **TODO — one sentence, written by the person who took the screenshot.** "
        f"Context supplied at intake: {purpose}",
        f"- **Redactions:** {redactions}. File metadata (EXIF and PNG text chunks) is stripped by the "
        "intake script; the image is re-encoded losslessly, so the pixels are otherwise unchanged.",
        f"- **SHA-256:** `{digest}` — the register records the exact bytes that were reviewed.",
    ]
    if notes:
        entry.append(f"- **Notes:** {notes}")
    entry += [
        "",
        "> This capture is evidence that the named environment existed in the state shown on the date",
        "> given. It is **not** validation of a rule: a screenshot of a workspace is not a rule firing,",
        "> and a rule's validation status changes only through",
        "> [`../tests/validation/atomics.yaml`](../tests/validation/atomics.yaml).",
        "",
    ]
    return "\n".join(entry)


def append_to_register(area: str, entry: str) -> None:
    text = EVIDENCE.read_text(encoding="utf-8")
    heading = f"\n## {area}\n"
    if heading not in text:
        raise IntakeError(
            f"docs/evidence.md has no '{area}' section. Add one, or file the image under an area "
            f"that exists ({', '.join(AREAS)}).")
    start = text.index(heading) + len(heading)
    # Insert at the end of this section: before the next H2, or at the end of the file.
    rest = text[start:]
    match = re.search(r"\n## ", rest)
    if match:
        insert_at = start + match.start() + 1
        updated = text[:insert_at] + entry + "\n" + text[insert_at:]
    else:
        updated = text.rstrip("\n") + "\n\n" + entry
    EVIDENCE.write_text(updated, encoding="utf-8")


def mark_captured(text: str, shot_id: str, rel: str, date: str) -> str:
    """Flip one shot in the capture manifest from pending to captured.

    Text surgery rather than a YAML round-trip, for the same reason the playbook
    ARM templates are patched by string replacement: re-serialising the file would
    rewrite every comment in it. The block is located by its `- id:` line and ends
    at the next one.
    """
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if l.strip() == f"- id: {shot_id}"), None)
    if start is None:
        raise IntakeError(
            f"capture-manifest.yaml has no shot with id '{shot_id}'. Add it to "
            f"docs/images/capture-manifest.yaml, or drop --manifest-id.")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("  - id:")),
               len(lines))

    block = "".join(lines[start:end])
    if "status: captured" in block:
        raise IntakeError(f"shot '{shot_id}' is already marked captured in the manifest.")
    for field, value in (("status:", "captured"), ("file:", rel)):
        at = next((i for i in range(start, end) if lines[i].strip().startswith(field)), None)
        if at is None:
            raise IntakeError(f"shot '{shot_id}' has no '{field}' line to update.")
        indent = lines[at][:len(lines[at]) - len(lines[at].lstrip())]
        lines[at] = f"{indent}{field} {value}\n"
    at = next(i for i in range(start, end) if lines[i].strip().startswith("status:"))
    # quoted, so YAML hands the date back as text rather than as a date object
    lines.insert(at + 1,
                 f'{lines[at][:len(lines[at]) - len(lines[at].lstrip())]}captured: "{date}"\n')
    return "".join(lines)


def update_manifest(shot_id: str, rel: str, date: str, force: bool) -> None:
    """Record the capture in the manifest, refusing to overwrite a recorded one."""
    if not CAPTURE_MANIFEST.exists():
        raise IntakeError(f"{CAPTURE_MANIFEST.relative_to(REPO)} is missing.")
    text = CAPTURE_MANIFEST.read_text(encoding="utf-8")
    if force:
        block_start = text.index(f"- id: {shot_id}")
        block_end = text.find("- id:", block_start + 1)
        block = text[block_start:block_end if block_end > 0 else len(text)]
        text = text[:block_start] + block.replace("status: captured", "status: pending", 1) \
            .replace("captured: ", "superseded: ", 1) + text[block_end if block_end > 0 else len(text):]
    CAPTURE_MANIFEST.write_text(mark_captured(text, shot_id, rel, date), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", help="the screenshot file, as captured")
    parser.add_argument("--area", required=True, choices=AREAS)
    parser.add_argument("--slug", required=True, help="short kebab-case description, e.g. workspace-overview")
    parser.add_argument("--purpose", required=True,
                        help="what the picture is for; becomes part of the register entry")
    parser.add_argument("--environment", required=True,
                        help="what had to exist for the capture, e.g. 'lab: free-tier workspace, E5 dev tenant'")
    parser.add_argument("--redactions", required=True,
                        help="what you removed, or 'none required' with the reason")
    parser.add_argument("--date", default=dt.date.today().isoformat())
    parser.add_argument("--notes", default="")
    parser.add_argument("--manifest-id", default="",
                        help="id of the shot in docs/images/capture-manifest.yaml; marks it captured")
    parser.add_argument("--force", action="store_true", help="overwrite an existing image and entry")
    args = parser.parse_args(argv)

    source = pathlib.Path(args.source).expanduser()
    if not source.exists():
        print(f"::error::no such file: {source}", file=sys.stderr)
        return 2
    if not re.match(r"^[a-z0-9-]+$", args.slug):
        print("::error::--slug must be lower-case kebab-case", file=sys.stderr)
        return 2

    manifest_text = CAPTURE_MANIFEST.read_text(encoding="utf-8") if CAPTURE_MANIFEST.exists() else ""
    if args.manifest_id:
        if f"- id: {args.manifest_id}" not in manifest_text:
            print(f"::error::no shot with id '{args.manifest_id}' in "
                  f"{CAPTURE_MANIFEST.relative_to(REPO)}. See docs/images/capture-guide.md.",
                  file=sys.stderr)
            return 2
        if not args.force and "status: captured" in \
                manifest_text.split(f"- id: {args.manifest_id}")[1].split("- id:")[0]:
            print(f"::error::shot '{args.manifest_id}' is already captured. Use --force to supersede it.",
                  file=sys.stderr)
            return 2

    try:
        image, discarded = load_and_strip(source)
    except IntakeError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    if image.width < MIN_WIDTH or image.height < MIN_HEIGHT:
        print(f"::error::{source.name} is {image.width}x{image.height}. A console screenshot is at least "
              f"{MIN_WIDTH}x{MIN_HEIGHT}; this is probably a fragment or an icon.", file=sys.stderr)
        return 2

    area_dir = IMAGES / args.area
    destination = area_dir / f"{next_number(args.area)}-lab-{args.slug}.png"
    if destination.exists() and not args.force:
        print(f"::error::{destination.relative_to(REPO)} exists. Use --force to replace it.",
              file=sys.stderr)
        return 2

    rel = destination.relative_to(IMAGES).as_posix()
    if f"`{rel}`" in EVIDENCE.read_text(encoding="utf-8") and not args.force:
        print(f"::error::docs/evidence.md already registers {rel}.", file=sys.stderr)
        return 2

    digest = write_image(image, destination)

    try:
        append_to_register(args.area, register_entry(
            rel, args.area, args.purpose, args.environment, args.redactions,
            args.date, digest, args.notes))
    except IntakeError as exc:
        destination.unlink(missing_ok=True)
        destination.with_suffix(".png.sha256").unlink(missing_ok=True)
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    if args.manifest_id:
        try:
            update_manifest(args.manifest_id, f"docs/images/{rel}", args.date, args.force)
        except IntakeError as exc:
            print(f"::warning::{exc}", file=sys.stderr)
        else:
            print(f"manifest  {args.manifest_id} -> captured")

    print(f"filed     docs/images/{rel}")
    print(f"sha256    {digest[:16]}…")
    print(f"registered docs/evidence.md under '## {args.area}'")
    if discarded:
        summary = "; ".join(f"{k}: {', '.join(v) if isinstance(v, list) else v}"
                            for k, v in discarded.items())
        print(f"stripped  {summary}")
    else:
        print("stripped  no metadata was present")
    print()
    print("Two things left, both of which need you rather than a tool:")
    print(f"  1. Complete the 'Demonstrates' line for `{rel}` in docs/evidence.md.")
    print("  2. If the picture shows anything you meant to redact, redact it and re-run with --force.")
    print()
    print("Then: python -m pytest tests -q && python scripts/check_links.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
