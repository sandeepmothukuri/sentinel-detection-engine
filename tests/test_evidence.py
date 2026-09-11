#!/usr/bin/env python3
"""Evidence hygiene for the images under docs/images/.

A screenshot is the easiest way to leak a tenant identifier into a public
repository, and the easiest way to imply a validation that never happened. These
tests hold four lines:

1. Every committed image has a register entry (checked in tests/test_diagrams.py;
   repeated here for the intake path).
2. No committed image carries EXIF or PNG text metadata — a capture straight out
   of a browser or snipping tool can carry a device name, a timestamp, and
   sometimes the operating-system username.
3. Every entry claiming to be a Screenshot records an environment, a date and a
   redaction statement. Those three are what make a capture auditable.
4. The register never claims a screenshot proves a detection fired, and no
   Screenshot entry is registered while its `Demonstrates` line is still the
   intake placeholder.
5. The capture manifest and the disk agree: a shot marked captured has its image
   and its register entry, a shot still pending has neither, and every committed
   Screenshot is on the list. The list of what is missing is itself tracked, so
   it cannot quietly become a list of what was forgotten.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from conftest import REPO
from PIL import Image
from register_screenshot import AREAS, IntakeError, mark_captured

IMAGES = REPO / "docs" / "images"
EVIDENCE = REPO / "docs" / "evidence.md"
MANIFEST = IMAGES / "capture-manifest.yaml"
CAPTURE_GUIDE = IMAGES / "capture-guide.md"
PLACEHOLDER = "TODO — one sentence"

# Fields every Screenshot entry must carry, spelled as evidence.md spells them.
REQUIRED_SCREENSHOT_FIELDS = ["**Provenance class:** Screenshot", "**Environment:**",
                              "**Date:**", "**Redactions:**"]

IDENTIFYING_TEXT_KEYS = ["Software", "Author", "Comment", "Copyright", "Creation Time",
                         "Source", "Title", "Description", "XML:com.adobe.xmp", "exif"]


def committed_images() -> list[Path]:
    return sorted(p for p in IMAGES.rglob("*") if p.suffix.lower() in {".png", ".jpg", ".jpeg"})


def evidence_entries() -> dict[str, str]:
    """image file name -> the register block describing it."""
    text = EVIDENCE.read_text(encoding="utf-8")
    entries = {}
    for block in re.split(r"\n### `", text)[1:]:
        name = block.split("`", 1)[0]
        entries[Path(name).name] = block
    return entries


def test_images_exist():
    assert committed_images(), "no images found — did the layout move?"


def test_every_image_has_a_register_entry():
    entries = evidence_entries()
    missing = [p.name for p in committed_images() if p.name not in entries]
    assert not missing, f"images with no docs/evidence.md entry: {missing}"


def test_no_committed_image_carries_identifying_metadata():
    """A capture is not redacted until its metadata is gone too."""
    offenders = []
    for path in committed_images():
        with Image.open(path) as image:
            exif = getattr(image, "getexif", lambda: None)()
            if exif:
                offenders.append(f"{path.relative_to(REPO)}: EXIF block ({len(exif)} tags)")
            for key in IDENTIFYING_TEXT_KEYS:
                value = image.info.get(key)
                if value and key != "icc_profile":
                    offenders.append(f"{path.relative_to(REPO)}: {key}={str(value)[:40]!r}")
    assert not offenders, (
        "these images carry metadata that should have been stripped:\n  " + "\n  ".join(offenders) +
        "\nRe-file them through scripts/register_screenshot.py, which re-encodes without metadata.")


def test_screenshot_entries_record_environment_date_and_redactions():
    entries = evidence_entries()
    incomplete = []
    for path in committed_images():
        block = entries.get(path.name)
        if not block or "**Provenance class:** Screenshot" not in block:
            continue
        for field in REQUIRED_SCREENSHOT_FIELDS:
            if field not in block:
                incomplete.append(f"{path.name} is missing {field}")
        environment = re.search(r"\*\*Environment:\*\* (.+)", block)
        if environment and len(environment.group(1).strip()) < 25:
            incomplete.append(f"{path.name} has a stub environment description")
        redactions = re.search(r"\*\*Redactions:\*\* (.+)", block)
        if redactions and len(redactions.group(1).strip()) < 15:
            incomplete.append(f"{path.name} has a stub redaction statement")
    assert not incomplete, "incomplete screenshot register entries:\n  " + "\n  ".join(incomplete)


def test_no_screenshot_entry_is_still_a_placeholder():
    """Intake writes a TODO into Demonstrate; only a human can complete it."""
    text = EVIDENCE.read_text(encoding="utf-8")
    assert PLACEHOLDER not in text, (
        "docs/evidence.md still contains the intake placeholder for a newly filed screenshot: "
        "write the 'Demonstrates' sentence before committing it.")


def test_register_does_not_claim_a_screenshot_proves_a_detection():
    """The register explains the limit locally, where a reader looking at a
    screenshot will actually see it."""
    text = EVIDENCE.read_text(encoding="utf-8")
    assert "not a Sentinel screenshot" in text or "not** validation" in text, (
        "docs/evidence.md must state that a captured screenshot is not evidence of a detection firing")


def test_screenshot_files_are_named_to_their_convention():
    """Lab captures use an NN-lab-<slug> name so a reader can tell at a glance
    which images came from an environment rather than from a generator."""
    bad = []
    for path in committed_images():
        if "lab-" in path.name:
            if not re.match(r"^\d{2}-lab-[a-z0-9-]+\.png$", path.name):
                bad.append(str(path.relative_to(REPO)))
    assert not bad, f"lab captures must be named NN-lab-<slug>.png: {bad}"


@pytest.mark.parametrize("area", ["architecture", "sentinel", "detections", "hunting",
                                  "soar", "workbooks", "attack", "ci-cd"])
def test_register_has_a_section_for_each_area(area):
    """A capture can only be filed under an area the register already has."""
    assert f"## {area}" in EVIDENCE.read_text(encoding="utf-8"), (
        f"docs/evidence.md has no '## {area}' section, so a capture in that area cannot be registered")


# --------------------------------------------------------------- capture manifest
def manifest() -> dict:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def register_entries() -> dict[str, str]:
    """Map every register entry path to the text of its entry."""
    text = EVIDENCE.read_text(encoding="utf-8")
    entries = {}
    for match in re.finditer(r"^### `([^`]+)`\n(.*?)(?=^### |^## |\Z)", text, re.M | re.S):
        entries[match.group(1)] = match.group(2)
    return entries


def test_capture_manifest_is_well_formed():
    """The wish list is data, so it can be checked like data."""
    data = manifest()
    assert data["schema_version"] == 1
    shots = data["shots"]
    assert shots, "the manifest lists no shots"
    required = {"id", "area", "slug", "priority", "status", "file", "proves"}
    for shot in shots:
        assert required <= set(shot), f"{shot.get('id')}: missing {required - set(shot)}"
        assert shot["status"] in {"pending", "captured"}, shot["id"]
        assert shot["area"] in AREAS, f"{shot['id']}: '{shot['area']}' is not a register area"
        assert re.match(r"^[a-z0-9-]+$", shot["slug"]), shot["id"]
        assert isinstance(shot["priority"], int), shot["id"]
        assert len(shot["proves"]) >= 40, f"{shot['id']}: 'proves' says too little to be useful"
        if "captured" in shot:
            assert isinstance(shot["captured"], str), (
                f"{shot['id']}: the capture date must be quoted, or YAML returns a date object")
    ids = [shot["id"] for shot in shots]
    assert len(ids) == len(set(ids)), f"duplicate shot ids: {ids}"


def test_manifest_and_disk_agree_for_every_shot():
    """A pending shot must have no capture, and a captured one must have an image
    and a register entry. Drift in either direction is how a checklist becomes
    decorative."""
    entries = register_entries()
    evidence = EVIDENCE.read_text(encoding="utf-8")
    problems = []
    for shot in manifest()["shots"]:
        if shot["status"] == "captured":
            if not shot["file"]:
                problems.append(f"{shot['id']}: captured with no file recorded")
                continue
            path = REPO / shot["file"]
            if not path.exists():
                problems.append(f"{shot['id']}: {shot['file']} does not exist")
                continue
            rel = path.relative_to(IMAGES).as_posix()
            entry = entries.get(rel, "")
            if "**Provenance class:** Screenshot" not in entry:
                problems.append(f"{shot['id']}: {rel} has no Screenshot entry in docs/evidence.md")
            if f"-lab-{shot['slug']}.png" in rel and not path.name.endswith(
                    f"-lab-{shot['slug']}.png"):
                problems.append(f"{shot['id']}: {rel} does not match the intake naming convention")
        else:
            if shot["file"]:
                problems.append(f"{shot['id']}: pending but records {shot['file']}")
            stray = sorted(p.name for p in (IMAGES / shot["area"]).glob(f"*-lab-{shot['slug']}.png"))
            if stray:
                problems.append(
                    f"{shot['id']}: still marked pending, but {stray} is committed — "
                    f"file it through scripts/register_screenshot.py with --manifest-id")
            if f"-lab-{shot['slug']}.png" in evidence:
                problems.append(f"{shot['id']}: pending, but the register already has an entry")
    assert not problems, "capture manifest and repository disagree:\n  " + "\n  ".join(problems)


def test_every_committed_screenshot_is_a_manifest_capture():
    """The manifest is the only place a reader can see what the capture programme
    still owes, so a filed capture that is not on the list defeats it."""
    captured = {shot["file"] for shot in manifest()["shots"] if shot["status"] == "captured"}
    missing = [f"docs/images/{rel}" for rel, entry in register_entries().items()
               if "**Provenance class:** Screenshot" in entry and f"docs/images/{rel}" not in captured]
    assert not missing, (
        f"these committed screenshots are not listed as captured in "
        f"docs/images/capture-manifest.yaml: {missing}")


def test_every_shot_is_documented_in_the_capture_guide():
    """A shot with no capture instructions is an aspiration. The guide is where a
    reader learns the portal path, what has to be visible and what to redact."""
    guide = CAPTURE_GUIDE.read_text(encoding="utf-8")
    undocumented = [shot["id"] for shot in manifest()["shots"] if f"`{shot['id']}`" not in guide]
    assert not undocumented, f"docs/images/capture-guide.md does not cover: {undocumented}"


def test_intake_marks_a_shot_captured_in_the_manifest():
    """Filing a capture flips its status, so the checklist cannot drift from what
    the intake script actually did. Checked on the real manifest text."""
    text = MANIFEST.read_text(encoding="utf-8")
    before = manifest()
    pending = next(shot for shot in before["shots"] if shot["status"] == "pending")
    updated = mark_captured(text, pending["id"], f"docs/images/{pending['area']}/{pending['slug']}.png",
                            "2026-09-11")
    after = yaml.safe_load(updated)
    shot = next(s for s in after["shots"] if s["id"] == pending["id"])
    assert shot["status"] == "captured"
    assert shot["file"] == f"docs/images/{pending['area']}/{pending['slug']}.png"
    assert shot["captured"] == "2026-09-11"
    assert len(after["shots"]) == len(before["shots"]), "the flip added or removed a shot"
    assert "#" in updated, "the flip dropped the manifest's comments"

    with pytest.raises(IntakeError):
        mark_captured(updated, pending["id"], "x.png", "2026-09-11")
    with pytest.raises(IntakeError):
        mark_captured(text, "no-such-shot", "x.png", "2026-09-11")


IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff"}


def test_no_image_lives_outside_the_registered_directory():
    """Every image in this repository is registered, and the register only knows
    about `docs/images/`. On 2026-09-11 two captures were committed to an
    `uploads/` directory at the repository root — the leftover attachment copies of
    pictures already filed, pixel-identical, but outside the register, outside the
    metadata check and outside the capture manifest. Nothing caught it, because
    every check in this module scanned `docs/images/` specifically.

    So the check is now a boundary rather than a directory listing: an image
    anywhere else in the repository fails the build and names its own path.
    """
    strays = []
    for path in REPO.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.suffix.lower() not in IMAGE_SUFFIXES:
            continue
        if IMAGES in path.parents:
            continue
        strays.append(str(path.relative_to(REPO)))
    assert not strays, (
        "images outside docs/images/ are not covered by the evidence register, the metadata "
        "check or the capture manifest. File them through scripts/register_screenshot.py, move "
        "them under docs/images/, or delete the duplicate:\n  " + "\n  ".join(sorted(strays)))
