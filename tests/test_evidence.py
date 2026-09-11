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
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import REPO
from PIL import Image

IMAGES = REPO / "docs" / "images"
EVIDENCE = REPO / "docs" / "evidence.md"
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
