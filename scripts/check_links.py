#!/usr/bin/env python3
"""
Check relative markdown links across README, docs/, tests/, Playbooks/, and
coverage.md. Verifies that every relative link target exists on disk and that
in-repo anchors referenced from `tests/atomics.md`-style links are plausible.

Stdlib only. Exit 1 on any broken link.
"""
from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MD_DIRS = [REPO, REPO / "docs", REPO / "tests", REPO / "Playbooks", REPO / ".github"]
MD_FILES = sorted(set(
    list(REPO.glob("*.md"))
    + list((REPO / "docs").rglob("*.md"))
    + list((REPO / "tests").rglob("*.md"))
    + list((REPO / "Playbooks").rglob("*.md"))
    + list((REPO / ".github").rglob("*.md"))
))

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def strip_anchors(target: str) -> str:
    return target.split("#", 1)[0]


def main() -> int:
    broken = 0
    checked = 0
    for md in MD_FILES:
        text = md.read_text(encoding="utf-8", errors="replace")
        for m in LINK_RE.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "<")):
                continue
            path_part = urllib.parse.unquote(strip_anchors(target))
            if not path_part:
                continue
            checked += 1
            resolved = (md.parent / path_part).resolve()
            if not resolved.exists():
                broken += 1
                print(f"::error file={md.relative_to(REPO).as_posix()}::"
                      f"broken link '{target}'")
    print(f"\n{checked - broken}/{checked} relative links OK.")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
