#!/usr/bin/env python3
"""
Shared helpers for the test suite: load rules, expose repo paths.
Stdlib + pyyaml.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_rules(subdir: str) -> list[tuple[Path, dict]]:
    d = REPO / subdir
    out = []
    for path in sorted(d.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out.append((path, data))
    return out


def all_rules() -> list[tuple[Path, dict]]:
    return load_rules("Detections") + load_rules("Hunting Queries")
