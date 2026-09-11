#!/usr/bin/env python3
"""
Package detection rules for Microsoft Sentinel Repositories (GitOps) import.

Sentinel's GitOps importer expects analytics rules in the official YAML
export schema. This repo's rule YAMLs additionally carry a human-facing
`metadata:` block (false positives, tuning guidance, validation status)
that is not part of that schema. This script emits a clean copy of every
rule under dist/sentinel-yaml/ with the metadata block stripped, ready
for a GitOps-connected branch or for manual import.

Run from repo root: python scripts/package_rules.py
"""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "dist" / "sentinel-yaml"


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    total = 0
    for d in ("Detections", "Hunting Queries"):
        src_dir = REPO / d
        dst_dir = OUT / d
        dst_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(src_dir.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            data.pop("metadata", None)
            (dst_dir / path.name).write_text(
                yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            total += 1
    print(f"Packaged {total} rules into {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
