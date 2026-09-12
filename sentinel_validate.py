#!/usr/bin/env python3
"""Stable local entry point for sentinel-detection-engine validation."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main() -> int:
    script = ROOT / "scripts" / "ci_validate.py"
    cmd = [sys.executable, str(script)] + sys.argv[1:]
    completed = subprocess.run(cmd, cwd=ROOT, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
