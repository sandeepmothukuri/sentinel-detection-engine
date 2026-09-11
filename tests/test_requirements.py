#!/usr/bin/env python3
"""The CI environment has to contain what CI runs.

Why this file exists: `.github/workflows/validate.yml` installed `pyyaml yamllint
pytest` while `tests/test_evidence.py` imports Pillow and the design-preview drift
gate imports matplotlib. Nothing failed until the workflow ran on a runner, because
every developer machine had those libraries already — which is the worst kind of
green build: locally true, remotely broken.

So the third-party imports of `scripts/` and `tests/` are compared against
`requirements.txt`, and the workflows are checked to install from that file rather
than from a hand-maintained list that can drift away from it again.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
REQUIREMENTS = REPO / "requirements.txt"
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))
LOCAL_MODULES = {path.stem for path in (REPO / "scripts").glob("*.py")} | {"conftest"}


def declared() -> set[str]:
    """Distribution names in requirements.txt, normalised for comparison."""
    names = set()
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        names.add(re.split(r"[<>=!~\[;]", line, maxsplit=1)[0].strip().lower())
    return names


def import_name_of(distribution: str) -> str:
    """The import name is not always the distribution name (PyYAML -> yaml)."""
    return {"pyyaml": "yaml", "pillow": "PIL"}.get(distribution, distribution)


# Distributions that deliver an executable rather than an importable module.
BINARY_PROVIDERS = {"actionlint-py": "actionlint"}


def third_party_imports(directory: pathlib.Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(directory.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in sys.stdlib_module_names or name in LOCAL_MODULES:
                    continue
                found.setdefault(name, set()).add(path.relative_to(REPO).as_posix())
    return found


def test_every_third_party_import_is_declared() -> None:
    available = {import_name_of(name) for name in declared()}
    missing = {name: sorted(files) for name, files in third_party_imports(REPO / "scripts").items()
               if name not in available}
    missing.update({name: sorted(files) for name, files in third_party_imports(REPO / "tests").items()
                    if name not in available})
    assert not missing, (
        "these imports are used by scripts/ or tests/ but are not declared in requirements.txt, "
        f"so CI would fail on a runner that has not installed them by hand: {missing}")


def test_requirements_are_the_only_dependency_list_ci_uses() -> None:
    offenders = []
    for workflow in WORKFLOWS:
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            # A pip install that names packages instead of the requirements file.
            match = re.search(r"pip install ((?!--)(?!-r\b).)*(\w[\w.-]*)", line)
            if "pip install" in line and "-r " not in line and "upgrade pip" not in line:
                offenders.append(f"{workflow.name}:{number}: {line.strip()}  ({match.group(0) if match else ''})")
    assert not offenders, (
        "workflows must install dependencies with `pip install -r requirements.txt` so the "
        f"declared toolchain and the CI toolchain cannot diverge: {offenders}")


def test_every_imported_library_is_actually_installed_here() -> None:
    """If a library is declared but not importable in this environment, the suite is
    not exercising what CI will exercise."""
    import importlib
    import shutil

    unavailable = []
    for name in declared():
        binary = BINARY_PROVIDERS.get(name)
        if binary:
            if not (shutil.which(binary) or shutil.which(f"{binary}.exe")):
                unavailable.append(f"{name} (provides the `{binary}` executable, not on PATH)")
        elif importlib.util.find_spec(import_name_of(name)) is None:
            unavailable.append(import_name_of(name))
    assert not unavailable, f"declared in requirements.txt but not usable: {unavailable}"
