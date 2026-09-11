#!/usr/bin/env python3
"""
Minimal Sigma → KQL converter, targeted at Microsoft Defender XDR / Sentinel tables.

Scope: handles the subset of Sigma we actually want from public repos —
process_creation, network_connection, image_load, registry_event for Windows.
Stdlib + pyyaml.

Supported detection conditions:
  selection | a and b | a and not b | not a
  1 of selection_* | all of selection_* | 1 of them | all of them

Anything else raises a ValueError — the converter refuses to emit KQL it
cannot guarantee is semantically correct.

Not a full pySigma replacement. Known limitations (by design):
  - Only the four logsource categories in TABLE_MAP; everything else fails loudly.
  - Sigma modifiers supported: |contains, |startswith, |endswith, |re, and lists.
    Multi-value |endswith / |startswith expand to an explicit OR of per-element
    predicates, because KQL has no set form and has_any() would change the
    semantics from prefix/suffix to substring matching.
    Other modifiers (|base64offset, |endswithfield, |gt, |exists, ...) are
    treated as plain field names and will usually produce wrong KQL — check
    the output before use.
  - The `Hashes` field maps to SHA256, but Sigma expresses Hashes as a list of
    "ALGO=value" strings, so an exact-match `=~` against SHA256 will not match.
    Rewrite hash conditions by hand.
  - Field-value wildcards (|\\mimikatz.exe) become endswith/has matches, not
    true glob matching.
  - No timeframe handling, no aggregation conditions (count() by ...), no
    correlation rules.

Usage:
    python scripts/sigma_to_kql.py <sigma-file.yml>
    python scripts/sigma_to_kql.py --batch sigma/process_creation/*.yml > converted.kql
"""
from __future__ import annotations

import argparse
import glob
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Sigma logsource.category → MDE/Sentinel table + field map
TABLE_MAP = {
    "process_creation": {
        "table": "DeviceProcessEvents",
        "fields": {
            "Image": "FolderPath",
            "OriginalFileName": "FileName",
            "CommandLine": "ProcessCommandLine",
            "ParentImage": "InitiatingProcessFolderPath",
            "ParentCommandLine": "InitiatingProcessCommandLine",
            "User": "AccountName",
            "IntegrityLevel": "ProcessIntegrityLevel",
            "Hashes": "SHA256",
        },
    },
    "network_connection": {
        "table": "DeviceNetworkEvents",
        "fields": {
            "Image": "InitiatingProcessFolderPath",
            "DestinationIp": "RemoteIP",
            "DestinationPort": "RemotePort",
            "DestinationHostname": "RemoteUrl",
            "SourcePort": "LocalPort",
        },
    },
    "image_load": {
        "table": "DeviceImageLoadEvents",
        "fields": {
            "Image": "InitiatingProcessFolderPath",
            "ImageLoaded": "FolderPath",
            "OriginalFileName": "FileName",
        },
    },
    "registry_event": {
        "table": "DeviceRegistryEvents",
        "fields": {
            "TargetObject": "RegistryKey",
            "Details": "RegistryValueData",
            "EventType": "ActionType",
            "Image": "InitiatingProcessFolderPath",
        },
    },
}


def _render_value(field: str, value, table_fields: dict[str, str]) -> str:
    op_endswith = field.endswith("|endswith")
    op_startswith = field.endswith("|startswith")
    op_contains = field.endswith("|contains")
    op_re = field.endswith("|re")
    base_field = field.split("|", 1)[0]
    kql_field = table_fields.get(base_field, base_field)
    values = value if isinstance(value, list) else [value]
    quoted = [f'"{str(v)}"' for v in values]
    if op_re:
        return f"{kql_field} matches regex {quoted[0]}"
    # KQL has no set form of endswith/startswith: `endswith_cs any (...)` is not
    # valid syntax and scripts/kql_lint.py rejects it. For multiple values the
    # equivalent is an explicit OR of per-element predicates. has_any() is *not*
    # a substitute — it is term-based and order-insensitive, so it would silently
    # widen a prefix/suffix match into a substring match.
    if op_endswith:
        if len(quoted) == 1:
            return f"{kql_field} endswith_cs {quoted[0]}"
        return " or ".join(f"{kql_field} endswith_cs {q}" for q in quoted)
    if op_startswith:
        if len(quoted) == 1:
            return f"{kql_field} startswith_cs {quoted[0]}"
        return " or ".join(f"{kql_field} startswith_cs {q}" for q in quoted)
    if op_contains:
        # has_any is case-insensitive and term-based, which matches Sigma's
        # case-insensitive substring intent closely enough for single tokens;
        # multi-word literals keep has_any's term-sequence semantics.
        return f"{kql_field} has_any ({', '.join(quoted)})"
    if len(quoted) > 1:
        return f"{kql_field} in~ ({', '.join(quoted)})"
    return f"{kql_field} =~ {quoted[0]}"


def _render_block(block: dict, table_fields: dict[str, str]) -> str:
    parts = [_render_value(k, v, table_fields) for k, v in block.items()]
    # A multi-value endswith/startswith renders as an OR chain, which must be
    # bracketed before it is ANDed with the rest of the selection.
    wrapped = [f"({p})" if " or " in p else p for p in parts]
    return " and ".join(wrapped)


def _resolve_condition(condition: str, rendered: dict[str, str]) -> str:
    """Resolve a Sigma condition against rendered selection expressions.

    Supports: single selection, 'a and b', 'a and not b', 'not a',
    '1 of <prefix>*', 'all of <prefix>*', '1 of them', 'all of them'.
    Raises ValueError on anything else rather than emitting wrong KQL.
    """
    cond = condition.strip()
    lowered = cond.lower()

    if lowered == "1 of them":
        return " or ".join(f"({e})" for e in rendered.values())
    if lowered == "all of them":
        return " and ".join(f"({e})" for e in rendered.values())

    m = re.match(r"^(1|all)\s+of\s+(\S+)$", lowered)
    if m:
        quantifier, pattern = m.group(1), m.group(2)
        prefix = pattern.rstrip("*")
        matches = {k: v for k, v in rendered.items() if k.lower().startswith(prefix)}
        if not matches:
            raise ValueError(f"condition {condition!r}: no selections match {pattern!r}")
        joiner = " or " if quantifier == "1" else " and "
        return joiner.join(f"({e})" for e in matches.values())

    # Boolean composition of named selections (a and b, a and not b, not a, a)
    tokens = re.findall(r"\b(not\s+)?([A-Za-z0-9_]+)\b", cond)
    unknown = [name for not_, name in tokens
               if name.lower() not in ("and", "or", "not") and name not in rendered]
    if unknown:
        raise ValueError(f"condition {condition!r} references unknown selections: {unknown}")
    expr = re.sub(
        r"\b([A-Za-z0-9_]+)\b",
        lambda m: f"({rendered[m.group(1)]})" if m.group(1) in rendered else m.group(1),
        cond,
    )
    return expr


def convert(sigma: dict) -> str:
    category = (sigma.get("logsource") or {}).get("category", "")
    if category not in TABLE_MAP:
        raise ValueError(f"Unsupported logsource.category: {category!r}")
    table = TABLE_MAP[category]["table"]
    fields = TABLE_MAP[category]["fields"]

    det = sigma.get("detection") or {}
    condition = det.get("condition", "selection")
    blocks = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}

    rendered = {}
    for name, block in blocks.items():
        if isinstance(block, list):
            sub = [_render_block(b, fields) if isinstance(b, dict) else "" for b in block]
            sub = [s for s in sub if s]
            rendered[name] = " or ".join(f"({s})" for s in sub)
        elif isinstance(block, dict):
            rendered[name] = _render_block(block, fields)

    expr = _resolve_condition(str(condition), rendered)

    title = sigma.get("title", "Converted Sigma rule")
    desc = sigma.get("description", "")
    sigma_id = sigma.get("id", "")
    techniques = []
    for tag in sigma.get("tags", []) or []:
        if tag.startswith("attack.t"):
            techniques.append(tag.split(".", 1)[1].upper())

    out = []
    out.append(f"// {title}")
    if sigma_id:
        out.append(f"// Sigma ID: {sigma_id}")
    if desc:
        for line in desc.splitlines():
            out.append(f"// {line.strip()}")
    if techniques:
        out.append(f"// ATT&CK: {', '.join(techniques)}")
    out.append(f"{table}")
    out.append(f"| where {expr}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="+", help="Sigma YAML file(s) or globs")
    p.add_argument("--batch", action="store_true", help="treat paths as globs")
    args = p.parse_args()

    files: list[Path] = []
    if args.batch:
        for pat in args.path:
            for f in glob.glob(pat):
                files.append(Path(f))
    else:
        files = [Path(p) for p in args.path]

    failures = 0
    for f in files:
        try:
            sigma = yaml.safe_load(f.read_text(encoding="utf-8"))
            print(convert(sigma))
        except Exception as exc:
            print(f"// FAILED: {f}: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
