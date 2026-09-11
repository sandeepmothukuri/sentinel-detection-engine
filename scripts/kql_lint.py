#!/usr/bin/env python3
"""
Lightweight KQL linter for Sentinel rule/hunt queries.

This is a LINTER, not a parser. It catches the classes of KQL defects that
break real queries in Sentinel while staying stdlib-only:

  1. Unbalanced brackets and quotes (including @"..." verbatim strings).
  2. Invalid set-based string operators (e.g. `endswith any`, `startswith any`
     — KQL set forms exist only for `in`, `in~`, `has_any`, `has_any_cs`,
     `has_all`).
  3. `matches regex` patterns that are not valid regular expressions
     (validated with Python's `re`, which accepts the .NET-flavoured regexes
     used in KQL for the patterns we ship).
  4. `now()` inside scheduled-rule queries (breaks Sentinel's time-handling
     guidance and produces unstable alert timestamps).
  5. Suspicious truncation: no tabular statement found.

Intentionally NOT attempted: full syntax parsing, operator-arity checking,
or schema-aware column validation. Use the workspace's own query editor or
the Advanced Hunting API for that.
"""
from __future__ import annotations

import re

INVALID_SET_OPERATORS = (
    "endswith any", "endswith_cs any",
    "startswith any", "startswith_cs any",
    "contains any", "contains_cs any",
    "!endswith any", "!startswith any", "!contains any",
)

VERBATIM_STRING_RE = re.compile(r'@"((?:[^"]|"")*)"')
QUOTED_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def strip_comments(query: str) -> str:
    lines = []
    for line in query.splitlines():
        idx = line.find("//")
        lines.append(line[:idx] if idx >= 0 else line)
    return "\n".join(lines)


def strip_comments_and_strings(query: str) -> tuple[str, list[str]]:
    """Single-pass scanner: blank string literals (regular and verbatim) and
    remove // comments, respecting that // inside a string is not a comment
    and that a verbatim string may contain doubled quotes."""
    strings: list[str] = []
    out: list[str] = []
    i, n = 0, len(query)
    in_quote = False
    while i < n:
        ch = query[i]
        if not in_quote and ch == "@" and i + 1 < n and query[i + 1] == '"':
            j = i + 2
            buf: list[str] = []
            while j < n:
                if query[j] == '"':
                    if j + 1 < n and query[j + 1] == '"':  # doubled quote escape
                        buf.append('""')
                        j += 2
                        continue
                    break
                buf.append(query[j])
                j += 1
            strings.append("".join(buf))
            out.append('"' + " " * max(0, j - i - 1) + '"')
            i = j + 1
            continue
        if not in_quote and ch == '"':
            in_quote = True
            out.append(ch)
            i += 1
            continue
        if in_quote:
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                in_quote = False
                out.append(ch)
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        if ch == "/" and i + 1 < n and query[i + 1] == "/":
            while i < n and query[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), strings


def lint(query: str, is_detection: bool = True) -> list[str]:
    issues: list[str] = []
    if not query or not query.strip():
        return ["query is empty"]

    cleaned, verbatim_strings = strip_comments_and_strings(query)
    no_comments = strip_comments(query)

    # 1. Bracket balance
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for ch in cleaned:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in pairs.values():
            if not stack or stack[-1] != ch:
                issues.append(f"unbalanced bracket near '{ch}'")
                break
            stack.pop()
    else:
        if stack:
            issues.append(f"unclosed brackets, expected: {''.join(reversed(stack))}")

    # 1b. Quote balance (double quotes only; verbatim strings already blanked)
    if cleaned.count('"') % 2 != 0:
        issues.append("odd number of double quotes — unterminated string literal")

    # 2. Invalid set-based operators
    lowered = cleaned.lower()
    for op in INVALID_SET_OPERATORS:
        if op in lowered:
            issues.append(
                f"invalid KQL set operator '{op}' — use has_any / in / in~ or per-element endswith"
            )

    # 3. Regex validation for matches regex patterns
    for m in re.finditer(r"matches\s+regex\s+(@\"[^\"]*\"|\"(?:[^\"\\]|\\.)*\")", no_comments, re.IGNORECASE):
        pattern = m.group(1)
        if pattern.startswith('@'):
            pattern = pattern[2:-1]
        else:
            pattern = pattern[1:-1]
        try:
            re.compile(pattern)
        except re.error as exc:
            issues.append(f"invalid regex in 'matches regex': {pattern!r} ({exc})")

    # 3b. Regex patterns passed to extract() as verbatim strings
    for m in re.finditer(r"extract\s*\(\s*@\"((?:[^\"]|\"\")*)\"", no_comments, re.IGNORECASE):
        pattern = m.group(1).replace('""', '"')
        try:
            re.compile(pattern)
        except re.error as exc:
            issues.append(f"invalid regex in extract(): {pattern!r} ({exc})")

    # 4. now() in scheduled-rule queries
    if is_detection and re.search(r"\bnow\s*\(\s*\)", cleaned):
        issues.append(
            "scheduled rule uses now() — prefer max(TimeGenerated) or bin(TimeGenerated); "
            "now() makes alert timestamps unstable and obscures the event window"
        )

    # 5. Truncation / no tabular statement
    if not re.search(r"^\s*\w+\s*(\||$)|^\s*let\s+", cleaned, re.MULTILINE):
        issues.append("query has no recognizable tabular expression or let statement")

    return issues
