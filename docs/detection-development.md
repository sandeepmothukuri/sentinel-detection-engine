# Detection Development

![Analytics rule anatomy and the gate that checks each section](images/detections/02-analytics-rule-anatomy.png)

*Source: `docs/diagrams/detections/02-analytics-rule-anatomy.mmd`. Each gate name corresponds to a
check family implemented in `scripts/ci_validate.py`.*


## Rule anatomy

Every detection in `Detections/` follows one schema. Example skeleton:

```yaml
id: <uuid4, stable for the life of the rule>
name: <Source> - <Behaviour>
description: |
  What fires, why it matters, and what the attacker is doing.
severity: High            # Informational | Low | Medium | High
status: Available
requiredDataConnectors:   # must match the tables the query reads
  - connectorId: ...
    dataTypes: [...]
queryFrequency: 1h        # how often the query runs
queryPeriod: 1h           # how far back it looks (>= queryFrequency)
triggerOperator: gt
triggerThreshold: 0
tactics: [...]            # Sentinel tactic names
relevantTechniques: [...] # ATT&CK IDs, validated against the vendored dataset
query: |
  ...
entityMappings: [...]     # columns projected by the query
incidentConfiguration:    # incident creation + grouping
eventGroupingSettings:
metadata:                 # human-facing, stripped for GitOps import
  author: Sandeep Mothukuri
  validationStatus: static-validation
  telemetryDependency: ...
  falsePositives: |
  tuningGuidance: |
  suppression: |
  expectedVolume: ...
version: 1.1.0
```

## What CI enforces

`scripts/ci_validate.py` + the pytest suite reject a PR that:

- misses any core field, or reuses an `id`/`name`;
- references an ATT&CK technique that is invalid, revoked, or deprecated (checked against `scripts/attack_data.json`, built from MITRE CTI);
- declares tactics that contradict the referenced techniques;
- reads a table whose connector/dataType is not declared;
- has unbalanced brackets/quotes, invalid KQL set operators (e.g. `endswith any`), invalid `matches regex` patterns, or `now()` inside a scheduled rule;
- lacks entity mappings, incident grouping, or the tuning metadata block;
- lets `coverage.md` or `attack-navigator/layer.json` drift from rule metadata.

## Query style rules

1. **Filter early** — put `where TimeGenerated > ago(...)` and the most selective filters first; a scheduled rule runs hourly, and cost compounds across 18 rules.
2. **Bound time explicitly** — every `let` sub-query re-derives its own window from `ago()`; never rely on implicit workspace defaults.
3. **Use baselines deliberately** — the two anomaly rules (`MassSharePointDownload`, `KeyVaultSpike`) pay a 14-day `queryPeriod` (the platform maximum) for their baselines; this is a documented cost/precision trade-off in [metrics.md](metrics.md).
4. **Entity-mapped columns must be projected** strings, not arrays (`make_set` output cannot be entity-mapped).
5. **Case sensitivity** — prefer `=~` / `in~` for names, `has_any` for term lists, and be explicit with `_cs` operators when casing matters.
6. **Allow-lists live in the query** — `let excluded_* = dynamic([]);` placeholders, filled during tuning, kept under change control. No magic numbers buried mid-query; thresholds are named `let` values.

## Adding a new detection

1. Copy an existing rule; generate a fresh UUID (never reuse).
2. Write the query; verify tables against the connector catalog in `scripts/ci_validate.py` (`TABLE_CATALOG`) — add new tables there if you introduce a source.
3. Fill the full metadata block. If you cannot articulate the false positives, the rule is not ready.
4. Map it to Atomic Red Team tests (or a manual procedure) in `tests/atomics.md`.
5. Run `python scripts/ci_validate.py && python scripts/generate_coverage.py` and commit the regenerated coverage artifacts.
6. Bump nothing else; version the new rule at `1.0.0`.

## Modifying an existing rule

- Bump `version` (patch for metadata/tuning, minor for logic, major for behaviour change).
- The PR report bot diffs severity/tactics/techniques/query and flags missing version bumps.

## Removing a rule

Document why in the PR (no longer exploitable, superseded, too noisy to fix). CI detects the deletion; the ATT&CK coverage regenerates automatically.
