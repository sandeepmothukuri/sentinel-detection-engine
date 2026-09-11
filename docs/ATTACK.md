# ATT&CK Mapping

## How coverage is generated

Coverage is derived from rule metadata, never hand-maintained:

1. Every rule declares `tactics` (Sentinel names) and `relevantTechniques` (ATT&CK ids).
2. [`scripts/ci_validate.py`](../scripts/ci_validate.py) validates every technique id against `scripts/attack_data.json` — a compact dataset built from official MITRE CTI (`scripts/build_attack_data.py`), containing 697 active techniques with revoked/deprecated entries excluded. Referencing a stale id **fails CI**.
3. The validator also checks tactic↔technique consistency. MITRE's ATT&CK v18 renamed the *Defense Evasion* phase to *Defense Impairment* and added a *Stealth* phase; Sentinel rule YAML still uses the classic 14 tactic names, so the validator normalises `defense-impairment` and `stealth` to `DefenseEvasion` on the comparison side while keeping Sentinel vocabulary in the rules.
4. [`scripts/generate_coverage.py`](../scripts/generate_coverage.py) regenerates:
   - [`coverage.md`](../coverage.md) — techniques → rules matrix,
   - [`attack-navigator/layer.json`](../attack-navigator/layer.json) — drop into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

CI fails if either artifact drifts from rule metadata, so coverage always reflects the rules actually in the repo.

## Current coverage snapshot

- 12 detections + 10 hunts
- 31 unique techniques across 11 tactics (see [coverage.md](../coverage.md))
- Technique density (how many rules touch a technique) drives the Navigator layer colour scale

## Technique replacement note

`T1562.007` (*Disable or Modify Cloud Firewall*) was deprecated in the current ATT&CK matrix; the Azure NSG exposure rule now maps to its successor `T1686.001` (*Cloud Firewall*). This is exactly the class of drift the dataset-driven validator catches automatically.

## Limitations

- Coverage measures **detection intent**, not detection efficacy — a technique being "covered" says nothing about whether the rule fires in your telemetry. That is what the [validation ledger](../tests/atomics.md) is for.
- Tactics in Navigator show the rule-pack view; incident-time tactics may differ as attackers chain techniques.
- The vendored dataset is refreshed manually (`python scripts/build_attack_data.py`); CI will not silently absorb new ATT&CK releases until you refresh and review.
