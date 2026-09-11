# Testing

This repository separates **what CI can prove** from **what only a live tenant can prove**, and labels every rule accordingly.

## Validation status vocabulary

| Label | Meaning |
|---|---|
| `VALIDATED IN LIVE TENANT` | Executed against a real Sentinel tenant with real telemetry; evidence recorded in [`tests/atomics.md`](../tests/atomics.md). |
| `SIMULATED` | Validated against injected synthetic events in a live workspace. |
| `STATIC VALIDATION` | CI-validated schema, KQL lint, ATT&CK mapping, telemetry dependencies, and tests. Never executed against telemetry. |
| `NOT YET VALIDATED` | Mapped but not yet executed. |

**Current status: all 12 detections and 10 hunts are `STATIC VALIDATION`.** No rule has been fired against a live tenant by the author. That is recorded openly in the validation ledger in [`tests/atomics.md`](../tests/atomics.md) rather than implied by screenshots.

## CI test layers

| Layer | Tool | What it proves |
|---|---|---|
| YAML lint | yamllint (`.yamllint.yml`) | Well-formed YAML |
| Schema + metadata | `scripts/ci_validate.py` | Required fields, unique ids/names, severity, entity mappings, grouping config, tuning metadata |
| ATT&CK | `scripts/ci_validate.py` + vendored `scripts/attack_data.json` (MITRE CTI, 697 techniques; revoked/deprecated excluded) | Technique ids exist and tactics are consistent |
| Telemetry | `scripts/ci_validate.py` (`TABLE_CATALOG`) | Every table the query reads is produced by a declared connector/dataType |
| KQL lint | `scripts/kql_lint.py` | Bracket/quote balance (string-aware), invalid set operators, `matches regex`/`extract()` regex validity, no `now()` in scheduled rules |
| Python tests | `pytest tests/` (22 tests) | Regressions: parameter parsing patterns, uniqueness, honest validation statuses, JSON artifacts parse |
| Coverage drift | `validate.yml` | `coverage.md` + Navigator layer regenerate byte-identical |
| Links | `scripts/check_links.py` | No broken relative markdown links |
| Secrets | gitleaks | Nothing credential-shaped is committed |

## What CI cannot prove (be honest)

- Whether a query **returns results** against real tenant data (KQL is linted, not executed — the workspace is the only ground truth).
- Whether a rule's threshold produces the expected alert volume.
- Whether entity mappings resolve to the entities you expect in the incident graph.

These require the live procedure below.

## Live validation procedure (self-service)

1. Deploy per [deployment.md](deployment.md) — the [30-minute walkthrough](30-minute-walkthrough.md) gets you a fresh tenant.
2. Pick a rule from the ledger in [`tests/atomics.md`](../tests/atomics.md) that has an Atomic Red Team mapping.
3. On an isolated test VM: `Invoke-AtomicTest <Txxxx.xxx> -TestNumbers <n>` (install steps in atomics.md).
4. Within `queryFrequency` (worst case 1h), check:
   - Sentinel → Incidents: incident created, entities populated as designed;
   - Sentinel → Logs: run the rule's query manually over the last 2h — verify the event appears and noise is acceptable.
5. Move the ledger row to `VALIDATED IN LIVE TENANT` / `SIMULATED` with dated evidence (incident number, query result excerpt).
6. Record precision/volume observations in [metrics.md](metrics.md).

For Entra ID / M365 rules without atomics, the manual procedures listed in atomics.md (VPN sign-ins, SMTP AUTH, secret-list loops, etc.) are the intended path.

## Atomic mapping accuracy

Each rule↔atomic pairing was chosen so the atomic's observed behaviour matches the rule's query predicate (e.g. `T1218.005-1` pulls an HTA over HTTPS → matches the `https?://` filter in `MDE_MSHTA_RemoteScript`). A pairing is a **hypothesis until executed**; after a live run, correct or replace mappings that did not fire.
