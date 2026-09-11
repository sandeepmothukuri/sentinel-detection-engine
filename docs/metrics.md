# Metrics — Detection Quality Framework

No metric in this file is invented. Values are recorded only when they can be backed by workspace queries or executed tests, and every rule starts at the same honest baseline: **static validation only, no live measurements.**

## Statuses

| Field | Values | Where |
|---|---|---|
| validationStatus | `static-validation` / `simulated` / `validated-live-tenant` / `not-yet-validated` | rule YAML + [`tests/atomics.md`](../tests/atomics.md) ledger |
| testStatus | `mapped` / `executed-passed` / `executed-failed` / `manual-only` | [`tests/atomics.md`](../tests/atomics.md) |
| tuningStatus | `untuned` / `tuning-in-progress` / `tuned` | [`workflows/tuning-log.md`](workflows/tuning-log.md) |

## Per-rule quality matrix

Precision, recall, FP rate, and alert volume are **blank until a live or simulated deployment produces them**. The workbook computes them from `SecurityIncident`/`SecurityAlert` automatically once data exists (see formulas below).

| Rule | Telemetry dependency | Severity | Expected volume (stated, unmeasured) | Precision | FP rate | Alert volume (30d) | Test status | Tuning status |
|---|---|---|---|---|---|---|---|---|
| EntraID_ImpossibleTravel | SigninLogs | High | Low | — | — | — | manual-only | untuned |
| EntraID_MFAFatigue | SigninLogs | High | Very low | — | — | — | manual-only | untuned |
| EntraID_LegacyAuthSuccess | SigninLogs | High | ~0 post-CA-block | — | — | — | manual-only | untuned |
| EntraID_ServicePrincipalCredAdd | AuditLogs | High | Low | — | — | — | manual-only | untuned |
| M365_InboxRuleExfil | OfficeActivity | High | Very low | — | — | — | T1114.003-1 mapped | untuned |
| M365_MassSharePointDownload | OfficeActivity (30d baseline) | Medium | Low post-exclusions | — | — | — | manual-only | untuned |
| M365_OAuthConsentSuspiciousApp | AuditLogs | High | Low | — | — | — | T1528-1 mapped | untuned |
| MDE_LOLBin_Rundll32_Network | DeviceProcess+Network | High | Low | — | — | — | T1218.011-1/-23 mapped | untuned |
| MDE_MSHTA_RemoteScript | DeviceProcessEvents | High | Very low | — | — | — | T1218.005-1/-2 mapped | untuned |
| MDE_PowerShell_EncodedCommand | DeviceProcessEvents | High | Low, bursts on rollouts | — | — | — | T1059.001-1/-3 mapped | untuned |
| Azure_NSG_OpenToInternet | AzureActivity | High | Low | — | — | — | manual-only | untuned |
| Azure_KeyVault_SecretAccessSpike | AzureDiagnostics (30d baseline) | High | Very low | — | — | — | manual-only | untuned |

## Formulas (computed by the workbook once incidents exist)

- **Alert volume** — `SecurityAlert | where AlertName == <rule> | count()` per 30d window.
- **FP rate** — closed incidents with `CloseReason == "FalsePositive"` ÷ total closed incidents for the rule (the *Tuning indicators* tile shows this per rule for ≥ 5 closed incidents).
- **Precision** — 1 − FP rate (proxy; not a ground-truth measure).
- **Recall** — requires executed red-team tests: `tests fired → incidents raised ÷ tests executed`. Only possible after the [validation procedure](testing.md#live-validation-procedure-self-service).
- **MTTA / MTTR** — `SecurityIncident`: `FirstActivityTime − CreatedTime`, `ClosedTime − CreatedTime` (workbook tile).

## Rules for updating this file

- Fill a cell only from a workspace query or an executed test; cite the incident number or ledger row in the tuning log entry that introduced it.
- `expectedVolume` in rule metadata is an engineering estimate — when measured volume differs by >2×, tune or update the estimate (and say which happened).
