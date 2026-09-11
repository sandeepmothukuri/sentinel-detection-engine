# Detection Performance Metrics

Per-rule operational metrics. Every cell starts as `Not yet measured` because no
rule in this repository has been measured against live telemetry. **These values
are only ever filled in from a workspace query or an executed test** — with the
query and the date recorded alongside. Estimates belong in the rule's
`metadata.expectedVolume`, clearly labelled as an estimate.

See [`docs/metrics.md`](../../docs/metrics.md) for the formulas and the rationale.

## How to fill a row

Run the queries below over a window of at least 30 days of production data, then
copy the numbers in. Cite the date range in the *Window* column.

```kusto
// Alerts, closed incidents and TP/FP split for one rule.
let rule = "<rule display name>";
let start = ago(30d);
let alerts =
    SecurityAlert
    | where TimeGenerated > start
    | where AlertName =~ rule
    | summarize AlertsGenerated = count();
let incidents =
    SecurityIncident
    | where TimeGenerated > start
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Title has rule
    | summarize IncidentsCreated = count(),
                TruePositive = countif(Classification =~ "TruePositive"),
                FalsePositive = countif(Classification =~ "FalsePositive"),
                BenignPositive = countif(Classification =~ "BenignPositive"),
                Undetermined = countif(Classification =~ "Undetermined"),
                Closed = countif(Status =~ "Closed"),
                MTTA_min = avg(datetime_diff('minute', FirstModifiedTime, CreatedTime)),
                MTTR_min = avg(datetime_diff('minute', ClosedTime, CreatedTime));
alerts | extend dummy = 1
| join kind=inner (incidents | extend dummy = 1) on dummy
| project AlertsGenerated, IncidentsCreated, TruePositive, FalsePositive,
          BenignPositive, Undetermined, Closed,
          round(MTTA_min, 1), round(MTTR_min, 1),
          // Precision proxy: of the incidents the SOC actually closed, how many
          // were real. Not ground truth — it measures analyst agreement with the
          // alert, which is why the closure-discipline caveat below matters.
          Precision_pct = iff(Closed > 0, round(100.0 * TruePositive / Closed, 1), toreal(null)),
          FP_rate_pct  = iff(Closed > 0, round(100.0 * FalsePositive / Closed, 1), toreal(null))
```

```kusto
// Detection latency: event time to alert time, p50 and p95.
SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName =~ "<rule display name>"
| extend LatencyMin = datetime_diff('minute', TimeGenerated, StartTime)
| summarize p50 = percentile(LatencyMin, 50), p95 = percentile(LatencyMin, 95)
```

```kusto
// Suppression rate: how often the rule fired but the incident was merged into
// an existing one rather than creating a new one.
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title has "<rule display name>"
| summarize Incidents = count(), MergedAlerts = sum(array_length(AlertIds)) by Status
```

## Metrics table

`Events evaluated` requires a query log export and is often the hardest column to
populate honestly. Leave it blank rather than guessing from a `count()` of the
source table — that is not what the detection engine evaluated.

| Rule | Window (UTC) | Events evaluated | Alerts generated | Alerts/day | TP | FP | Benign+ | Undetermined | Precision % | FP rate % | MTTA (min) | MTTR (min) | Detection latency p50/p95 (min) | Suppression rate % | Dominant closure reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EntraID_ImpossibleTravel | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| EntraID_MFAFatigue | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| EntraID_LegacyAuthSuccess | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| EntraID_ServicePrincipalCredAdd | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| EntraID_PrivilegedRoleAssignment | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| M365_InboxRuleExfil | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| M365_MassSharePointDownload | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| M365_OAuthConsentSuspiciousApp | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_LOLBin_Rundll32_Network | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_MSHTA_RemoteScript | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_PowerShell_EncodedCommand | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_ShadowCopyDeletion | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_Ransomware_MassFileRename | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_WinRM_RemoteExecution | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| MDE_PsExec_ServiceExecution | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| Azure_NSG_OpenToInternet | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| Azure_KeyVault_SecretAccessSpike | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| Azure_KeyVault_AccessControlChange | Not yet measured | Not yet measured | Not yet measured | Not yet measured | — | — | — | — | — | — | — | — | — | — | — |
| HUN_FirstSeenASN_PerUser | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_SignInFromDatacenterASN | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_AnomalousMailboxForwarding | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_GuestUserInvitedToPrivilegedGroup | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_NewScheduledTask | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_OfficeChildProcess | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_RareProcessPerDevice | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_UnsignedBinaryFromTemp | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_DNSRequestsToFreeDynamicDomains | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |
| HUN_NewSSHConnectionFromInternal | n/a — interactive hunt | n/a | n/a | n/a | — | — | — | — | — | — | — | — | — | — | — |

## Closure discipline

Precision and FP rate are computed from incident `Classification`, so they are
only as good as the SOC's closing discipline. Two rules for anyone filling this
table in:

1. **An incident that was never triaged is not a false positive.** `Undetermined`
   and `BenignPositive` are separate columns for exactly this reason. Do not
   collapse them into FP to make a rule look noisy.
2. **A rule with zero closed incidents has no measured precision.** Record
   `n/a — no closures in window`, not `100%`. A rule that never fires is not
   precise; it is untested.

## Rule-tuning candidates

A rule becomes a tuning candidate when either:

- its FP rate is above 30% on at least five closed incidents (the workbook's
  *Tuning indicators* tile applies the same gate), or
- its alert volume exceeds its `metadata.expectedVolume` by more than 2×.

Either condition opens an entry in
[`docs/workflows/tuning-log.md`](../../docs/workflows/tuning-log.md). The
threshold change, the allow-list change, or the logic fix lands as a reviewed PR
with the volume delta recorded after `queryFrequency × 5` runs.
