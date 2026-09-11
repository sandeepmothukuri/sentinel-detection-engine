# Detection Tuning Log

> Purpose: record **why** a rule was changed after it fired in a real environment, so that a
> future reviewer can tell a deliberate tuning decision from an accidental regression.
>
> **No tuning entries have been logged yet.** No rule in this repository has fired against a
> live tenant, so there is no false-positive evidence to tune against. The log below contains
> the entry format and one clearly-marked illustrative record; it does not contain real
> incidents. Populate it from your own tenant once the rules are deployed and incidents close
> with a `FalsePositive` or `BenignPositive` classification.
>
> Rules of the log:
>
> 1. Only incidents that were **closed** by a human appear here. An alert that was never triaged
>    is not evidence of a false positive.
> 2. Every entry names the incident number and the rule version before and after the change.
> 3. A tuning change that alters detection logic requires a `version` bump in the rule YAML —
>    `scripts/pr_diff_report.py` fails the pull request when the query changes without one.
> 4. Entries are appended, never rewritten. A tuning decision that was later reversed gets a
>    new entry that says so.
> 5. Watchlist-based exclusions (for example a `LegacyAuthExemptions` list) are recorded here
>    with the owner of the exemption — an exclusion with no named owner is an unfixed blind spot.

## Entry template

```
### YYYY-MM-DD — <rule name>
- Incident: INC-<number>                         # the closed incident that triggered the entry
- Rule version: <before> → <after>
- Classification: FalsePositive | BenignPositive # as recorded on the incident
- FP pattern: what benign behaviour produced the alert, and the evidence for that conclusion
- Decision: exclude | tighten threshold | watchlist | suppression | accept and document
- Change: the exact query or metadata change, with the reason it is narrower and not wider
- Risk accepted: what the change could now miss, and why that is acceptable
- Owner: <name>
- Due / Status: YYYY-MM-DD — Open | In-PR | Merged | Won't-fix
- PR: #<number>
- Verification: how the fix was confirmed (FP volume over the following N days, re-run of the
  original query against the same time window, or an explicit "not yet verified")
```

## Illustrative record — format only, not a real incident

This example exists to show what a completed entry looks like. Every value below is invented;
do not read it as an operational record, an incident history, or a validated tuning outcome.

```
### YYYY-MM-DD — MDE - PowerShell EncodedCommand With Long Payload
- Incident: INC-000000
- Rule version: 1.0.0 → 1.1.0
- Classification: FalsePositive
- FP pattern: a configuration-management client deployed signed `-EncodedCommand` payloads
  from its own installation directory during a patch cycle. The encoded body decoded to a
  vendor-signed deployment script, and the signing certificate was the deciding evidence.
- Decision: exclude by parent process, not by command line
- Change: added a filter on `InitiatingProcessFileName` / `InitiatingProcessFolderPath` for the
  management client, rather than filtering on payload size. Filtering on size would have
  removed the rule's actual signal.
- Risk accepted: a real attacker who drops a payload into that vendor directory is no longer
  caught by this rule; that gap is covered by the vendor-directory integrity watch and by
  `HUN_UnsignedBinaryFromTemp`.
- Owner: <engineer>
- Due / Status: YYYY-MM-DD — Merged
- PR: #<number>
- Verification: not yet verified — requires N days of post-change volume to compare against the
  pre-change baseline recorded in `tests/validation/performance-metrics.md`.
```

## Open entries

_None._

## Closed entries

_None._

---

## Weekly review checklist (detection-engineering on-call)

```
□ Entries Open for more than 14 days → escalate to the detection-engineering lead
□ Any rule with more than 5 tuning entries in a quarter → schedule a rewrite review
□ Every exclusion watchlist has a named owner and a review date
□ Merged entries from the last 7 days → confirm the false-positive rate moved by comparing
  the rule's row in the L3 Triage workbook against the pre-change value
□ Any rule whose tuning is "suppress the alert" more than once → the rule is not detecting
  anything an analyst acts on; propose retirement in the roadmap
□ Rules with no incidents and no tuning entries for a quarter → confirm the rule is still
  deployed and its connector is still feeding (telemetry freshness panel)
```

## Measuring false-positive rate per rule

The primary source is the incident record, because that is what a human classified. Incidents
carry the rule's `Title`; alerts carry `AlertName`. In most tenants these match, but if several
rules share a title, resolve the rule name through the alert instead of the incident.

Per-rule breakdown over a window, using the incident record:

```kusto
let window = 14d;
let min_sample = 5;                 // do not judge a rule on one bad day
SecurityIncident
| where TimeGenerated > ago(window)
| summarize arg_max(TimeGenerated, *) by IncidentNumber   // incidents are append-only
| where Status =~ "Closed"
| summarize
    Closures = count(),
    TruePositive = countif(Classification == "TruePositive"),
    FalsePositive = countif(Classification == "FalsePositive"),
    BenignPositive = countif(Classification == "BenignPositive"),
    Undetermined = countif(isempty(Classification) or Classification == "Undetermined")
    by Title
| where Closures >= min_sample
| extend FPRate = round(100.0 * FalsePositive / Closures, 1)      // of all closures
| extend FPRateOfJudged = round(100.0 * FalsePositive / (TruePositive + FalsePositive + BenignPositive), 1)
| project Title, Closures, TruePositive, FalsePositive, BenignPositive, Undetermined,
          FPRate, FPRateOfJudged
| order by FPRate desc
```

Notes that matter when reading that output:

- `Undetermined` is kept separate on purpose. Counting untriaged incidents as false positives is
  the most common way a detection-engineering team convinces itself a rule is noisy.
- The tuning gate in `tests/validation/performance-metrics.md` is an FP rate above 30% on a
  sample of at least 5 closures; this query is the input to that gate, not the gate itself.
- If the incident title does not identify the rule on your tenant, resolve it through the alert:

```kusto
// Secondary form: resolve the analytics rule through the alert record. Confirm the column
// names against your workspace before relying on this — the alert join depends on
// SecurityAlert.SystemAlertId matching the ids carried in SecurityIncident.AlertIds.
SecurityAlert
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName
| join kind=inner (
    SecurityIncident
    | where TimeGenerated > ago(14d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | where Status =~ "Closed"
    | mv-expand AlertId = AlertIds
    | extend SystemAlertId = tostring(AlertId)
) on SystemAlertId
| summarize
    Closures = count(),
    FalsePositive = countif(Classification == "FalsePositive")
    by AlertName
| extend FPRate = round(100.0 * FalsePositive / Closures, 1)
| where Closures >= 5
| order by FPRate desc
```

## Where tuning evidence is recorded elsewhere

| Record | Path | Relationship to this log |
|---|---|---|
| Per-rule metrics table | `tests/validation/performance-metrics.md` | Holds the current numbers; this log holds the reasoning behind changes to them |
| Rule metadata | `Detections/*.yaml` → `metadata.falsePositives`, `metadata.tuningGuidance`, `metadata.suppression` | Standing guidance shipped with the rule; the log records one-off decisions |
| Validation ledger | `tests/validation/atomics.yaml` | Proves a rule can fire; this log records what happened after it did |
| Release history | Git history on `Detections/*.yaml` | Version bumps are the audit trail for logic changes |
