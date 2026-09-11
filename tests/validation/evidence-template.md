# Validation Evidence — `<RULE NAME>`

> Copy this file to `tests/validation/evidence/<RULE-STEM>-<YYYY-MM-DD>.md` and fill it in
> **while you are validating**, not afterwards. Every field below is a question someone will ask
> you later. A field you cannot answer honestly is filled with `Not observed` — that is a valid
> and useful answer; an invented value is not.
>
> The ledger entry in `tests/validation/atomics.yaml` is the summary. This file is the record.

## Identification

| Field | Value |
|---|---|
| Rule file | `Detections/<file>.yaml` |
| Rule name | |
| Rule version | `metadata.version` as committed (a validation performed against a different version is not valid for this one) |
| Ledger entry | `tests/validation/atomics.yaml` → `rule: <stem>` |
| Validation status claimed | `SIMULATED` or `VALIDATED IN LIVE TENANT` |
| Date of execution | `YYYY-MM-DD` |
| Performed by | |

## Environment

| Field | Value |
|---|---|
| Environment type | Lab workspace / production tenant / replay environment |
| Workspace or tenant | redacted identifier (name or id, partially masked) |
| Region | |
| Sentinel data retention at time of test | days |
| Confirm the connectors were *receiving*, not merely *enabled* | `Not observed` / evidence |
| Endpoint onboarding | MDE-onboarded hosts used, or `Not observed` |
| Identity of the test account | purpose-built test account / no account used / redacted |
| Was any real user or device touched? | **Yes/No** — if yes, state the authorisation |

## What was executed

| Field | Value |
|---|---|
| Technique and atomic id | e.g. `T1490-1` |
| Atomic name as published upstream | |
| Atomic source revision or commit | |
| Executor used | |
| Parameters changed from the atomic's defaults | or `none` |
| If a manual procedure: the exact commands | |
| Preconditions met before execution | |

## Observed result

| Field | Value |
|---|---|
| Did the atomic complete successfully? | Yes / No / Partially — with the error if no |
| Time the action ran (UTC) | |
| Time the alert was created (UTC) | |
| Detection latency | minutes |
| Did the rule fire? | Yes / No |
| If it did not fire, was the cause identified? | query logic / telemetry absent / connector / schedule window / not investigated |

**Raw confirmation query** (paste the query exactly as run, with the workspace identifier removed):

```kusto
// paste here
```

**Raw result** (paste the rows, or state the row count and the values of the fields that matter):

```
```

## Interpretation

| Question | Answer |
|---|---|
| What does this result prove? | |
| What does it *not* prove? | |
| Which branch of the query was exercised, and which was not? | |
| If the atomic was recorded as `partial`: precisely what remains unproven? | |
| Did the test expose a defect? | Yes/No — link the pull request or the ledger note |
| Any tuning change made as a result? | version before → after, or `none` |

## Evidence references

| Artefact | Reference |
|---|---|
| Incident number (required for `VALIDATED IN LIVE TENANT`) | |
| Alert id | |
| Screenshot or export (if any) | path and what was redacted |
| Query used for the confirmation | above |
| Related pull request | |

## Sign-off

```
Validated by:            <name>
Role:                    <role>
Date:                    <YYYY-MM-DD>
I confirm these results were observed by me in the environment named above,
and that no value in this record was inferred, estimated or reconstructed.
Signature (typed name is sufficient in a repository record):
```

## Post-validation housekeeping

- [ ] Ledger entry updated: `status`, `evidence`, and the date in `last_reviewed`.
- [ ] `tests/atomics.md` regenerated (`python scripts/generate_atomics_ledger.py`) and committed.
- [ ] `tests/validation/performance-metrics.md` row updated with the observed volume, if the rule
      produced more than one alert.
- [ ] If the rule changed as a result, `metadata.version` bumped in the rule file and a
      `docs/workflows/tuning-log.md` entry added.
- [ ] `docs/metrics.md` updated if this changes the count of validated rules.
