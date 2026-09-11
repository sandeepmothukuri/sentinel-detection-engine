# Live Validation Guide

How to take a rule from `STATIC VALIDATION` to `VALIDATED IN LIVE TENANT` without inventing
results, and without breaking a real environment while doing it.

The repository's current status is stated in [`../atomics.md`](../atomics.md): every rule is at
`STATIC VALIDATION`. Nothing here has been executed against a live tenant by the author. This
guide is the procedure a reader — or the author, in their own lab — follows to change that.

---

## 1. The four statuses

| Status | Means | What CI requires |
|---|---|---|
| `STATIC VALIDATION` | Passes schema, KQL lint, ATT&CK coherence, telemetry parity, metadata | Nothing beyond a green run |
| `SIMULATED` | Exercised against deliberately produced telemetry outside production | Dated evidence file |
| `VALIDATED IN LIVE TENANT` | Fired on real telemetry in a tenant the author is authorised to test in, with the resulting incident reviewed by a person | Dated evidence file **and** an incident reference |
| `NOT YET VALIDATED` | Present but neither statically validated nor executed | A reason it is in the repository |

`STATIC VALIDATION` is not a lesser form of `SIMULATED`; it is a different claim. A rule that
passes static validation has been proven internally consistent. It has not been proven to detect
anything.

## 2. Prerequisites

Do not start until every line is true. A validation run against a half-connected workspace
produces a false negative and wastes the effort.

- [ ] The connectors the rule depends on are **receiving data**, not merely enabled. Check the
      telemetry freshness panel in the L3 workbook, or:
      ```kusto
      union isfuzzy=true
          (SigninLogs | project TimeGenerated), (AuditLogs | project TimeGenerated),
          (OfficeActivity | project TimeGenerated), (AzureActivity | project TimeGenerated),
          (DeviceProcessEvents | project TimeGenerated), (DeviceFileEvents | project TimeGenerated),
          (DeviceNetworkEvents | project TimeGenerated), (AzureDiagnostics | project TimeGenerated)
      | summarize ['Last event'] = max(TimeGenerated), ['Rows'] = count() by Type
      ```
      A table whose last event is hours old is an ingestion problem, not a detection result.
- [ ] The rule is **deployed** in the workspace, and the deployed version matches the committed
      `metadata.version`. Validating version 1.0.0 does not validate 1.1.0.
- [ ] The test account and test device are named, purpose-built, and authorised. Never validate
      with a real user's account.
- [ ] For destructive atomics: a snapshot exists and can be restored.
- [ ] The evidence file is open and being filled in **as you go**:
      `tests/validation/evidence/<RULE-STEM>-<YYYY-MM-DD>.md` from
      [`evidence-template.md`](evidence-template.md).
- [ ] You know what "the rule fired" will look like: the alert name it renders and the entity it
      maps.

## 3. Procedure

### Step 1 — Baseline
Record the rule's state before you touch anything:

```kusto
SecurityAlert
| where TimeGenerated > ago(24h)
| where AlertName has "<rule name>"
| summarize Alerts = count(), Latest = max(TimeGenerated)
```

Zero rows is the expected answer for a rule that has never fired. It is not an error and it is
not evidence the rule works.

### Step 2 — Run the test
Use the ledger entry for the rule in `tests/validation/atomics.yaml`:

- **`trigger` atomic** — execute it as documented, noting any parameter you changed.
- **`precondition` atomic** — execute it, but do not count it as a trigger.
- **`partial` atomic** — execute it, and record precisely which part of the predicate it left
  unexercised. The ledger note says what that is.
- **manual procedure** — perform it and paste the exact commands into the evidence file.

Record the wall-clock time (UTC) you ran the action. Latency is measured from that instant, so an
approximate time makes the latency number worthless.

### Step 3 — Confirm the telemetry existed
Before blaming the rule, confirm the event reached the table. This is the difference between
"the rule does not work" and "the telemetry never arrived".

```kusto
// Example for an endpoint test. Substitute the table and the observable.
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where DeviceName =~ "<test device>"
| where ProcessCommandLine has "<distinctive string from the test>"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Step 4 — Check the rule
Run the rule's own query body with its time window over the test period. If the query returns a
row but no alert exists, the problem is in the deployment or the schedule, not the logic. If the
query returns nothing but the telemetry is present, the predicate is wrong — that is a defect,
and it gets a fix and a version bump, not a note.

```kusto
// Paste the rule's query, with its lookback widened to cover the test window.
```

### Step 5 — Confirm the alert and the incident
```kusto
SecurityAlert
| where TimeGenerated > ago(1h)
| where AlertName has "<rule name>"
| project TimeGenerated, AlertName, AlertSeverity, Entities, Description
| order by TimeGenerated desc

SecurityIncident
| where TimeGenerated > ago(1h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Title has "<rule name>"
| project IncidentNumber, Title, Severity, Status, CreatedTime, Owner
```

Note the alert's entity list. A rule that fires with an empty entity list will group badly and
hand the analyst nothing to pivot on — that is a finding even when the alert is correct.

### Step 6 — Record, then promote the status
1. Complete the evidence file. Paste raw output; do not paraphrase results.
2. Update the ledger entry: `status`, `evidence` (with the date), and `last_reviewed`.
3. Regenerate the ledger and commit both files together:
   ```bash
   python scripts/generate_atomics_ledger.py
   python scripts/ci_validate.py
   ```
4. If the rule needed a change, bump `metadata.version` and add a
   [`../../docs/workflows/tuning-log.md`](../../docs/workflows/tuning-log.md) entry.

CI will reject `SIMULATED` or `VALIDATED IN LIVE TENANT` without a dated evidence reference, and
will reject a live-tenant claim without an incident number.

## 4. Safety boundaries

### Destructive atomics

| Atomic | Effect | Boundary |
|---|---|---|
| `T1490` (all) | Destroys shadow copies, backup catalogs or recovery configuration | Disposable VM only. Snapshot first. Never on a production host, never on a host whose backups are the only copy. |
| `T1486` | Encrypts or mass-creates files | Isolated directory on a disposable host. Never point it at a share. |
| `T1021.006`, `T1569.002` | Remote execution and service creation | Lab hosts only, both ends onboarded, no route to production subnets. |
| `T1098.*`, `T1136.003` | Creates users, adds credentials or roles | A dedicated test tenant. Never the tenant that holds production identities. If a role is granted, record the removal step before you run the test. |

Three rules for anything destructive:

1. **Snapshot before, restore after.** If you cannot restore it, you cannot test it.
2. **Blast radius is checked before execution, not after.** Confirm the target's network position,
   its share mounts, and whether its backups are replicated anywhere.
3. **A blocked test is an untested rule.** If egress filtering stops the payload reaching the
   network, the rule is untested — write `Not observed` and say why. Do not record it as a
   detection failure, and do not record it as a pass.

### Playbook and automation boundaries

Validating a playbook is validating a response capability, so the safety rules are stricter than
for a query:

- Never let a validation run reach a containment action against a real identity or device. The
  playbooks take `MinimumSeverity`, `DisableUserConfidenceThreshold`, `AllowlistedIPs` and
  `IpGroupResourceId` parameters for exactly this reason: point them at a test resource group and
  a test account first.
- `AutoEnrichDisableUser` and `IsolateDeviceMDE` are **not** safe to trigger from a real incident
  during a test. Drive them with a manually created incident whose entity is the test account, or
  run the logic against the same inputs through a separate test playbook.
- Confirm the rollback path *before* the first execution: re-enable the user, release the device,
  remove the IP from the address group. If you cannot describe the rollback, the test does not
  run.
- Record, in the evidence file, which safety gate was configured and how you verified it does not
  fire automatically on a query result alone.

## 5. When validation fails

| Symptom | Most likely cause | What to do |
|---|---|---|
| Query returns rows, no alert | Rule not deployed, or the deployed version is older than the committed one | Check the deployed version, redeploy, retest |
| Query returns nothing, telemetry present | Predicate wrong: wrong column, wrong case, wrong JSON key, too strict a threshold | Fix the rule, bump the version, add a tuning-log entry, retest |
| Query returns nothing, telemetry absent | Connector, retention, or scope gap | Record as a telemetry gap; do not record a validation |
| Rule fires on the test but the entity list is empty | Entity mapping points at a column the query does not produce, or at an array | Fix `entityMappings`; add the case to the negative test suite |
| Fires far more than expected | Threshold too low for the environment's normal behaviour, or a legitimate automation was caught | Tune with the tuning log; check the exclusions the metadata already documents |
| Alert latency exceeds the rule's `queryFrequency` | Ingestion latency, not rule latency | Measure from event time, not from execution time, and record both |

Nothing in this procedure is a reason to edit the ledger to a status you did not reach. If the
run was inconclusive, the honest status is the one it already had.
