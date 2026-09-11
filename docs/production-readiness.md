# Production Readiness Assessment

Assessment date: **2026-09-11** · Assessed by: Sandeep Mothukuri (author)

This page answers one question honestly: *if someone deployed this repository into their Sentinel
workspace tomorrow, what would work, what would need their input, and what has never been
tested?* It is written to be uncomfortable to read where the truth is uncomfortable. Where
something is unproven, it says so instead of implying otherwise.

---

## 1. Verdict summary

| Dimension | Score | Meaning of the score |
|---|---|---|
| Portfolio readiness | **9 / 10** | Ready to show. Content, automation, tests, documentation and generated artefacts are all consistent and reproducible. |
| Engineering maturity | **7 / 10** | Real validation tooling, real negative tests, six drift gates, and a deployment artifact generated from the validated rules. Held back by the absence of execution history. |
| Production readiness | **5 / 10** | Deployable content with correct semantics, but nobody has run it against live telemetry. Tuning thresholds are unvalidated estimates. |
| Operational validation | **1 / 10** | Static validation only. Zero rules have produced an alert outside CI. Deliberately scored at the floor because nothing has been observed. |

These scores are not a marketing device. The gap between portfolio readiness and operational
validation *is* the point: the repository is honest about which of the two it demonstrates.

## 2. What is genuinely ready

| Capability | State | Evidence |
|---|---|---|
| Rule schema and deployment shape | Ready | 18 analytics rules and 10 hunts pass `scripts/ci_validate.py`; `kind`, scheduling, grouping and entity mappings are all present |
| Query correctness at the syntax and schema level | Ready | `kql_lint` plus explicit table, connector, entity and alert-detail parity checks |
| ATT&CK accuracy | Ready | Every technique validated against the vendored MITRE CTI dataset; tactic coherence enforced; retired ids rejected |
| Reproducible coverage reporting | Ready | `coverage.md` and `attack-navigator/layer.json` regenerated in CI with a drift gate |
| Reproducible quality matrix | Ready | `docs/metrics-matrix.md` generated from the rules and the ledger, drift-gated, so the framework cannot lose a rule |
| Deployable artifacts | Ready to deploy | `deploy/analytic-rules/` and `deploy/hunting-queries/` hold 28 generated ARM templates — the format a Sentinel Repositories connection actually consumes — regenerated and drift-gated in CI |
| Validation honesty | Ready | `tests/validation/atomics.yaml` → `tests/atomics.md`, with atomic citations checked against upstream and evidence requirements for any claim above static validation |
| Response automation design | Ready | Four playbooks, each behind a confidence threshold and allowlist parameters, with a documented rollback path |
| Analyst-facing workbook | Ready to deploy | 13 panels, all reading `SecurityIncident`/`SecurityAlert` with real column names |
| CI/CD | Ready | Secret scanning, lint, validation, tests, six drift gates, least-privilege permissions, SHA-pinned actions, Dependabot |

## 3. What needs the deployer's input

| Item | Why it cannot be shipped complete | Consequence if ignored |
|---|---|---|
| Tuning thresholds | Every threshold (`rename_threshold`, `min_distinct_targets`, anomaly multipliers, `suspicious_ports`) is an estimate chosen from the behaviour the rule describes, not from an observed baseline | A rule may be far too noisy or far too quiet in your estate. Each threshold is a named `let` binding precisely so it is one edit away. |
| Allowlists | Playbooks ship with placeholder `AllowlistedIPs`, `ExcludedUserPrincipals` and IP-group resource ids | A destructive action could target an identity you meant to protect |
| Notification and ticketing targets | ServiceNow instance, assignment group, Teams/SMTP destinations are parameters with no values | Playbooks fail at the first external call |
| Escalation contacts | `docs/workflows/escalation-matrix.md` ships placeholder roles | Escalation goes nowhere |
| Data connectors | SigninLogs, AuditLogs, OfficeActivity, AzureActivity, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceInfo, AzureDiagnostics | A rule whose table is absent is silently silent; the workbook's telemetry-freshness panel is the check |

## 4. What has never been run

Stated plainly, because the alternative is a reader assuming otherwise:

- **No rule in this repository has fired against real telemetry.** Every row of
  [`../tests/atomics.md`](../tests/atomics.md) is at `STATIC VALIDATION`.
- **No Atomic Red Team test has been executed by the author.** The ledger records what *would*
  be executed, with citations verified to exist upstream, and marks the mappings that only
  partially exercise a rule.
- **No playbook has been triggered by an incident.** Their logic is reviewed and their
  parameters are documented; their behaviour under a real incident is unknown.
- **No metric in [`metrics.md`](metrics.md) or [`../tests/validation/performance-metrics.md`](../tests/validation/performance-metrics.md)
  has a value.** Precision, false-positive rate, volume, latency, MTTA and MTTR all read
  `Not yet measured` or `Awaiting live telemetry`.
- **The workbook has never rendered with data.** Its design preview is a drawing, generated from
  the workbook definition, and is labelled as such.

## 5. Known weaknesses

| Weakness | Severity | Why it is not fixed here |
|---|---|---|
| Single-author review | Medium | A second reviewer is a process constraint, not a code change. The CI gates are the compensating control; they are real and they run. |
| Anomaly rules use hand-rolled statistics (`mean`/`stdev`) | Medium | `series_decompose_anomalies` or `make_series` would be more robust, but they behave differently across lookback windows and need a tenant to calibrate. Documented in each rule's `tuningGuidance`. |
| Baseline-dependent rules (impossible travel, SharePoint download, Key Vault spike) | Medium | Their behaviour on day one differs from day thirty because the baseline is thin. `docs/deployment.md` says to expect a settling period; the rules do not suppress themselves during it. |
| Two detection families were removed after review | Low | T1562.001/T1562.007-based rules were dropped when those ids were retired; the replacements (T1685, T1686.001) are only partly covered because they need telemetry this repository does not assume. |
| Threat intelligence enrichment is documented, not implemented | Low | A MISP/TAXII model is described in `docs/data-sources.md`; no connector is configured. Nothing claims otherwise. |
| Workbooks are single-workspace | Low | No cross-workspace or Defender-XDR-native incident correlation is attempted. With the Defender portal becoming the only Sentinel surface after 31 March 2027, see section 6. |
| Detection content is Microsoft-first | Accepted | Scanning, OT, cloud-native (AWS/GCP) and third-party EDR telemetry are out of scope by design. Adding connectors without data is the failure mode this repository avoids. |

## 6. Platform currency

| Change | State | Action taken |
|---|---|---|
| Azure portal Sentinel support ends **31 March 2027** | Tracked | Deployment and triage documentation states the Defender portal as the target surface, with Azure-portal paths kept as compatibility notes. Content itself is portal-agnostic: YAML, KQL, workbooks and playbooks deploy either way. |
| Sentinel incidents onboarded to the Defender portal drop the `Description` field and correlate alerts into incidents more aggressively | Tracked | The workbook does not depend on `Description`, and it groups by `IncidentNumber` with `arg_max` rather than assuming one alert per incident. `Title`-based grouping is documented as a convention that can change after onboarding, with an alert-side alternative query in `docs/workflows/tuning-log.md`. |
| ATT&CK v19 retired Defense Evasion (TA0005 → Stealth, new Defense Impairment TA0112) | Handled | The vendored dataset is v19, the validator normalises tactic names at comparison time, and the Navigator layer declares version 19. No rule references a retired id. |

## 7. Deployment gates

Before this content is used in an environment where it matters, each gate must be satisfied. None
of them can be satisfied by this repository alone.

- [ ] `python scripts/ci_validate.py` passes on the deployer's own branch or fork.
- [ ] `python -m pytest tests` passes.
- [ ] Every connector named in `requiredDataConnectors` is connected **and receiving** — verified
      with the telemetry-freshness panel, not with the connector blade.
- [ ] The deployer has reviewed every threshold against their own baseline and adjusted the named
      `let` bindings, or accepted them with the knowledge that they are estimates.
- [ ] Playbook parameters are set to real values, and the destructive playbooks have been tested
      against a disposable identity and device.
- [ ] The first two weeks of alerts are reviewed as a tuning exercise, and the results are recorded
      in `docs/workflows/tuning-log.md`.
- [ ] Each rule's ledger status is moved only when a dated evidence record exists in
      `tests/validation/evidence/`.

## 8. What would move the operational score

In order, and each requires an environment rather than more code:

1. Deploy the rules to a lab workspace and run the manual procedures in the ledger — moves rules
   to `SIMULATED`.
2. Close incidents properly for two weeks so precision and false-positive rate become measurable.
3. Execute the destructive atomics on a disposable VM, recording snapshot and restore evidence.
4. Trigger one playbook through a test incident, with the rollback documented.
5. Record every result in `tests/validation/evidence/`, then promote the ledger entries.

Until step 5 is done for a rule, that rule's status stays `STATIC VALIDATION`, and this page will
keep saying so.
