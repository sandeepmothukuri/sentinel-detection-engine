# SOC / Detection-Engineering Maturity Self-Assessment

> Adapted from the SANS SOC Maturity Model and Palantir's *Alerting and Detection Strategy* framework. Scores are 0–4 per dimension; 2.0 = "industry baseline", 3.0 = "demonstrably better than median enterprise SOC", 4.0 = "industry-leading". This is what this repo would score for the deploying org if every artefact in `Detections/`, `Hunting Queries/`, `Workbooks/`, `Playbooks/`, and `docs/workflows/` were adopted as-is.

## Summary

| Dimension | Score | Notes |
|---|---:|---|
| 1. Detection breadth (ATT&CK coverage) | 2.5 | 31 techniques across 11 tactics — covers identity, cloud, endpoint; gaps in Impact + LateralMovement |
| 2. Detection engineering rigour | 3.0 | YAML-as-code, CI validation, ATT&CK mapping, ART validation per rule |
| 3. Telemetry coverage | 2.5 | Entra ID + M365 + MDE + AzureActivity + KeyVault; no on-prem AD, no network IDS, no DLP |
| 4. Triage process | 3.0 | Documented SOP, tiered hand-off, dispositioning labels, MTTA/MTTR tracking |
| 5. Containment automation | 2.5 | 4 SOAR playbooks (enrich+disable, isolate, ticket, firewall block); manual-only for cloud workload kills |
| 6. Tuning + lifecycle | 3.0 | Tuning log, weekly review cadence, PR-driven changes, FP-rate tracking |
| 7. Threat intel integration | 1.5 | VT + AbuseIPDB enrichment; no MISP, no TAXII feeds, no internal IOC lifecycle |
| 8. Postmortem / learning loop | 2.5 | Template + required sections; no blameless-incident review process documented |
| 9. Metrics + reporting | 2.5 | Workbook KPIs (MTTA, MTTR, FP rate); no exec-level scorecard yet |
| 10. Purple-team validation | 3.0 | Atomic Red Team mapping per rule; CI doesn't yet run live ART against a staging tenant |
| **Weighted average** | **2.6** | Strong mid-tier; clear next steps to push toward 3.5 |

## Maturity-band definitions

- **0** — Absent or ad-hoc, no documented process.
- **1** — Process exists but is undocumented or executed inconsistently.
- **2** — Documented, executed consistently, manual. (industry median)
- **3** — Documented, executed consistently, partially automated, measured.
- **4** — Documented, executed consistently, mostly automated, continuously improved with measured outcomes.

## Per-dimension detail and roadmap

### 1. Detection breadth — 2.5 → goal 3.0
- Add 4 LateralMovement detections (T1021.002 SMB admin, T1021.006 WinRM, T1550.002 PtH, T1563.002 RDP hijack)
- Add 3 Impact detections (T1486 mass file modification rate, T1490 shadow-copy delete, T1485 data destruction)

### 2. Detection engineering rigour — 3.0 → goal 4.0
- Generate per-rule unit tests by running ART in a staging tenant nightly and asserting the rule fires within N minutes
- Add backtesting: run new query against last 30 d of data, surface FP/TP counts in the PR

### 3. Telemetry coverage — 2.5 → goal 3.0
- Ship Sysmon → AMA → custom table for on-prem endpoints not yet on MDE
- Add Zeek / Suricata via Logstash → custom logs

### 5. Containment automation — 2.5 → goal 3.5
- Add MDE Live Response playbook for one-click memory dump on `MDE_*` alerts
- Add `ForceMfaReenrollment` playbook for `EntraID_MFAFatigue` true positives

### 7. Threat intel integration — 1.5 → goal 3.0 (biggest gap)
- Add MISP as a watchlist source via Sentinel Logic App
- Enrich every IP entity against a TI feed before disposition
- Track which IOCs the detections actually catch (proves TI value)

### 8. Postmortem loop — 2.5 → goal 3.5
- Adopt the **blameless** postmortem template (link contributing factors to systems, not people)
- Quarterly review: pull every postmortem's action items, score completion rate

## How to use this document

- **For a hiring conversation:** this is evidence you think about detection programs as systems, not just rule lists.
- **For onboarding:** the scoring narrative explains *what we have, what's next, and why*. Onboard a new analyst by walking them through the lower-scoring dimensions and the corresponding roadmap items.
- **For quarterly review:** rescore. The delta is the headline; the *reasons* for the delta are the substance.

## References

- SANS SOC Maturity Model (SEC511)
- Palantir, *Alerting and Detection Strategy Framework* — <https://github.com/palantir/alerting-detection-strategy-framework>
- MITRE ATT&CK Evaluations methodology
- Google SRE Book, ch. 13 (Emergency Response) — postmortem culture
