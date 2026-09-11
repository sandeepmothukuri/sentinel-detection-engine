# Architecture

![Logical architecture](images/architecture/01-logical-architecture.png)

*Source: `docs/diagrams/architecture/01-logical-architecture.mmd`, rendered by
`scripts/render_diagrams.py`. Provenance: [`evidence.md`](evidence.md).*


## Overview

`sentinel-detection-engine` is a detection-as-code repository for Microsoft Sentinel. Everything that reaches a production workspace starts as a reviewed, versioned file in Git and passes CI validation on every push.

```
┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────────┐   ┌──────────────────────┐
│ Git repo        │ → │ CI (validate)    │ → │ Deploy                   │ → │ Microsoft Sentinel   │
│ rules + hunts   │ → │ schema / ATT&CK  │ → │ generated ARM in deploy/ │ → │ workspace            │
│ metadata blocks │ → │ KQL lint / links │ → │ YAML tarball             │ → │ incidents · workbook │
└─────────────────┘   └──────────────────┘   └──────────────────────────┘   └──────────────────────┘
```

## Components

| Component | Location | Purpose |
|---|---|---|
| Scheduled analytics rules (18) | `Detections/*.yaml` | High-signal detections across Entra ID, M365, MDE, Azure |
| Hunting queries (10) | `Hunting Queries/*.yaml` | Hypothesis-driven interactive hunts |
| SOAR playbooks (4) | `Playbooks/*/azuredeploy.json` | Enrichment + containment + ticketing |
| Workbook | `Workbooks/L3-Triage-Dashboard.json` | L3 triage KPIs, tuning indicators |
| ATT&CK layer | `attack-navigator/layer.json` | Auto-generated Navigator coverage |
| Generated ARM deployment set | `deploy/` | `alertRules` and `savedSearches` templates generated from the rule files |
| CI scripts | `scripts/` | Validation, coverage generation, ARM generation, packaging |
| Tests | `tests/` | pytest suite + atomic test mapping |

## Data flow (detection)

1. **Telemetry** lands in the workspace via connectors: Entra ID sign-in/audit logs, Office 365 activity, MDE advanced hunting tables (via the Microsoft Defender XDR connector), Azure Activity, Key Vault diagnostics.
2. **Scheduled rules** run at their `queryFrequency`, evaluate the KQL against `queryPeriod` of data, and raise alerts/incidents with entity mappings.
3. **Automation rules** route incidents: enrichment → containment → ticketing, gated by the SOAR safeguards in [SOAR.md](SOAR.md).

## Detection metadata model

Each rule YAML carries:

- **Sentinel core fields** — id, name, severity, tactics/techniques, connectors, query, entity mappings, incident/grouping configuration.
- **`metadata:` block** (author-facing; kept in the rule file and deliberately absent from the generated ARM templates, because it is not a property of an analytics rule) — false positives, tuning guidance, suppression policy, expected volume, telemetry dependency, validation status.

## Data source coverage

Which connector produces which table. **This table deliberately carries no rule counts.** It
carried them once, named rule by rule, and went stale the moment the rule pack grew; counts of
rules per table now live only in
[`docs/images/sentinel/01-connector-table-coverage.png`](images/sentinel/01-connector-table-coverage.png),
whose numbers `tests/test_diagrams.py` recomputes from `requiredDataConnectors` on every build. The
set of tables below is checked the same way, so a new table cannot appear in the rules without
appearing here.

| Table | Produced by |
|---|---|
| `SigninLogs`, `AuditLogs` | Entra ID connector |
| `OfficeActivity` | Office 365 connector |
| `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceInfo` | Defender XDR advanced hunting (MDE onboarding required) |
| `AzureActivity` | Azure Activity connector |
| `AzureDiagnostics` | Key Vault diagnostic settings |

Setup detail, retention and the assumptions each query makes: [data-sources.md](data-sources.md).
The workbook reads `SecurityIncident` and `SecurityAlert`, which are native to Sentinel and need no
connector.
