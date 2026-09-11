# Architecture

## Overview

`sentinel-detection-engine` is a detection-as-code repository for Microsoft Sentinel. Everything that reaches a production workspace starts as a reviewed, versioned file in Git and passes CI validation on every push.

```
┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   ┌──────────────┐
│ Git repo     │→ │ CI (validate)│→ │ Deploy           │→ │ Microsoft     │
│ rules+hunts  │  │ schema/ATT&CK│   │ GitOps / manual  │   │ Sentinel      │
└─────────────┘   │ KQL lint/links│  │ / release tarball│   │ workspace     │
                   └──────────────┘   └─────────────────┘   └──────────────┘
                                                                     │
        SOAR (Logic Apps) ← automation rules ← incidents ← analytics ┘
```

## Components

| Component | Location | Purpose |
|---|---|---|
| Scheduled analytics rules (12) | `Detections/*.yaml` | High-signal detections across Entra ID, M365, MDE, Azure |
| Hunting queries (10) | `Hunting Queries/*.yaml` | Hypothesis-driven interactive hunts |
| SOAR playbooks (4) | `Playbooks/*/azuredeploy.json` | Enrichment + containment + ticketing |
| Workbook | `Workbooks/L3-Triage-Dashboard.json` | L3 triage KPIs, tuning indicators |
| ATT&CK layer | `attack-navigator/layer.json` | Auto-generated Navigator coverage |
| CI scripts | `scripts/` | Validation, coverage generation, packaging |
| Tests | `tests/` | pytest suite + atomic test mapping |

## Data flow (detection)

1. **Telemetry** lands in the workspace via connectors: Entra ID sign-in/audit logs, Office 365 activity, MDE advanced hunting tables (via the Microsoft Defender XDR connector), Azure Activity, Key Vault diagnostics.
2. **Scheduled rules** run at their `queryFrequency`, evaluate the KQL against `queryPeriod` of data, and raise alerts/incidents with entity mappings.
3. **Automation rules** route incidents: enrichment → containment → ticketing, gated by the SOAR safeguards in [SOAR.md](SOAR.md).

## Detection metadata model

Each rule YAML carries:

- **Sentinel core fields** — id, name, severity, tactics/techniques, connectors, query, entity mappings, incident/grouping configuration.
- **`metadata:` block** (author-facing, stripped for GitOps import by `scripts/package_rules.py`) — false positives, tuning guidance, suppression policy, expected volume, telemetry dependency, validation status.

## Data source coverage

| Table | Source | Rules |
|---|---|---|
| `SigninLogs` | Entra ID connector | Impossible Travel, MFA Fatigue, Legacy Auth, 3 hunts |
| `AuditLogs` | Entra ID connector | SP Credential Added, OAuth Consent, Guest Privilege hunt |
| `OfficeActivity` | Office 365 connector | Inbox Rule, Mass Download, Mailbox Forwarding hunt |
| `DeviceProcessEvents` / `DeviceNetworkEvents` / `DeviceInfo` | Defender for Endpoint (M365 advanced hunting) | 3 MDE rules, 6 hunts |
| `AzureActivity` | Azure Activity connector | NSG Exposure |
| `AzureDiagnostics` | Key Vault diagnostic settings | Key Vault Spike |

See [data-sources.md](data-sources.md) for connector setup details.
