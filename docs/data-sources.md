# Data Sources

Every rule's telemetry dependency is declared in `requiredDataConnectors` (machine-checked by CI) and summarised in `metadata.telemetryDependency`. This page documents what to enable and the assumptions baked into the queries.

## Connectors

| Connector | Data types | Assumptions the queries make |
|---|---|---|
| **Entra ID** (`AzureActiveDirectory`) | `SigninLogs`, `AuditLogs` | `LocationDetails.geoCoordinates` populated on interactive sign-ins; `AutonomousSystemNumber` populated; MFA failure ResultTypes in (50074, 50076, 500121, 530002); audit `OperationName` values as of 2026 (hyphen/en-dash variants handled) |
| **Office 365** (`Office365`) | `OfficeActivity` (Exchange, SharePoint) | Exchange admin audit logging enabled; `Parameters` is a dynamic name/value array (queries `mv-expand` it — see regression test); `FileDownloaded` / `FileSyncDownloadedFull` operations present |
| **Microsoft Defender for Endpoint** (`MicrosoftThreatProtection`) | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceInfo`, ... | Devices onboarded to MDE; command-line capture on (MDE default); `RemoteIPType` classification available; `AdditionalFields.IsSigned` populated on process events (verify on a sample device — see hunt limitations) |
| **Azure Activity** (`AzureActivity`) | `AzureActivity` | Subscription-level activity log connected; NSG rule writes carry `Properties.requestbody` (very large bodies may be truncated — noted in rule metadata) |
| **Key Vault** (`AzureKeyVault`, diagnostic mode) | `AzureDiagnostics` | Diagnostic settings enabled per vault for `SecretGet`/`KeyGet`/`CertificateGet`; identity columns `identity_claim_upn_s` / `identity_claim_appid_g_s` present |

## Enabling connectors

Portal path: Sentinel → Data connectors → search the connector name → Open connector page → follow its steps. Details and prerequisites are in [deployment.md](deployment.md#data-connectors-required-by-this-pack).

## Cost notes

- The two baseline rules (`M365_MassSharePointDownload`, `Azure_KeyVault_SecretAccessSpike`) run a 30-day `queryPeriod` hourly — the most expensive queries in the pack. Reduced lookbacks are documented in each rule's tuning guidance.
- MDE advanced hunting volume scales with device count; the hunts scan 24h–14d windows and are intended for interactive use, not scheduled.
- `SigninLogs` are already high-volume; the Entra ID rules filter on `ResultType`/client lists early to keep scanned data bounded.

## Tables used but not required

`SecurityIncident` / `SecurityAlert` (workbook only) are native to Sentinel and need no connector.
