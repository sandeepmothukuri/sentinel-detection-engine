# Atomic Red Team → Rule Mapping

For each detection, this table lists at least one [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test that **should** cause the rule to fire on a properly onboarded test endpoint. Use it to validate every rule end-to-end after deployment.

## Validation status vocabulary

| Status | Meaning |
|---|---|
| `VALIDATED IN LIVE TENANT` | Executed against a real Microsoft Sentinel tenant with real telemetry; evidence recorded below. |
| `SIMULATED` | Validated against synthetic events (injected test data) in a live workspace. |
| `STATIC VALIDATION` | CI-validated schema, KQL lint, ATT&CK mapping, and telemetry dependencies. Never executed. |
| `NOT YET VALIDATED` | Mapped but not yet executed. |

> **Honesty statement:** as of this writing, **no detection in this repository has been fired against a live tenant by the author.** Every rule is at `STATIC VALIDATION`. The tables and procedures below exist so that anyone (including the author, after a tenant deployment via [docs/30-minute-walkthrough.md](../docs/30-minute-walkthrough.md)) can move rules to `VALIDATED IN LIVE TENANT` with recorded evidence — and so nobody mistakes "mapped to an atomic" for "tested".

> Always run atomics on an isolated, dedicated test machine. Never on a production host.

## Validation ledger

| Rule | ATT&CK | Atomic Test ID | Atomic name | Status | Evidence |
|---|---|---|---|---|---|
| EntraID_ImpossibleTravel | T1078.004 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| EntraID_MFAFatigue | T1621 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| EntraID_LegacyAuthSuccess | T1110 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| EntraID_ServicePrincipalCredAdd | T1098.001 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| M365_InboxRuleExfil | T1114.003 | T1114.003-1 | New-InboxRule forwarding | STATIC VALIDATION | CI pass; execution pending |
| M365_MassSharePointDownload | T1213.002 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| M365_OAuthConsentSuspiciousApp | T1528 | T1528-1 | OAuth consent grant | STATIC VALIDATION | CI pass; execution pending |
| MDE_LOLBin_Rundll32_Network | T1218.011 | T1218.011-1 | Rundll32 execute JS remote | STATIC VALIDATION | CI pass; execution pending |
| MDE_LOLBin_Rundll32_Network | T1218.011 | T1218.011-23 | rundll32 with Inline VBS | STATIC VALIDATION | CI pass; execution pending |
| MDE_MSHTA_RemoteScript | T1218.005 | T1218.005-1 | mshta executes hta over HTTPS | STATIC VALIDATION | CI pass; execution pending |
| MDE_MSHTA_RemoteScript | T1218.005 | T1218.005-2 | mshta executes javascript: | STATIC VALIDATION | CI pass; execution pending |
| MDE_PowerShell_EncodedCommand | T1059.001 | T1059.001-1 | Mimikatz via PowerShell EncodedCommand | STATIC VALIDATION | CI pass; execution pending |
| MDE_PowerShell_EncodedCommand | T1059.001 | T1059.001-3 | PowerShell -enc dropper | STATIC VALIDATION | CI pass; execution pending |
| Azure_NSG_OpenToInternet | T1190 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| Azure_KeyVault_SecretAccessSpike | T1555.005 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| HUN_FirstSeenASN_PerUser | T1078.004 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| HUN_RareProcessPerDevice | T1027 | T1027-7 | XOR-encoded binary | STATIC VALIDATION | CI pass; execution pending |
| HUN_AnomalousMailboxForwarding | T1114.003 | T1114.003-2 | Set-Mailbox ForwardingSmtpAddress | STATIC VALIDATION | CI pass; execution pending |
| HUN_UnsignedBinaryFromTemp | T1204.002 | T1204.002-1 | Execute downloaded file from %TEMP% | STATIC VALIDATION | CI pass; execution pending |
| HUN_SignInFromDatacenterASN | T1078.004 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| HUN_OfficeChildProcess | T1566.001 | T1566.001-1 | Macro spawns powershell | STATIC VALIDATION | CI pass; execution pending |
| HUN_NewScheduledTask | T1053.005 | T1053.005-1 | schtasks /create with powershell action | STATIC VALIDATION | CI pass; execution pending |
| HUN_GuestUserInvitedToPrivilegedGroup | T1098.003 | n/a (manual) | — | STATIC VALIDATION | CI schema/KQL/ATT&CK pass |
| HUN_DNSRequestsToFreeDynamicDomains | T1071.004 | T1071.004-1 | DNS resolve to dyn-DNS host | STATIC VALIDATION | CI pass; execution pending |
| HUN_NewSSHConnectionFromInternal | T1021.001 | T1021.001-1 | RDP to remote host | STATIC VALIDATION | CI pass; execution pending |

When you complete a live or simulated run, move that row to `VALIDATED IN LIVE TENANT` / `SIMULATED` and add a dated evidence line (incident number, screenshot reference, or query result excerpt) in the Evidence column.

## Manual validation notes

- `EntraID_ImpossibleTravel` — sign in from a VPN, then within 5 min sign in from a different country's VPN to the same account.
- `EntraID_MFAFatigue` — use Evilginx2 or similar in a lab to issue repeated MFA prompts; user approves on attempt 6+.
- `EntraID_LegacyAuthSuccess` — authenticate via SMTP AUTH (`telnet outlook.office365.com 587`) with a test account that has legacy auth allowed.
- `EntraID_ServicePrincipalCredAdd` — `New-AzADAppCredential -ObjectId <appId>` adds a client secret to a test app registration.
- `M365_MassSharePointDownload` — use `pnp.powershell` `Get-PnPFile` in a loop to download 200 files in <1h from a test SharePoint site.
- `Azure_NSG_OpenToInternet` — `az network nsg rule create --source-address-prefixes '*' --destination-port-ranges 3389 --access Allow ...`.
- `Azure_KeyVault_SecretAccessSpike` — with a test SP, `az keyvault secret show` in a loop over 30+ secrets in a single vault.
- `HUN_FirstSeenASN_PerUser` — sign in from a never-before-used VPN provider.
- `HUN_SignInFromDatacenterASN` — sign in from an OVH / DigitalOcean VPS.
- `HUN_GuestUserInvitedToPrivilegedGroup` — invite a guest, then add it to "Application Administrator".

## Running atomics

Install Invoke-AtomicRedTeam on a test VM:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

After the atomic runs, expect the corresponding rule to fire within `queryFrequency` (typically 1 hour, faster for near-real-time rules). Record the outcome in the ledger above before changing any rule's `validationStatus`.
