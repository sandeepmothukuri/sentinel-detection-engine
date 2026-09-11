# Playbook: IsolateDeviceMDE

Triggered on Sentinel incident creation. For every Host entity that carries an MDE device ID, calls the MDE `machineActions/isolate` API and posts an audit comment back to Sentinel.

**Isolation modes:**
- `Selective` (default): blocks all outbound network EXCEPT Defender + Outlook + Teams. Lets the user continue limited comms while you investigate.
- `Full`: total network block. Use for confirmed ransomware staging.

## Required permissions

App registration with the following Microsoft Defender for Endpoint API permissions, **admin-consent granted**:
- `Machine.Isolate`
- `Machine.Read.All`

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=IsolateDeviceMDE IsolationType=Selective
```

Bind to incidents via Sentinel **Automation rule**: trigger = `Incident created`, condition = `Analytic rule name contains MDE_`, action = run this playbook.

## Reversal

`Unisolate` the device from MDE portal → Device → Actions → **Release from isolation**, or run the inverse Graph API call. Always document reversal in the incident comment.

## Safeguards (v1.1)

- **Severity gate** — `MinimumSeverity` (default `High`). Incidents below the gate receive a comment, never an isolation. In Sentinel the top severity is `High` (there is no Critical), so the default means "top severity only".
- **Missing MDE ID** — hosts without an `MdatpDeviceId` entity value are skipped with an explicit comment (no silent no-ops).
- Trigger concurrency pinned to 1 run at a time.
- `Selective` isolation is the deployed default; `Full` must be chosen deliberately at deploy time.
- Every isolation comment embeds the rollback instruction.

## Least privilege

The connection identity needs only `Machine.Isolate` + `Machine.Read.All` on the MDE API — never a broad subscription role. If you also run release-isolation through automation, add those permissions separately, not by default.
