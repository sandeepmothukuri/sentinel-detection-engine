# Playbook: IsolateDeviceMDE

Triggered on Sentinel incident creation. For every Host entity that carries an MDE device ID **and is not on the device exclusion list**, calls the MDE `machineActions/isolate` API and posts an audit comment back to Sentinel. A host that matches the exclusion list is named in a review comment instead: critical infrastructure is a manual decision.

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
  --parameters PlaybookName=IsolateDeviceMDE \
               IsolationType=Selective \
               MinimumSeverity=High \
               ExcludedDeviceNames='["dc01.contoso.com","hv-cluster01"]'
```

Bind to incidents via Sentinel **Automation rule**: trigger = `Incident created`, condition = `Analytic rule name contains MDE_`, action = run this playbook.

## Reversal

`Unisolate` the device from MDE portal → Device → Actions → **Release from isolation**, or run the inverse Graph API call. Always document reversal in the incident comment.

## Safeguards (v1.1)

- **Severity floor** — `MinimumSeverity` (default `High`). Incidents *at or above* the floor may be isolated; anything below receives a comment instead. The comparison is by severity rank (High 3, Medium 2, Low 1, Informational 0), so a floor of `Medium` still isolates on `High`. In Sentinel the top severity is `High` (there is no Critical), so the default means "top severity only".
- **Device exclusion list** — `ExcludedDeviceNames`: domain controllers, hypervisors, backup and build infrastructure, jump hosts. Isolation is cheap to reverse but expensive while it is wrong, and taking a DC off the network costs more than the incident it answers. Matching is substring-based against **both** `HostName` and `ComputerDnsName`, so an alias-only entity is still caught. Populate it before enabling auto-isolation — an empty list excludes nothing (see [`docs/limitations.md`](../../docs/limitations.md) L10).
- **Missing MDE ID** — hosts without an `MdatpDeviceId` entity value are skipped with an explicit comment naming the host and the reason (no silent no-ops).
- Trigger concurrency pinned to 1 run at a time.
- `Selective` isolation is the deployed default; `Full` must be chosen deliberately at deploy time.
- Every isolation comment embeds the rollback instruction.

## Least privilege

The connection identity needs only `Machine.Isolate` + `Machine.Read.All` on the MDE API — never a broad subscription role. If you also run release-isolation through automation, add those permissions separately, not by default.
