# Free-tier setup — deploy this pack in ~30 minutes for $0

A working Microsoft Sentinel environment is the fastest way to take real, defensible portfolio screenshots and to validate the rules with Atomic Red Team. Microsoft's free credits let you do this end-to-end without spending money.

## What you get

- New Microsoft 365 E5 developer tenant (free, 90-day renewable)
- New Azure free account with $200 credit (30 days)
- Sentinel free trial — 10 GB/day for 31 days
- A Windows 11 VM onboarded to Microsoft Defender for Endpoint trial
- This entire rule pack deployed via GitOps

Estimated cost across the trial window: **$0** if you cap log ingestion at 10 GB/day.

## Step 1 — Create a Microsoft 365 E5 developer tenant

1. Sign up at <https://developer.microsoft.com/en-us/microsoft-365/dev-program>
2. "Set up E5 sandbox" → "Instant sandbox" (auto-provisions a tenant + 25 fake users)
3. Note the tenant domain (`yourname.onmicrosoft.com`) and global admin creds

## Step 2 — Create an Azure free account

1. Sign in to <https://portal.azure.com> with the **same global admin** from step 1
2. Activate the free $200 credit (requires a credit card for ID verification — never charged within the credit limit)
3. Create a resource group, e.g. `rg-sentinel-lab`, region East US

## Step 3 — Create a Log Analytics workspace + enable Sentinel

```bash
az group create -n rg-sentinel-lab -l eastus

az monitor log-analytics workspace create \
  --resource-group rg-sentinel-lab \
  --workspace-name law-sentinel-lab \
  --sku PerGB2018 \
  --retention-time 30

# Daily cap to stay free
az monitor log-analytics workspace update \
  --resource-group rg-sentinel-lab \
  --workspace-name law-sentinel-lab \
  --quota 1 # GB/day; raise to 10 to stay within free trial

# Onboard Sentinel
az sentinel onboarding-state create \
  --resource-group rg-sentinel-lab \
  --workspace-name law-sentinel-lab \
  --name default
```

## Step 4 — Connect the data sources

In Sentinel → **Content Hub** → install:

- "Microsoft Entra ID"
- "Microsoft 365"
- "Azure Activity"
- "Microsoft Defender XDR"

Then Sentinel → **Data connectors** → for each, click **Open connector page** → **Connect** with the recommended log streams (SigninLogs, AuditLogs, OfficeActivity, AzureActivity, DeviceProcessEvents, DeviceNetworkEvents, DeviceInfo).

## Step 5 — Onboard a Windows VM to MDE

1. Sign up for the **Defender for Endpoint trial** at <https://security.microsoft.com> (90 days free)
2. Spin up a B1s Windows 11 VM in `rg-sentinel-lab` (free for 750 hr / month)
3. Run the MDE onboarding script on the VM (downloaded from Defender portal → Settings → Endpoints → Onboarding)
4. Verify the device appears under Defender → Assets → Devices

## Step 6 — Deploy this rule pack via Sentinel Repositories

1. Push this repo to **your** GitHub account: `https://github.com/sandeepmothukuri/sentinel-detection-engine`
2. Sentinel → **Repositories** → **Add new** → GitHub → authorise → select the repo
3. Branch: `main` → Save
4. Sentinel pulls the YAML files; within ~5 min you should see all 12 analytic rules + 10 hunting queries + 1 workbook in the portal

## Step 7 — Validate one detection end-to-end

On the MDE-onboarded VM:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

Within ~5 min the rule `MDE - PowerShell EncodedCommand With Long Payload` should fire. Confirm under Sentinel → **Incidents**.

## Now you can take real screenshots

With incidents actually firing on your tenant, capture screenshots of:
- Sentinel → Analytics → rules list
- Sentinel → Incidents → one incident's investigation graph
- Sentinel → Workbooks → L3 Triage Dashboard (loaded with real data)
- ATT&CK Navigator with `attack-navigator/layer.json` loaded

Drop them into `docs/images/` and reference them from the README.

## Tear-down

```bash
az group delete -n rg-sentinel-lab --yes --no-wait
```

This removes Sentinel, workspace, VM, NIC, public IP, disk — everything. Cancel the Defender trial under the Microsoft 365 admin center.
