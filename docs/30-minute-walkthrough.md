# 30-minute walkthrough — get real Sentinel screenshots

Follow this top-to-bottom. Every step is copy-paste or click-by-click. At the end you have a working Sentinel tenant, real incidents firing on real rules, and four legitimate screenshots for your portfolio.

**Time:** ~30 min active + 10–15 min of waiting for log ingestion
**Cost:** $0 (Microsoft credits cover everything in the trial window)
**You need:** a credit card (for ID verification — never charged), a Windows machine, a phone for MFA

---

## Phase 0 — Accounts (5 min)

### 0.1  Microsoft 365 E5 developer tenant

1. Open <https://developer.microsoft.com/en-us/microsoft-365/dev-program>
2. **Join now** → sign in with a personal Microsoft account (NOT a work one)
3. Fill the form → choose **"Instant sandbox"** → English (United States)
4. Set a global admin password. Write down:
   - Admin UPN: `admin@<yourname>.onmicrosoft.com`
   - Password: ____________________
   - Tenant ID: copy from the success screen
5. Sign in to <https://admin.microsoft.com> with those credentials to confirm

> The sandbox auto-creates 25 fake users and assigns E5 licences — you don't have to.

### 0.2  Azure free account on the same tenant

1. Open a new private window → <https://azure.microsoft.com/free>
2. **Start free** → sign in with the global admin UPN from 0.1
3. Verify with phone + credit card (ID only — Microsoft will not charge inside the credit)
4. Activate the $200 / 30-day credit

You now own an Azure subscription tied to your dev tenant.

---

## Phase 1 — Spin up Sentinel (8 min)

Open Cloud Shell at <https://portal.azure.com> (top bar, `>_` icon) → choose **Bash**. Then paste:

```bash
SUB=$(az account show --query id -o tsv)
LOC=eastus
RG=rg-sentinel-lab
WS=law-sentinel-lab

az group create -n $RG -l $LOC

az monitor log-analytics workspace create \
  --resource-group $RG \
  --workspace-name $WS \
  --sku PerGB2018 \
  --retention-time 30 \
  --quota 1

WS_ID=$(az monitor log-analytics workspace show -g $RG -n $WS --query id -o tsv)

az sentinel onboarding-state create \
  --resource-group $RG \
  --workspace-name $WS \
  --name default
```

Wait ~60 s, then in the portal **search bar → "Microsoft Sentinel" → open it →** your workspace `law-sentinel-lab` is listed. Click it.

**📸 Screenshot #1 — `01-sentinel-overview.png`**
Sentinel → **Overview**. Shows your fresh workspace, zero incidents, ingestion ready.

---

## Phase 2 — Connect data sources (5 min)

In your Sentinel workspace:

1. **Content hub** (left nav) → search **"Microsoft Entra ID"** → Install
2. **Content hub** → search **"Azure Activity"** → Install
3. **Content hub** → search **"Microsoft 365"** → Install
4. **Content hub** → search **"Microsoft Defender XDR"** → Install (Defender XDR connector)

Then **Data connectors** (left nav):

| Connector | What to enable |
|---|---|
| Microsoft Entra ID | SigninLogs, AuditLogs, NonInteractiveUserSignInLogs |
| Azure Activity | Subscription = your free sub |
| Office 365 | Exchange + SharePoint + Teams |
| Microsoft Defender XDR | Connect, enable all tables (DeviceProcessEvents etc.) |

> Office 365 connector needs you to consent as the global admin — popup will ask.

**📸 Screenshot #2 — `02-data-connectors.png`**
Sentinel → **Data connectors** with at least 4 green "Connected" rows.

---

## Phase 3 — Deploy this rule pack (4 min)

### 3.1  Push the repo to your GitHub

On your local machine (PowerShell, in `C:\Users\sande\Downloads\sentinel-detection-engine`):

```powershell
gh auth login          # if not already
gh repo create sentinel-detection-engine --public --source=. --push --description "Detection-as-code for Microsoft Sentinel"
```

### 3.2  Connect Sentinel to the GitHub repo (GitOps)

1. Sentinel → **Repositories** (left nav, under Configuration)
2. **Add new** → **GitHub** → authorise
3. Repository: `sandeepmothukuri/sentinel-detection-engine`
4. Branch: `main`
5. Content types: leave defaults (Analytic rules, Hunting queries, Workbooks, Playbooks)
6. **Add**

Sentinel runs a GitHub Actions deployment from your repo. Watch:

```powershell
gh run watch   # in your repo dir
```

Within ~3–5 min:
- Sentinel → **Analytics** → 12 new rules
- Sentinel → **Hunting** → 10 new queries
- Sentinel → **Workbooks** → L3 Triage Dashboard

**📸 Screenshot #3 — `03-analytics-rules.png`**
Sentinel → **Analytics** → **Active rules** tab — shows your 12 rules listed, enabled.

**📸 Screenshot #4 — `04-attack-navigator.png`** *(do this now while waiting for logs)*
Open <https://mitre-attack.github.io/attack-navigator/> in a new tab.
**Open Existing Layer** → **Upload from local** → upload `attack-navigator/layer.json` from your repo.
Screenshot the heatmap.

---

## Phase 4 — Onboard a Windows VM to MDE (6 min)

### 4.1  Activate Defender for Endpoint trial

1. Open <https://security.microsoft.com> (signed in as your dev-tenant admin)
2. You'll be prompted to start the Defender XDR setup → accept the 90-day trial
3. **Settings → Endpoints → Onboarding**
4. Operating system: **Windows 10 and 11**
5. Deployment method: **Local script (for up to 10 devices)**
6. **Download onboarding package** — saves a `.zip`

### 4.2  Create a small Windows 11 VM

Back in Cloud Shell:

```bash
az vm create \
  --resource-group $RG \
  --name vm-win11-lab \
  --image MicrosoftWindowsDesktop:Windows-11:win11-23h2-pro:latest \
  --size Standard_B2s \
  --admin-username labadmin \
  --admin-password 'Choose-a-strong-Pass-9182!' \
  --public-ip-sku Standard \
  --nsg-rule RDP
```

Wait ~3 min. Then **RDP** to the public IP using `labadmin` / your password.

### 4.3  Onboard the VM

On the VM:
1. Copy the onboarding `.zip` from step 4.1 over (paste through RDP clipboard or upload to a temp Storage Account)
2. Extract → run `WindowsDefenderATPLocalOnboardingScript.cmd` as Administrator
3. Within 5–10 min, the device appears under <https://security.microsoft.com> → **Assets → Devices**

---

## Phase 5 — Fire a real detection (3 min)

Still on the lab VM, in an **Administrator PowerShell**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module Invoke-AtomicRedTeam

Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

This runs a long Base64-encoded PowerShell payload — exactly the pattern your `MDE_PowerShell_EncodedCommand` rule targets.

**Wait 5–10 minutes** for MDE → Sentinel pipeline.

Then back in Sentinel:

1. **Incidents** → you should see a new incident: *"MDE - PowerShell EncodedCommand With Long Payload"*
2. Click → **Investigate** → see the entity graph (device, user, process)

**📸 Screenshot #5 — `05-incident-list.png`**
Sentinel → **Incidents** with your real incident visible.

**📸 Screenshot #6 — `06-investigation-graph.png`**
Open the incident → **Investigate** → screenshot the entity graph.

**📸 Screenshot #7 — `07-workbook-live.png`**
Sentinel → **Workbooks** → **My workbooks** → **L3 Triage Dashboard** → run → screenshot with real data.

> Repeat with `Invoke-AtomicTest T1218.011 -TestNumbers 1` and `Invoke-AtomicTest T1053.005 -TestNumbers 1` to populate more rules — adds depth to the workbook.

---

## Phase 6 — Stash screenshots + update README (2 min)

```powershell
cd C:\Users\sande\Downloads\sentinel-detection-engine
# drop the 7 PNGs into docs/images/
git add docs/images/*.png
git commit -m "Add real Sentinel + Navigator screenshots from lab deployment"
git push
```

The README already references `docs/images/` — your screenshots will render on GitHub automatically.

---

## Phase 7 — Tear down (1 min, when you're done)

```bash
az group delete -n rg-sentinel-lab --yes --no-wait
```

Cancel the Defender for Endpoint trial in <https://admin.microsoft.com> → Billing → Your products.
Keep the dev tenant — it's free indefinitely.

---

## Recap — your seven legitimate screenshots

| # | File | Source | Defensible |
|---|---|---|---|
| 1 | `01-sentinel-overview.png` | Your Sentinel workspace | Yes — you set it up |
| 2 | `02-data-connectors.png` | Your connectors | Yes — you connected them |
| 3 | `03-analytics-rules.png` | Your 12 rules deployed | Yes — your code |
| 4 | `04-attack-navigator.png` | Navigator + your layer.json | Yes — your coverage data |
| 5 | `05-incident-list.png` | Real incident on your tenant | Yes — your rule fired on your atomic |
| 6 | `06-investigation-graph.png` | Same incident's entity graph | Yes |
| 7 | `07-workbook-live.png` | Your workbook with live data | Yes — your JSON, your data |

Every one of these you can walk an interviewer through. That's the bar.
