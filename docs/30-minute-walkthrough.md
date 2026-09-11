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

On your local machine (PowerShell, in `<your-clone-dir>`):

```powershell
gh auth login          # if not already
gh repo create sentinel-detection-engine --public --source=. --push --description "Detection-as-code for Microsoft Sentinel"
```

### 3.2  Connect Sentinel to the GitHub repo (GitOps)

The connection deploys **ARM templates**, so point the content types at the generated folders:
`deploy/analytic-rules` for the rules and `deploy/hunting-queries` for the hunts. Pointing
"Analytic rules" at `Detections/` does not work — that folder holds the authoring YAML.

1. Sentinel → **Repositories** (left nav, under Configuration)
2. **Add new** → **GitHub** → authorise
3. Repository: `sandeepmothukuri/sentinel-detection-engine`
4. Branch: `main`
5. Set the content types to: Analytics rules → `deploy/analytic-rules`; Hunting queries →
   `deploy/hunting-queries`. Add Workbooks and Playbooks once you have wrapped the workbook in an
   ARM template (the playbooks already are).
6. **Add**

Sentinel then creates a deployment workflow in your repository and runs it on each commit.
Watch it with:

```powershell
gh run watch   # in your repo dir
```

Within ~3–5 min:
- Sentinel → **Analytics** → 18 new rules
- Sentinel → **Hunting** → 10 new queries
- Sentinel → **Workbooks** → L3 Triage Dashboard (once wrapped in ARM)

Every later push re-syncs: the repository becomes the source of truth, and portal edits to
connected content are overwritten on the next run.

**📸 Screenshot #3 — `03-analytics-rules.png`**
Sentinel → **Analytics** → **Active rules** tab — shows your 18 rules listed, enabled.

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
cd <your-clone-dir>

# File each capture under the matching area, with a descriptive name. The directories
# already exist and hold the generated diagrams:
#   docs/images/sentinel/    workspace, connectors, analytics-rule list
#   docs/images/attack/      ATT&CK Navigator with your layer.json loaded
#   docs/images/detections/  the incident that your atomic produced
#   docs/images/workbooks/   the L3 dashboard rendering your own data
git add docs/images
git commit -m "Add lab screenshots captured after deploying the rule pack"
git push
```

**Register each image before you push it.** Add a row to [`evidence.md`](evidence.md) recording its
purpose, source, environment, date, what it demonstrates and what you redacted (tenant or
subscription id, user principal names, addresses, hostnames, tokens). Images without a register entry
do not belong in the repository: an unlabelled screenshot is exactly what this repository's evidence
policy exists to prevent.

Once registered, reference the images from the README's screenshot section. The generated diagrams
are already referenced there; your captures go alongside them, clearly identified as coming from
your own lab.

---

## Phase 7 — Tear down (1 min, when you're done)

```bash
az group delete -n rg-sentinel-lab --yes --no-wait
```

Cancel the Defender for Endpoint trial in <https://admin.microsoft.com> → Billing → Your products.
Keep the dev tenant — it's free indefinitely.

---

## Recap — the screenshots that would be legitimate

| # | File | Source | Defensible |
|---|---|---|---|
| 1 | `01-sentinel-overview.png` | Your Sentinel workspace | Yes — you set it up |
| 2 | `02-data-connectors.png` | Your connectors | Yes — you connected them |
| 3 | `03-analytics-rules.png` | Your 18 rules deployed | Yes — your code |
| 4 | `04-attack-navigator.png` | Navigator + your layer.json | Yes — your coverage data |
| 5 | `05-incident-list.png` | Real incident on your tenant | Yes — your rule fired on your atomic |
| 6 | `06-investigation-graph.png` | Same incident's entity graph | Yes |
| 7 | `07-workbook-live.png` | Your workbook with live data | Yes — your JSON, your data |

Every one of these you can walk an interviewer through, because you produced it. That is the bar —
and it is why this repository ships none of them: a screenshot taken from a tenant that does not
exist would be a fabrication, and a redacted capture from a real workspace with real telemetry is
worth more than every diagram in `docs/images/` put together.

Until you capture them, the repository stands on what it can prove: 28 validated rule files, 31
upstream-verified atomic citations, and a build that fails when any of it drifts.
