# deploy/ — generated ARM templates

**Generated. Do not edit.** Every file here is produced from `Detections/*.yaml` and
`Hunting Queries/*.yaml` by [`scripts/generate_arm_templates.py`](../scripts/generate_arm_templates.py).
A CI drift gate fails if this directory stops matching the rule files, and
`tests/test_arm_templates.py` checks the shape of the output.

```bash
python scripts/generate_arm_templates.py          # regenerate
python scripts/generate_arm_templates.py --check   # what CI runs
```

## Why it is not just the YAML

Microsoft Sentinel **Repositories** — the CI/CD connection between a Git repository and a workspace —
deploys **Bicep or ARM templates**. The analytics-rule YAML used for authoring (the
[Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) layout this repository's `Detections/`
folder follows) is not one of those formats. Connecting a repository and pointing the "Analytic
rules" content type at `Detections/` does not sync those rules: they have to be converted.

Microsoft's own sample content ships a PowerShell converter
([`ConvertAnalyticsRuleFromYamlToArm.ps1`](https://github.com/SentinelCICD/RepositoriesSampleContent/blob/main/Detections/ConvertAnalyticsRuleFromYamlToArm.ps1))
for exactly this reason. This directory is the tested, reviewable equivalent, generated in CI so the
deployable artifact can never drift from the rule that was validated.

| Directory | Content type | ARM resource |
|---|---|---|
| `analytic-rules/` | Analytics rules | `Microsoft.OperationalInsights/workspaces/providers/alertRules` (`2020-01-01`), `kind: Scheduled` |
| `hunting-queries/` | Hunting queries | `Microsoft.OperationalInsights/workspaces/savedSearches` (`2020-08-01`), `category: Hunting Queries` |

## How a repository connection uses it

In the Microsoft Defender portal: **Microsoft Sentinel → Content management → Repositories → Add new**,
point the connection at this repository and set the folders per content type:

| Content type | Folder |
|---|---|
| Analytic rules | `deploy/analytic-rules` |
| Hunting queries | `deploy/hunting-queries` |
| Workbooks | `Workbooks` (after wrapping in an ARM template — see [`docs/deployment.md`](../docs/deployment.md)) |
| Playbooks | `Playbooks` (already ARM) |

Each template takes one parameter, `workspace`, which is the Log Analytics workspace name that
Sentinel is enabled on. The resource name is built as
`<workspace>/Microsoft.SecurityInsights/<rule id>`, using the `id` committed in the rule file rather
than a fresh GUID — so re-running the deployment **updates** the existing rule instead of creating a
duplicate.

## What this directory is not

- **Not a deployment.** No template here has been deployed to a tenant. Their structure is validated
  by tests; Azure has not seen them. See [`docs/limitations.md`](../docs/limitations.md).
- **Not the authoring format.** `metadata:` — false-positive notes, tuning guidance, validation
  status — is deliberately dropped, because it is not a property of an alert rule and a template
  carrying it would be rejected. It stays in the rule files under `Detections/`.
- **Not playbooks.** `Playbooks/*/azuredeploy.json` are hand-written ARM templates and are not
  generated from anything.
