# Repository metadata — paste these into GitHub

GitHub doesn't read this file automatically. Use it as the reference when configuring repo settings.

## Description (one line, ≤ 350 chars)

```
Detection-as-code for Microsoft Sentinel and Defender XDR. 18 scheduled analytics rules, 10 hunting queries, 4 SOAR playbooks behind explicit safety gates, an L3 triage workbook, an ARM deployment set generated from the validated rules, generated ATT&CK v19 coverage, a validation ledger with upstream-verified Atomic Red Team citations, and the full L3 SOC workflow documentation (IR runbook, triage SOP, escalation matrix, tuning log, maturity assessment).
```

## Website

```
https://github.com/sandeepmothukuri/sentinel-detection-engine
```

(Or your portfolio site / LinkedIn if you have one.)

## Topics (paste each, GitHub UI: Settings → top of page → ⚙ "About")

Pick **all** of these — every additional topic is another discovery channel:

```
azure-sentinel
microsoft-sentinel
defender-xdr
defender-for-endpoint
kql
detection-engineering
detection-as-code
threat-hunting
soc
incident-response
blue-team
mitre-attack
security-automation
soar
logic-apps
sigma-rules
atomic-red-team
entra-id
security-operations
cybersecurity
```

## How to set these via gh CLI

```bash
gh repo edit sandeepmothukuri/sentinel-detection-engine \
  --description "Detection-as-code for Microsoft Sentinel and Defender XDR. 18 scheduled analytics rules, 10 hunting queries, 4 SOAR playbooks behind safety gates, an L3 triage workbook, an ARM deployment set generated from the validated rules, generated ATT&CK coverage, a validation ledger with upstream-verified atomic citations, and full L3 SOC workflow documentation." \
  --homepage "https://github.com/sandeepmothukuri" \
  --add-topic azure-sentinel,microsoft-sentinel,defender-xdr,defender-for-endpoint,kql,detection-engineering,detection-as-code,threat-hunting,soc,incident-response,blue-team,mitre-attack,security-automation,soar,logic-apps,sigma-rules,atomic-red-team,entra-id,security-operations,cybersecurity
```

## Social preview image

Settings → Social preview → upload a 1280×640 PNG.

Use one of the **original diagrams**, not a mockup of a portal: the architecture diagram
(`docs/images/architecture/01-logical-architecture.png`) and the ATT&CK coverage chart
(`docs/images/attack/01-attack-coverage-by-tactic.png`) are both source-controlled and generated from
this repository's own content. Crop, place on a flat background and add the repository name.

Do not use the workbook design preview as a social image. It is a deliberately data-free wireframe
whose banner says it requires deployment to display live telemetry; cropping that banner away would
turn a labelled design artefact into something that reads like a screenshot of a running system.
