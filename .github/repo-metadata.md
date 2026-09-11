# Repository metadata — paste these into GitHub

GitHub doesn't read this file automatically. Use it as the reference when configuring repo settings.

## Description (one line, ≤ 350 chars)

```
Detection-as-code for Microsoft Sentinel and Defender XDR. 12 analytic rules, 10 hunting queries, 4 SOAR playbooks, ATT&CK Navigator coverage, CI validation, and the full L3 SOC workflow documentation (IR runbook, triage SOP, escalation matrix, tuning log, maturity assessment).
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
  --description "Detection-as-code for Microsoft Sentinel and Defender XDR. 12 analytic rules, 10 hunting queries, 4 SOAR playbooks, ATT&CK Navigator coverage, CI validation, and full L3 SOC workflow documentation." \
  --homepage "https://github.com/sandeepmothukuri" \
  --add-topic azure-sentinel,microsoft-sentinel,defender-xdr,defender-for-endpoint,kql,detection-engineering,detection-as-code,threat-hunting,soc,incident-response,blue-team,mitre-attack,security-automation,soar,logic-apps,sigma-rules,atomic-red-team,entra-id,security-operations,cybersecurity
```

## Social preview image

Settings → Social preview → upload a 1280×640 PNG.
Quick option: a cropped screenshot of `docs/dashboard-preview.html` (the workbook mockup) with the title overlaid.
