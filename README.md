# sentinel-detection-engine

**Detection-as-code for Microsoft Sentinel and Microsoft Defender XDR** — 18 scheduled analytics rules, 10 hypothesis-driven hunting queries, 4 SOAR playbooks behind explicit safety gates, an L3 triage workbook, generated ATT&CK coverage, a validation ledger that cites real Atomic Red Team tests, and the full L3 SOC workflow documentation to go with them.

[![validate](https://github.com/sandeepmothukuri/sentinel-detection-engine/actions/workflows/validate.yml/badge.svg)](https://github.com/sandeepmothukuri/sentinel-detection-engine/actions/workflows/validate.yml)
[![release](https://github.com/sandeepmothukuri/sentinel-detection-engine/actions/workflows/release.yml/badge.svg)](https://github.com/sandeepmothukuri/sentinel-detection-engine/actions/workflows/release.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **Validation status — read this first.** Nothing in this repository has been executed against a live tenant. Every rule is at `STATIC VALIDATION` and the repository documents the distinction between static validation and live production evidence.

## 1. Overview

| | |
|---|---|
| **Scope** | Microsoft Sentinel detection engineering: Entra ID, Microsoft 365, Defender for Endpoint, Azure control plane and Key Vault |
| **Detections** | 18 scheduled analytics rules |
| **Hunting queries** | 10 hypothesis-driven KQL hunts |
| **Response automation** | 4 playbooks behind confidence thresholds, allowlists and rollback paths |
| **Reporting** | L3 triage workbook, generated ATT&CK coverage and static HTML preview |
| **ATT&CK coverage** | 37 unique techniques across 12 of the 14 enterprise tactics |
| **Quality gates** | Automated validation, tests, CI drift checks and secret scanning |
| **Author** | Sandeep Mothukuri |

## 2. Why this exists

A detection is treated as an engineering hypothesis until it has evidence supporting its behaviour. Rules, hunts, playbooks, coverage artefacts and validation records are source-controlled and checked by CI.

## 3. Architecture

Telemetry flows from Entra ID, Microsoft 365, Defender for Endpoint, Azure Activity and Key Vault into the required Log Analytics tables. Detection rules and hunting queries consume those tables, incidents reach analysts through triage workflows and automation is constrained by explicit SOAR safety gates.

## 4. Detection inventory

The repository contains 18 scheduled analytics rules covering identity, Microsoft 365, endpoint, Azure control-plane and Key Vault activity.

## 5. Hunting inventory

The repository contains 10 hypothesis-driven hunting queries with required telemetry, expected findings, investigation steps, escalation guidance and limitations.

## 6. ATT&CK coverage

Coverage is generated from rule metadata and validated against the repository's vendored ATT&CK dataset.

## 7. Telemetry

Connector and table requirements are documented so a detection cannot silently depend on telemetry that the deployment does not provision.

## 8. SOAR

Four Logic App playbooks are constrained by explicit safety gates, allowlists, confidence thresholds and rollback guidance.

## 9. CI/CD

GitHub Actions validates detection content, metadata, KQL structure, mappings, coverage artefacts, tests and repository invariants.

## 10. Testing

The repository includes automated tests and generation checks designed to prevent undocumented drift.

## 11. Validation methodology

Validation separates static repository checks from live tenant evidence. Rules remain explicitly marked `STATIC VALIDATION` until a documented live procedure has been performed.

## 12. Deployment

Deployment documentation describes required connectors, tables, ARM templates, playbooks and workbooks without claiming a live tenant deployment where none exists.

## 13. Screenshots and diagrams

Repository diagrams document architecture, telemetry flow, hunting workflows and SOAR safety gates.

## 14. Metrics

MTTD, MTTR, detection quality, automation rate and other operational metrics are defined as measurement targets; unsupported live figures are not claimed.

## 15. Limitations

The repository documents structural limitations and clearly distinguishes generated repository evidence from live operational evidence.

## 16. Roadmap

Planned work includes further ATT&CK coverage, additional detection content, deployment validation and operational measurement.

---

# 🛠️ Local Validation CLI

This repository is a **detection-as-code project**, not a standalone end-user scanner. The supported command-line entry point is the repository validator used by CI.

### Install the validation toolchain

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Run the validator

From the repository root:

```bash
python sentinel_validate.py
```

The wrapper delegates to `scripts/ci_validate.py`, so local validation uses the same validator implementation as CI. It returns a non-zero exit code when the repository fails validation.

Run the full test suite:

```bash
python -m pytest tests -v
```

Run the underlying validator directly when debugging a failing check:

```bash
python scripts/ci_validate.py
python scripts/ci_validate.py --ledger-only
```

### What validation checks

The validator covers rule schema, scheduling, ATT&CK mappings, telemetry declarations, entity mappings, alert-detail placeholders, production metadata, KQL linting, validation-ledger integrity and Atomic Red Team references. The repository's CI workflow then performs the additional lint, link, generated-artifact and chart/image consistency gates. See [`scripts/ci_validate.py`](scripts/ci_validate.py) and [`.github/workflows/validate.yml`](.github/workflows/validate.yml).

### Important distinction

A successful local validation run means the repository passes its **static engineering checks**. It does **not** mean the KQL has been executed in a live Microsoft Sentinel tenant. The README intentionally keeps those states separate.

---

## License

MIT — see [LICENSE](LICENSE).

---

# 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:

- Security Operations
- Detection Engineering
- Threat Hunting
- Incident Response
- SIEM / XDR
- SOAR
- DFIR
- MITRE ATT&CK
- Security Automation
- AI-Augmented SOC Operations

This repository is maintained as a practical security engineering environment for designing, testing and validating modern SOC capabilities.

- GitHub: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- Website: [cybertechnology.in](https://cybertechnology.in)
- LinkedIn: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- Email: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository Description | |
| --- | --- |
| [AI-SOC-Decision-Engine](https://github.com/sandeepmothukuri/AI-SOC-Decision-Engine) | AI-assisted SOC decision/control plane for triage, enrichment, safety controls and analyst approval |
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for analyst-assisted triage |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response |
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage |

---

**Author portfolio:** [github.com/sandeepmothukuri](https://github.com/sandeepmothukuri)
