# Cloud-Security-Operations-Investigation-Portfolio

This repository contains four SOC investigations demonstrating practical security operations workflows across **Microsoft Azure, Microsoft Sentinel, Microsoft Defender Unified Portal, AWS CloudTrail, CrowdStrike, Windows Security Logs, and ServiceNow**. The investigations cover cloud and endpoint telemetry analysis, detection engineering, alert investigation, threat hunting, incident management, cross-environment correlation, **MITRE ATT&CK mapping**, and evidence-based incident reporting.

Investigations 1 and 2 use testing-lab security telemetry ingested into Azure Log Analytics and investigated through Microsoft Sentinel, while Investigation 3 demonstrates a self-built live Windows RDP detection pipeline and Investigation 4 focuses on ServiceNow-based SOC alert triage and incident management.

---

## Overview

The portfolio demonstrates an end-to-end SOC workflow:

**Detection → Alert Triage → Investigation → Threat Hunting → Evidence Analysis → Cross-Alert Correlation → MITRE ATT&CK Mapping → Incident Classification → Escalation / Resolution**

All investigations include supporting **screenshots**, technical evidence, investigation findings, and documented analyst conclusions.

---

## Platforms, Tools & Frameworks

[![Microsoft Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-0078D4?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![Microsoft Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoft&logoColor=white)](https://azure.microsoft.com/products/microsoft-sentinel)
[![Microsoft Defender](https://img.shields.io/badge/Security-Microsoft%20Defender-5E5E5E?logo=microsoft&logoColor=white)](https://www.microsoft.com/security/business)
[![AWS CloudTrail](https://img.shields.io/badge/Cloud%20Security-AWS%20CloudTrail-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/cloudtrail/)
[![CrowdStrike](https://img.shields.io/badge/Endpoint-CrowdStrike-E01E5A?logo=crowdstrike&logoColor=white)](https://www.crowdstrike.com/)
[![ServiceNow](https://img.shields.io/badge/ITSM-ServiceNow-62D84E?logo=servicenow&logoColor=white)](https://www.servicenow.com/)
[![KQL](https://img.shields.io/badge/Detection-KQL-0078D4?logo=microsoft&logoColor=white)](https://learn.microsoft.com/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-FF6F00?logo=mitre&logoColor=white)](https://attack.mitre.org/)

---

## Investigations

### Investigation 1 — Microsoft Sentinel + Microsoft Defender Unified Portal

**CrowdStrike & Windows Security Logs**

Multi-stage endpoint compromise investigation involving Windows Security telemetry and CrowdStrike data. The investigation reconstructed attacker activity across **execution, credential access, persistence, command and control, defense evasion, collection, and impact**, with cross-source correlation, IOC analysis, attack timeline reconstruction, and **MITRE ATT&CK mapping**.

[**View Investigation 1**](./investigations/Investigation%201%20%E2%80%94%20Microsoft%20Sentinel%20%2B%20Microsoft%20Defender%20Unified%20Portal%20-%20CrowdStrike%20%26%20Windows%20Security%20Logs/)

---

### Investigation 2 — Microsoft Sentinel + Microsoft Defender Unified Portal

**AWS CloudTrail Investigation**

AWS cloud account compromise investigation covering **cloud reconnaissance, IAM enumeration, persistence, privilege escalation, EC2 deployment, S3 data access, malicious activity, and CloudTrail tampering**. The investigation includes CloudTrail analysis, attack-chain reconstruction, IOC identification, evidence review, and **MITRE ATT&CK mapping**.

[**View Investigation 2**](./investigations/Investigation%202%20%E2%80%94%20Microsoft%20Sentinel%20%2B%20Microsoft%20Defender%20Unified%20Portal%20-%20AWS%20CloudTrail%20Investigation/)

---

### Investigation 3 — Microsoft Defender Unified Portal

**Live Windows RDP Brute-Force Detection**

Live detection investigation using a self-built Azure Windows Server 2022 detection pipeline with **Microsoft Sentinel, Azure Monitor Agent, Windows Security Logs, and Microsoft Defender Unified Portal**. Real external RDP authentication activity generated Windows Security **Event ID 4625** telemetry and triggered a custom detection. The alert and incident were investigated and managed through the Microsoft security operations interface, including assignment, classification, resolution, **MITRE ATT&CK mapping**, and investigation of an automation playbook limitation.

[**View Investigation 3**](./investigations/Investigation%203%20%E2%80%94%20Microsoft%20Defender%20Unified%20Portal%20-%20Live%20Windows%20RDP%20Brute-Force%20Detection/)

---

### Investigation 4 — Triage - ServiceNow Alert Correlation

**SOC Alert Triage & Cross-Alert Correlation**

SOC alert-triage investigation involving six ServiceNow incidents representing suspicious and benign security activity. The investigation demonstrates **false-positive identification, benign activity validation, incident disposition, cross-alert correlation, timeline analysis, and escalation to Incident Response / L2**, including correlation between AWS CloudTrail and Windows endpoint activity.

[**View Investigation 4**](./investigations/Investigation%204%20%E2%80%94%20Triage%20-%20ServiceNow%20Alert%20Correlation/)

---

## Evidence & Documentation

Each investigation includes:

- **Investigation Report**
- **Supporting Screenshots**
- **Technical Investigation Evidence**
- **MITRE ATT&CK Mapping**
- **Detection / Query Analysis**
- **Incident Timeline**
- **IOC Analysis**
- **Analyst Findings & Disposition**
---

## Repository Structure

```text
Cloud-Security-Operations-Investigation-Portfolio/
│
├── README.md
│
├── architecture/
│   ├── investigation-1-2-unified-architecture.md
│   ├── investigation-3-live-rdp-detection-architecture.md
│   └── investigation-4-servicenow-correlation.md
│
└── investigations/
    │
    ├── Investigation 1 — Microsoft Sentinel + Microsoft Defender Unified Portal - CrowdStrike & Windows Security Logs/
    │   ├── screenshots/
    │   └── report/
    │       └── investigation-1-Microsoft Sentinel + Microsoft Defender Unified Portal - CrowdStrike & Windows Security Logs.md
    │
    ├── Investigation 2 — Microsoft Sentinel + Microsoft Defender Unified Portal - AWS CloudTrail Investigation/
    │   ├── screenshots/
    │   └── report/
    │       └── investigation-2-Microsoft Sentinel + Microsoft Defender Unified Portal - AWS CloudTrail Investigation.md
    │
    ├── Investigation 3 — Microsoft Defender Unified Portal - Live Windows RDP Brute-Force Detection/
    │   ├── screenshots/
    │   └── report/
    │       └── investigation-3-Microsoft Defender Unified Portal - Live Windows RDP Brute-Force Detection.md
    │
    └── Investigation 4 — Triage - ServiceNow Alert Correlation/
        ├── screenshots/
        └── report/
            └── investigation-4-Triage - ServiceNow Alert Correlation.md
```
---

## Focus

• SOC Operations • Microsoft Sentinel • Microsoft Defender Unified Portal • AWS CloudTrail • CrowdStrike • Windows Security Logs • ServiceNow • Detection Engineering • Threat Hunting • Incident Investigation • MITRE ATT&CK
