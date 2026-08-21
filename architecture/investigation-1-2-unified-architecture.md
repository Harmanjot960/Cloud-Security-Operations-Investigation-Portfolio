# Diagram — Unified Cloud & Endpoint Investigation Workflow

                  AWS Cloud Environment
             (Cloud Activity / CloudTrail)
                         │
                         ▼
                AWS Security Telemetry
                         │
                         │
                         ├──────────────────────────────┐
                         │                              │
                         ▼                              ▼
              Windows Endpoint                 Cloud / Identity Activity
              (Endpoint Telemetry)             (IAM / EC2 / S3)
                         │                              │
                         ▼                              ▼
               Security / Endpoint              AWS CloudTrail Logs
                    Events                             │
                         │                              │
                         └──────────────┬───────────────┘
                                        │
                                        ▼
                          Microsoft Sentinel
                           (SIEM / Detection)
                                        │
                                        ▼
                              Security Incidents
                                        │
                                        ▼
                       Microsoft Defender Unified
                           Security Operations
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                         ▼                             ▼
                  Incident Investigation        Advanced Threat Hunting
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                              KQL Investigation
                                        │
                                        ▼
                         Cross-Source Correlation
                                        │
                                        ▼
                         Attack Chain Reconstruction
                                        │
                                        ▼
                         MITRE ATT&CK Mapping
                                        │
                                        ▼
                         Analyst Assessment /
                         Incident Disposition


## Investigation Coverage

**Investigation 1 — Multi-Stage Endpoint Compromise**
- Windows Security telemetry
- Endpoint detection telemetry
- KQL investigation
- Advanced threat hunting
- Attack-chain reconstruction
- MITRE ATT&CK mapping

**Investigation 2 — AWS Cloud Account Compromise & Persistence**
- AWS CloudTrail telemetry
- IAM / EC2 / S3 investigation
- Microsoft Sentinel detection
- Microsoft Defender Unified Security Operations
- Advanced threat hunting
- Cross-service attack-chain reconstruction
- MITRE ATT&CK mapping

> Microsoft Defender Unified Security Operations is used for incident management and advanced threat hunting. Microsoft Sentinel provides the SIEM detection and investigation layer where applicable.
