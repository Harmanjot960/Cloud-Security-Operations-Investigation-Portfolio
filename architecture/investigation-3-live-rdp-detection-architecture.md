# Diagram — Live External RDP Brute-Force Detection & Incident Response Workflow

```text
Internet
  |
  v
External Source IPs
  |
  v
Public RDP Exposure (TCP/3389)
  |
  v
Windows Server 2022 (WindowsVM)
  |
  v
Windows Security Logs (Event ID 4625)
  |
  v
Azure Monitor Agent
  |
  v
Data Collection Rule
  |
  v
Log Analytics Workspace
  |
  v
Microsoft Sentinel
  |
  v
Custom KQL Detection
  |
  v
External Failed-Logon Threshold
>20 attempts / source IP
  |
  v
Sentinel Alert / Incident
  |
  v
Microsoft Defender Unified Security Operations Interface
  |
  +-----------------------------+
  |                             |
  v                             v
ALERT / EVIDENCE             INCIDENT MANAGEMENT
INVESTIGATION
  |                             |
  v                             +--> Assign Incident
Authentication Analysis         |
  |                             +--> Manage Incident
  v                             |
Source IP / Username /          v
Logon Type / NTLM /         Classification
Failure Codes                    |
  |                             v
  v                        True Positive
Check Successful             Malicious Activity
Authentication                   |
  |                             |
  +-------------+---------------+
                |
                v
            Resolution
                |
                v
       L1 Investigation Complete
                |
                v
      Automation Test / Playbook
                |
                v
      HTTP 400 / Authorization
             Limitation
                |
                v
       Limitation Documented
