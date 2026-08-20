# Investigation 4— ServiceNow Alert Triage and Cross-Alert Correlation

## ServiceNow | SOC Alert Triage | Incident Disposition

**Analyst:** Harman Jot<br>
**Environment:** ServiceNow SOC Training Environment<br>
**Primary Platform:** ServiceNow<br>
**Data Sources:** ServiceNow incidents, Windows Security telemetry, AWS CloudTrail activity, endpoint investigation results<br>

---

## 1. Summary

A six-incident ServiceNow alert queue was manually created from previously identified investigation data and then triaged to separate benign activity from actionable security events.

The incidents were not treated as six independent investigations. Four alerts were validated as benign or expected activity and resolved, while two suspicious alerts — **INC0010010** and **INC0010013** — were correlated into a single cross-environment compromise.

The key correlation was the shared:

- **Account:** `mirage`
- **Source IP:** `198.51.100.42`

This linked AWS reconnaissance activity with Windows endpoint activity on `win11a`.

### Final Result

- **4 alerts:** Benign / Expected → Resolved
- **2 alerts:** True Positive / Malicious → Escalated / In Progress
- **1 correlated investigation:** AWS + Windows endpoint

---

## 2. Six-Incident Triage

| Incident | Alert | Verdict | Disposition |
|---|---|---|---|
| **INC0010008** | Single failed contractor login | False Positive / Benign | **Resolved** |
| **INC0010010** | Security Event log cleared – `win11a` | **True Positive** | **Escalated / In Progress** |
| **INC0010011** | Known backup script after hours | Benign / Expected | **Resolved** |
| **INC0010012** | New user account created – HR onboarding | Benign / Expected | **Resolved** |
| **INC0010013** | Suspicious AWS CLI – `mirage` | **True Positive** | **Escalated / In Progress** |
| **INC0010014** | Expected vulnerability scanner | Benign / Expected | **Resolved** |

### Benign Alerts

The following incidents were resolved after validating their context:

- **INC0010008:** Single failed login with no evidence of successful authentication, brute-force activity, or account compromise.
- **INC0010011:** Activity associated with a known backup process.
- **INC0010012:** Account creation associated with legitimate HR onboarding.
- **INC0010014:** Activity matched an authorized vulnerability scanner and documented scanning schedule.

Each benign incident was documented in ServiceNow Work notes and resolved using the **Solution provided** resolution code.

---

## 3. True-Positive Alerts

### INC0010010 — NRT Security Event Log Cleared - win11a

**Verdict:** True Positive — Malicious Activity
**Assessment Severity:** High
**MITRE ATT&CK:** T1070.001 — Clear Windows Event Logs
**State:** In Progress
**Assigned To:** Harman Jot

At **8:38 AM**, Windows Security Event ID 1102 showed that the Security audit log on `win11a` was cleared by `PKWORK\mirage`. The activity was subsequently correlated with the same account and source IP (`198.51.100.42`) observed in the AWS investigation.

Viewed in isolation, this activity could potentially represent routine administrative log maintenance.

The alert was then correlated with **INC0010013 — Suspicious AWS CLI Command Execution - user mirage**.

Both incidents contained the same:

- Account: `mirage`
- Source IP: `198.51.100.42`

Subsequent endpoint investigation identified:

- Malicious file execution: `report.exe`
- Repeated LSASS credential dumping
- C2 communication with `update-service-cdn.xyz`
- Security tooling tampering
- Encoded PowerShell execution
- Sensitive document staging
- Shadow-copy deletion

The Event ID 1102 activity was therefore assessed as **malicious defense evasion** rather than routine log maintenance.

### Action

Escalate to **Incident Response / L2** for full compromise assessment.

Recommended actions included:

- Rotate credentials associated with `mirage`.
- Review related AWS CloudTrail and S3 activity.
- Continue investigation of `win11a`.
- Monitor for additional related indicators.
- Keep the incident open pending further investigation.

---

### INC0010013 — Suspicious AWS CLI Command Execution - user mirage

**Verdict:** True Positive — Malicious Activity
**Assessment Severity:** High
**MITRE ATT&CK:** T1580 — Cloud Infrastructure Discovery
**State:** In Progress
**Assigned To:** Harman Jot

At **8:33 AM**, AWS user `mirage` executed a burst of read-only reconnaissance commands from source IP `198.51.100.42`.

Observed activity included:

- IAM user enumeration
- IAM role enumeration
- EC2/VPC discovery
- KMS key enumeration

Viewed in isolation, this activity could potentially represent legitimate cloud administration or auditing.

The alert was correlated with **INC0010010 — NRT Security Event log cleared - win11a**.

Both incidents contained the same:

- Account: `mirage`
- Source IP: `198.51.100.42`

### Timeline Correlation

**8:33 AM** — AWS reconnaissance
↓
**8:38 AM** — Windows Security Event ID 1102 / log clearing
↓
**8:46 AM** — `report.exe` execution on `win11a`
↓
**8:51 AM** — LSASS credential dumping
↓
**9:18 AM** — C2 activity
↓
**11:54 AM** — Security tooling tampering
↓
**11:57 AM onward** — Encoded PowerShell
↓
**12:01 PM onward** — Sensitive document staging
↓
**12:20 PM** — Shadow-copy deletion

The AWS activity immediately preceded the endpoint attack chain.

The AWS reconnaissance was therefore assessed as malicious cloud infrastructure discovery associated with the same broader compromise.

### Action

Escalate to **Incident Response / L2** for full cross-environment compromise assessment.

Recommended actions included:

- Rotate credentials associated with `mirage`.
- Review AWS CloudTrail and S3 activity.
- Investigate additional activity involving `win11a`.
- Monitor for related cloud and endpoint indicators.
- Keep the incident open pending further investigation.

---

## 4. Cross-Alert Correlation

The most important finding from the triage was that **INC0010010 and INC0010013 were not two independent investigations**.

They represented two alerts associated with the same broader compromise.

### Shared Indicators

| Indicator | Value |
|---|---|
| Account | `mirage` |
| Source IP | `198.51.100.42` |
| Endpoint | `win11a` |

### Correlated Attack Sequence

**AWS reconnaissance → Windows Security log clearing → malicious endpoint execution → LSASS credential dumping → C2 communication → defense evasion → PowerShell execution → sensitive file collection → shadow-copy deletion**

Individually:

- AWS reconnaissance could appear administrative.
- Windows Security log clearing could appear administrative.

After correlation with the endpoint investigation, the activity formed a consistent compromise sequence:

**AWS reconnaissance → log clearing → endpoint compromise → credential access → C2 → defense evasion → collection → impact**

This demonstrated the importance of **cross-alert correlation rather than evaluating each alert in isolation**.

---

## 5. ServiceNow Triage Actions

The ServiceNow workflow demonstrated the following SOC analyst activities:

- Reviewed each incident individually.
- Assessed alerts based on available evidence and context.
- Documented analyst findings in Work notes.
- Identified four benign or expected alerts.
- Resolved four benign/expected incidents.
- Identified two correlated malicious alerts.
- Assigned the malicious incidents to **Harman Jot**.
- Increased priority for the confirmed malicious incidents.
- Retained **INC0010010** and **INC0010013** as **In Progress**.
- Documented escalation to **Incident Response / L2**.
- Recommended credential rotation and additional cloud and endpoint investigation.

The ServiceNow training environment did not require creation of a separate Incident Response/L2 user or group. The escalation was documented in the Work notes while **Harman Jot** remained the assigned analyst.

---

## 6. Evidence / Screenshots

The following screenshots document the completed ServiceNow triage workflow:

| Screenshot | Evidence |
|---|---|
| **01** | Final ServiceNow incident queue showing the six alerts and their dispositions |
| **02** | INC0010008 benign/false-positive assessment and resolution |
| **03** | INC0010010 true-positive assessment, correlation, and escalation |
| **04** | INC0010011 known backup activity and resolution |
| **05** | INC0010012 legitimate HR onboarding activity and resolution |
| **06** | INC0010013 true-positive AWS reconnaissance, correlation, and escalation |
| **07** | INC0010014 expected vulnerability scanner activity and resolution |

The individual screenshots provide evidence of the analyst Work notes, incident state, priority, assignment, resolution code, and resolution notes where applicable.

---

## 7. Final Disposition

| Result | Count |
|---|---:|
| Benign / Expected | **4** |
| True Positive / Malicious | **2** |
| Total Alerts | **6** |

**4 / 6 alerts were resolved as benign or expected activity.**

**2 / 6 alerts were retained as true positives and escalated.**

The two true positives were correlated into **one cross-environment compromise** involving AWS activity and the `win11a` Windows endpoint.

---

## 8. Conclusion

This project demonstrates a practical SOC alert-triage workflow using ServiceNow and a controlled six-alert training queue based on previously identified investigation data.

The analyst did not simply resolve each alert independently. Benign activity was filtered out while potentially related alerts were correlated using:

- Identity
- Source IP
- Event timing
- Endpoint evidence
- Cloud activity
- Previously identified investigation results

The key correlation was:

**`mirage` + `198.51.100.42`**

This linked:

**AWS reconnaissance → Windows Security log clearing → endpoint compromise**

The final disposition resulted in:

**4 benign/expected alerts → Resolved**

**2 malicious alerts → Escalated / In Progress**

The two malicious alerts were treated as **one broader cross-environment investigation** rather than two unrelated incidents.

---

## 9. Skills Demonstrated

- SOC alert triage
- False-positive identification
- Benign activity validation
- ServiceNow incident management
- Work note documentation
- Incident disposition
- Alert correlation
- Timeline analysis
- Incident prioritization
- Incident escalation
- Cross-environment investigation
- AWS security-event analysis
- Windows security-event analysis
- Endpoint investigation correlation
- Incident Response / L2 escalation

---

*This project was conducted in a ServiceNow training environment as an independent SOC analyst skills-development exercise involving a controlled six-alert triage scenario based on previously identified investigation data.*
