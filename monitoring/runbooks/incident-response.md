# Incident Response Runbook
## Zero-Trust Federal Cloud Environment

**Document Classification:** Internal Use  
**Last Updated:** 2024-12-15  
**Review Cycle:** Quarterly  
**NIST Controls:** IR-4, IR-5, IR-6, IR-8  

---

## 1. Incident Severity Classification

| Severity | Definition | Examples | Response SLA |
|----------|-----------|----------|-------------|
| **P1 — Critical** | Active breach, data exfiltration, or complete service loss | Lateral movement detected (ZT-002), privilege escalation (ZT-003), data exfiltration (ZT-004) | 5-min triage, 15-min CISO, 4-hr resolution |
| **P2 — High** | Potential breach indicator or significant security degradation | Service account abuse (ZT-005), certificate anomaly (ZT-006), DNS tunneling (ZT-008) | 15-min triage, 30-min SOC lead, 8-hr resolution |
| **P3 — Medium** | Configuration drift or policy violation | Security group changed outside IaC (ZT-007), encryption config modified | 1-hr triage, next business day review, 5-day resolution |
| **P4 — Low** | Informational finding or minor policy deviation | Failed login below threshold, routine certificate rotation | 4-hr triage, weekly SOC review, 30-day resolution |

---

## 2. Five-Minute Triage Flow

```
Alert fires (SIEM correlation rule triggers)
│
├── Step 1: Validate alert                                    [60 seconds]
│   • Is this a known false positive? Check FP suppression list
│   • Is this during a scheduled maintenance window?
│   • Does the alert correlate with a known change request?
│   └── If YES to any → Document and close. If NO → Continue.
│
├── Step 2: Identify blast radius                             [90 seconds]
│   • Which trust zone(s) are affected?
│   • How many systems/identities involved?
│   • Is the affected system internet-facing?
│   • What data classification does the system handle?
│   └── Record: zones, systems, data classification
│
├── Step 3: Correlate events in SIEM                          [90 seconds]
│   • Same source IP/identity across multiple segments?
│   • Privilege escalation events in the same time window?
│   • Unusual data access patterns from the same identity?
│   • Configuration changes preceding the alert?
│   └── Record: correlated events, timeline
│
└── Step 4: Classify and engage                               [60 seconds]
    • Assign severity (P1–P4) based on matrix above
    • P1: Page on-call responder + notify CISO within 15 min
    • P2: Notify SOC lead within 30 min
    • P3/P4: Queue for scheduled review
    └── Create incident ticket with triage findings
```

---

## 3. Response Procedures by Alert Type

### ZT-002: Lateral Movement Detected

**Trigger:** New east-west communication path AND/OR failed auth followed by successful connection.

**Immediate containment (within 15 minutes):**

1. **Isolate the source workload**
   - Apply quarantine security group (blocks all egress except to SIEM)
   - Do NOT terminate the instance — preserve forensic evidence
   
2. **Revoke associated credentials**
   - Disable the source identity in IdP
   - Rotate all service account credentials on the affected workload
   - Invalidate all active sessions for the identity

3. **Preserve evidence**
   - Snapshot the affected instance's storage volumes
   - Export the last 24 hours of flow logs for affected security groups
   - Export authentication logs for the affected identity
   - Record the current state of all security group rules

**Investigation (within 4 hours):**

4. **Trace the attack path**
   - Query SIEM: all network connections from the source identity in last 48 hours
   - Query SIEM: all authentication events for the source identity in last 48 hours
   - Map: which systems did the compromised workload communicate with?
   - Determine: was any data accessed or exfiltrated?

5. **Determine root cause**
   - How was the workload initially compromised?
   - Was it a vulnerability exploit, credential theft, or insider?
   - Are other workloads similarly vulnerable?

6. **Assess impact**
   - Which data was potentially accessed?
   - Data classification of affected systems?
   - Number of users/records potentially affected?

**Recovery:**

7. **Remediate the vulnerability**
   - Patch the exploited vulnerability
   - Strengthen security groups to prevent the specific attack path
   - Update IDS/IPS signatures if applicable

8. **Restore service**
   - Deploy clean replacement workload from known-good image
   - Verify security group rules match Terraform state
   - Restore from backup if data integrity is compromised
   - Monitor closely for 72 hours post-restoration

---

### ZT-003: Privilege Escalation

**Trigger:** Admin role assumed from unauthorized source.

**Immediate containment:**

1. **Revoke the escalated privileges immediately**
   - Remove the assumed role from the identity
   - Disable the source identity pending investigation

2. **Audit all actions taken with elevated privileges**
   - Query CloudTrail/audit log for all API calls made with the assumed role
   - Identify: resources created, modified, or deleted
   - Identify: data accessed or downloaded

3. **Check for persistence mechanisms**
   - Were new IAM users/roles/policies created?
   - Were new SSH keys or API keys generated?
   - Were any automation pipelines modified?
   - Were any scheduled tasks (cron, Lambda) created?

---

### ZT-004: Data Exfiltration

**Trigger:** Outbound data transfer exceeds 2x baseline.

**Immediate containment:**

1. **Block egress from the affected security group**
   - Apply restrictive egress rules allowing only essential services
   - Do NOT block ingress — maintain ability to investigate

2. **Identify the data being transferred**
   - Correlate flow logs with data access logs
   - What databases/storage were queried in the time window?
   - What is the classification of the accessed data?

3. **Determine the destination**
   - Where is the data being sent? (IP, domain, service)
   - Is it an authorized destination? (Check approved egress list)
   - Is it a known malicious infrastructure? (Check threat intel feeds)

---

## 4. Communication Templates

### P1 Initial Notification (within 15 minutes)

```
Subject: [P1 INCIDENT] [Rule ID] — [Brief Description]

Incident ID: INC-YYYY-NNNN
Time Detected: [UTC timestamp]
Severity: P1 — Critical
Status: Active — Containment in progress

Summary: [2-3 sentence description of what was detected]

Affected Systems: [List trust zones and systems]
Data Classification: [Public / CUI / Sensitive]
Blast Radius: [Number of systems, estimated data exposure]

Actions Taken:
1. [Containment action 1]
2. [Containment action 2]

Next Update: [30 minutes from now]
Incident Commander: [Name]
```

---

## 5. Post-Incident Review Template

Every P1 and P2 incident requires a post-incident review within 5 business days.

1. **Timeline:** Minute-by-minute reconstruction of the incident
2. **Detection:** How was the incident detected? How long between compromise and detection?
3. **Root cause:** What was the underlying vulnerability or failure?
4. **Impact:** Systems affected, data exposed, business impact
5. **Response effectiveness:** What worked well? What could be improved?
6. **Remediation:** What was fixed? What remains to be done?
7. **Lessons learned:** What changes should be made to prevent recurrence?
8. **Action items:** Specific tasks with owners and due dates

---

## 6. Escalation Matrix

| Role | Contact Method | When to Engage |
|------|---------------|----------------|
| SOC Analyst (on-call) | PagerDuty | All alerts during off-hours |
| SOC Lead | PagerDuty + Slack | P1/P2 incidents |
| CISO | Phone + encrypted email | P1 incidents within 15 min |
| System Owner | Slack + email | When their system is affected |
| Legal/Privacy | Encrypted email | Potential data breach involving PII |
| Communications | Encrypted email | Potential public-facing impact |
| US-CERT | Secure reporting portal | Per FISMA reporting requirements |
