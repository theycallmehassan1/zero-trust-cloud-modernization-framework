# NIST SP 800-53 Rev 5 / FedRAMP Compliance Matrix

## Purpose

This document maps each NIST 800-53 Rev 5 control family to specific implementation components within the zero-trust federal cloud framework. It serves as evidence of compliance for FedRAMP authorization and FISMA assessments.

---

## Control Family: AC — Access Control

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| AC-2 | Account Management | Centralized IdP with automated provisioning/deprovisioning. Service accounts managed via SPIFFE/SPIRE with 1-hour SVID rotation. | IdP audit logs, SPIRE attestation logs |
| AC-2(1) | Automated System Account Management | Automated lifecycle: create on deploy, rotate hourly, revoke on decommission. Orphan account detection runs daily. | Automation pipeline logs, orphan account report |
| AC-3 | Access Enforcement | RBAC at infrastructure layer (hypervisor, storage, network). ABAC at application layer via policy engine. | Policy engine decision logs, security group configs |
| AC-4 | Information Flow Enforcement | Microsegmentation with distributed virtual firewalls. VXLAN isolation between trust zones. Explicit allow rules only. | Flow logs, security group rules, network topology |
| AC-6 | Least Privilege | Service accounts scoped to minimum required permissions. Human access reviewed quarterly. Privileged access requires MFA + approval. | IAM policy documents, access review records |
| AC-6(9) | Auditing Use of Privileged Functions | All admin API calls logged with caller identity, source IP, device posture, and request body hash. | SIEM dashboard, privileged access report |
| AC-17 | Remote Access | VPN with certificate-based authentication. Context-aware access policies. Split tunnel prohibited. | VPN logs, conditional access policy |

## Control Family: AU — Audit and Accountability

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| AU-2 | Event Logging | All authentication, authorization, network flow, API access, data access, configuration change, and certificate lifecycle events logged. | Log source inventory, FluentBit configuration |
| AU-3 | Content of Audit Records | Each log entry includes: timestamp, source identity, action, target resource, outcome, source IP, device ID, session ID. | Sample log records, log schema documentation |
| AU-6 | Audit Record Review, Analysis, and Reporting | SIEM correlation rules (ZT-001 through ZT-008) provide automated analysis. SOC reviews alerts per defined SLAs. | SIEM rule configuration, SOC activity reports |
| AU-6(1) | Process Integration | Audit findings automatically create tickets in incident management system. Critical alerts page on-call staff. | Integration configuration, sample incidents |
| AU-9 | Protection of Audit Information | Logs stored in append-only storage with integrity checksums. Access to log storage requires privileged role + MFA. | Storage configuration, access control policy |
| AU-12 | Audit Record Generation | Log agents (FluentBit) deployed on all compute hosts, containers, and network devices. Pipeline reliability monitored. | Agent deployment status, pipeline health dashboard |

## Control Family: CA — Security Assessment and Authorization

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| CA-2 | Security Assessments | Quarterly architecture reviews. Annual third-party penetration test. Monthly automated vulnerability scanning. | Assessment reports, pen test findings |
| CA-7 | Continuous Monitoring | Real-time SIEM monitoring. Daily configuration drift detection. Weekly vulnerability scan. Monthly DR test. | Monitoring dashboard, drift reports |
| CA-8 | Penetration Testing | Annual external pen test. Quarterly internal red team exercises. Monthly automated security scanning. | Pen test reports, red team findings |

## Control Family: CM — Configuration Management

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| CM-2 | Baseline Configuration | All infrastructure defined in Terraform. Application configurations in version-controlled Ansible playbooks. Approved base images in internal registry. | Git repository, Terraform state files |
| CM-3 | Configuration Change Control | All changes via pull request with peer review. Security-impacting changes require security team approval. Emergency changes documented within 24 hours. | Git history, PR approval records |
| CM-6 | Configuration Settings | CIS Level 2 benchmarks enforced via Ansible. STIG compliance for DoD-adjacent systems. Automated compliance scanning daily. | CIS scan reports, STIG checklist |
| CM-8 | System Component Inventory | Automated asset discovery with classification. Updated continuously via infrastructure-as-code deployments. | Asset inventory database, discovery scan results |

## Control Family: CP — Contingency Planning

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| CP-2 | Contingency Plan | Documented DR plan covering all tiers. Annual review and update. Covers scenarios: site loss, network partition, storage failure, cyber incident. | DR plan document, annual review records |
| CP-4 | Contingency Plan Testing | Monthly automated DR failover tests. Quarterly full-stack failover exercises. Findings tracked to remediation. | Test results, finding remediation log |
| CP-7 | Alternate Processing Site | Geographically separated DR site (>100 miles). Warm standby for Tier 2, hot standby for Tier 1 workloads. | DR site documentation, replication status |
| CP-9 | System Backup | Automated daily backups with encryption. Tier 1: synchronous replication. Tier 2: async replication (<15 min RPO). Tier 3: snapshot (<1 hour RPO). | Backup logs, replication lag monitoring |
| CP-10 | System Recovery and Reconstitution | Automated failover for Tier 1 workloads. Documented recovery procedures for Tier 2/3. Recovery tested monthly. | Failover test results, recovery time measurements |

## Control Family: IA — Identification and Authentication

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| IA-2 | Identification and Authentication (Org Users) | PIV/CAC primary authentication. FIDO2 hardware tokens as secondary. No password-only access to any system. | IdP configuration, authentication logs |
| IA-2(6) | Multi-Factor Authentication | MFA required for all access. Phishing-resistant methods only (PIV, FIDO2). No SMS/email OTP fallback. | MFA policy, enrollment statistics |
| IA-4 | Identifier Management | Unique identifiers for all human and machine identities. No shared accounts. Service identities via SPIFFE SVIDs. | Identity inventory, SPIRE attestation records |
| IA-5 | Authenticator Management | Automated certificate rotation (90-day for TLS, 1-hour for SVIDs). HSM-backed key storage. Compromised credential detection. | Certificate lifecycle logs, rotation records |
| IA-8 | Identification and Authentication (Non-Org Users) | Federated authentication with partner agencies via SAML 2.0 / OIDC. External users receive scoped, time-limited access. | Federation agreements, access logs |

## Control Family: IR — Incident Response

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| IR-4 | Incident Handling | Documented IR procedures with severity-based response SLAs. Automated containment actions for Critical severity. 5-minute triage flow. | IR runbook, incident records |
| IR-5 | Incident Monitoring | SIEM correlation rules for 8 threat categories. Real-time alerting. SOC operating 24/7 for Critical/High alerts. | SIEM configuration, alert statistics |
| IR-6 | Incident Reporting | Automated reporting to agency CISO for Critical/High incidents within 1 hour. US-CERT reporting within required timeframes. | Incident reports, notification records |
| IR-8 | Incident Response Plan | Annual IR plan review. Quarterly tabletop exercises. Post-incident reviews with documented lessons learned. | IR plan, exercise records, post-incident reports |

## Control Family: SC — System and Communications Protection

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| SC-7 | Boundary Protection | North-south: WAF + DDoS + API gateway. East-west: microsegmentation with distributed virtual firewalls. Default-deny on all boundaries. | Network architecture, firewall rules, flow logs |
| SC-8 | Transmission Confidentiality and Integrity | TLS 1.3 for all north-south traffic. mTLS for all east-west traffic. No plaintext communication anywhere. | TLS configuration, certificate inventory |
| SC-12 | Cryptographic Key Establishment and Management | HSM-backed key management (FIPS 140-2 Level 3). Three-tier key hierarchy. Automated key rotation. | HSM configuration, key rotation logs |
| SC-13 | Cryptographic Protection | AES-256 for all encryption operations. FIPS 140-2 validated cryptographic modules. Algorithm selection per ADR-003. | FIPS validation certificates, encryption configuration |
| SC-28 | Protection of Information at Rest | Block storage: LUKS2 with AES-256-XTS. Object storage: server-side AES-256-GCM. Database: TDE + column-level encryption. | Storage encryption configuration, audit logs |

## Control Family: SI — System and Information Integrity

| Control | Title | Implementation | Evidence |
|---------|-------|---------------|----------|
| SI-3 | Malicious Code Protection | Container image scanning in CI/CD pipeline. Runtime security monitoring. Signed image enforcement. | Scan results, runtime alerts |
| SI-4 | System Monitoring | Comprehensive monitoring: network flows, authentication events, API access, data access, configuration changes. | Monitoring dashboard, alert configuration |
| SI-5 | Security Alerts, Advisories, and Directives | Automated CVE tracking against asset inventory. Critical vulnerability patching within 7 days. | Vulnerability reports, patching records |
| SI-7 | Software, Firmware, and Information Integrity | File integrity monitoring on critical systems. Signed infrastructure-as-code deployments. Approved base image registry. | FIM alerts, deployment signatures |

---

## FedRAMP Authorization Boundary

This framework supports **FedRAMP High** baseline controls. The authorization boundary encompasses:

- All compute, storage, and network infrastructure in primary and DR data centers
- Identity provider and policy engine components
- Monitoring, logging, and SIEM infrastructure
- Management plane and automation tooling
- Encryption and key management systems

Components outside the authorization boundary:
- End-user devices (governed by agency endpoint management policy)
- Partner agency federated identity systems (governed by federation agreements)
- External DNS and CDN services (governed by service-level agreements)
