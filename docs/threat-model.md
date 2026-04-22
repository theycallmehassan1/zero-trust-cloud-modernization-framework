# Threat Model: Zero-Trust Federal Cloud Environment

## Methodology
STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) applied to each component of the zero-trust architecture.

---

## System Boundary

```
Trust Boundaries:
┌─────────────────────────────────────────────────────────────┐
│  TB-1: External Network Boundary                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  TB-2: DMZ / Web Tier                                  │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  TB-3: Application Tier                          │  │  │
│  │  │  ┌───────────────────────────────────────────┐  │  │  │
│  │  │  │  TB-4: Data Tier                           │  │  │  │
│  │  │  │  ┌─────────────────────────────────────┐  │  │  │  │
│  │  │  │  │  TB-5: Management Plane              │  │  │  │  │
│  │  │  │  └─────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## STRIDE Analysis by Component

### 1. API Gateway (TB-1 → TB-2)

| Threat | Category | Likelihood | Impact | Mitigation |
|--------|----------|------------|--------|------------|
| Forged authentication tokens | Spoofing | Medium | Critical | JWT signature verification with RS256, issuer validation, audience restriction |
| API parameter injection | Tampering | High | High | Input validation, parameterized queries, WAF rules for injection patterns |
| Unauthorized API access | Repudiation | Medium | High | Comprehensive API access logging with caller identity, request body hash |
| API response data leakage | Info Disclosure | Medium | Critical | Response filtering by caller authorization level, PII redaction |
| API endpoint exhaustion | DoS | High | High | Per-identity rate limiting (not per-IP), circuit breaker patterns |
| API key escalation | Elevation | Low | Critical | Scoped API keys with minimum permissions, automatic expiration |

### 2. Identity Provider (TB-1)

| Threat | Category | Likelihood | Impact | Mitigation |
|--------|----------|------------|--------|------------|
| Credential stuffing | Spoofing | High | Critical | MFA enforcement, account lockout (5 failures/15 min), credential breach detection |
| Session token theft | Spoofing | Medium | Critical | Short-lived tokens (4hr), binding to device fingerprint, secure cookie flags |
| MFA bypass techniques | Spoofing | Low | Critical | Phishing-resistant MFA (FIDO2/PIV), no SMS/email fallback |
| IdP service impersonation | Spoofing | Low | Critical | mTLS between IdP and all relying parties, certificate pinning |
| Account enumeration | Info Disclosure | Medium | Medium | Consistent error messages, rate-limited lookups, no username disclosure |

### 3. East-West Service Communication (TB-2 → TB-3 → TB-4)

| Threat | Category | Likelihood | Impact | Mitigation |
|--------|----------|------------|--------|------------|
| Service impersonation | Spoofing | Medium | Critical | mTLS with SPIFFE identity, certificate validation on every connection |
| Request payload tampering | Tampering | Medium | High | Message signing, mTLS integrity, input validation at each service |
| Lateral movement | Elevation | High | Critical | Microsegmentation, per-service security groups, anomaly detection on new connections |
| Internal data interception | Info Disclosure | Medium | Critical | mTLS on all east-west traffic, no plaintext internal communication |
| Service mesh bypass | Elevation | Low | Critical | Network policy denying non-mesh traffic, sidecar injection enforcement |
| Internal DDoS / noisy neighbor | DoS | Medium | High | Per-service resource quotas, circuit breakers, request rate limits |

### 4. Data Tier (TB-4)

| Threat | Category | Likelihood | Impact | Mitigation |
|--------|----------|------------|--------|------------|
| SQL injection via application | Tampering | Medium | Critical | Parameterized queries, WAF rules, database activity monitoring |
| Unauthorized data access | Info Disclosure | Medium | Critical | Row-level security, column-level encryption, access auditing |
| Backup data exposure | Info Disclosure | Medium | High | Encrypted backups (AES-256), access-controlled backup storage |
| Data exfiltration via authorized channel | Info Disclosure | Medium | Critical | DLP monitoring, anomalous query pattern detection, data transfer limits |
| Database privilege escalation | Elevation | Low | Critical | Dedicated service accounts per application, no shared admin credentials |
| Ransomware encryption | Tampering | Medium | Critical | Immutable backup copies, Ceph snapshot protection, offline backup validation |

### 5. Management Plane (TB-5)

| Threat | Category | Likelihood | Impact | Mitigation |
|--------|----------|------------|--------|------------|
| Hypervisor escape | Elevation | Low | Critical | Patching cadence <7 days for critical CVEs, minimal hypervisor attack surface |
| Management API compromise | Elevation | Low | Critical | Dedicated management network (VXLAN 4000), MFA + certificate auth for all API access |
| Configuration tampering | Tampering | Medium | Critical | Infrastructure as code, drift detection, approval workflow for all changes |
| Monitoring blind spot | Repudiation | Medium | High | Independent monitoring path, out-of-band log collection |
| Supply chain compromise (images) | Tampering | Medium | Critical | Signed images, vulnerability scanning in CI/CD, approved base image registry |

---

## Attack Scenarios

### Scenario 1: Advanced Persistent Threat — Lateral Movement

```
Phase 1: Initial Access
  Phishing email → Compromised workstation → Stolen session token
  
Phase 2: Reconnaissance  
  Internal network scanning → Identify service endpoints → Map trust relationships

Phase 3: Lateral Movement
  ✗ BLOCKED by microsegmentation — compromised workstation cannot reach data tier
  ✗ BLOCKED by identity — stolen token doesn't grant cross-segment access
  ✗ DETECTED by SIEM — unusual east-west traffic pattern triggers ZT-002 alert
  
Phase 4: Containment
  Automated response: revoke session, isolate workstation, alert SOC
  SOC triage within 5 minutes, full incident response within 4 hours
```

### Scenario 2: Insider Threat — Data Exfiltration

```
Phase 1: Authorized Access
  Legitimate user with database access → Normal query patterns established
  
Phase 2: Data Collection
  Increased query volume → Larger result sets → Data staging in user workspace

Phase 3: Exfiltration Attempt
  ✗ DETECTED by DLP — data transfer volume exceeds 95th percentile baseline
  ✗ DETECTED by SIEM — ZT-004 rule correlates sensitive data access + outbound transfer
  ✗ BLOCKED by network — egress filtering blocks unauthorized data transfer channels
  
Phase 4: Investigation
  Forensic timeline built from: auth logs + database audit + flow logs + DLP events
  Complete evidence chain assembled within 30 minutes
```

### Scenario 3: Supply Chain — Compromised Container Image

```
Phase 1: Image Compromise
  Malicious code injected into base image in upstream registry

Phase 2: Deployment
  ✗ BLOCKED by CI/CD — image signature verification fails (unsigned image)
  ✗ BLOCKED by scanner — vulnerability scan detects known malicious pattern
  ✗ BLOCKED by policy — only approved base images from internal registry allowed

Phase 3: If compromise reaches runtime (defense in depth)
  ✗ CONTAINED by microsegmentation — container can only reach explicitly allowed services
  ✗ DETECTED by runtime security — unexpected process execution triggers alert
  ✗ DETECTED by SIEM — container generates unusual network traffic pattern
```

---

## Risk Register Summary

| Risk ID | Threat | Residual Risk | Control Effectiveness |
|---------|--------|---------------|----------------------|
| R-001 | Credential compromise leading to lateral movement | Low | High (MFA + microsegmentation + detection) |
| R-002 | Data exfiltration by insider | Medium | Medium (DLP + monitoring, but authorized access is hard to distinguish) |
| R-003 | Supply chain compromise | Low | High (signed images + scanning + runtime security) |
| R-004 | Zero-day exploit in infrastructure | Medium | Medium (defense in depth limits blast radius, but initial compromise possible) |
| R-005 | DR failover security regression | Low | High (monthly validation, zero-trust controls replicated to DR) |
| R-006 | Configuration drift creating security gaps | Low | High (IaC + drift detection + automated remediation) |
| R-007 | Cryptographic key compromise | Low | High (HSM-backed, automated rotation, key hierarchy limits blast radius) |
