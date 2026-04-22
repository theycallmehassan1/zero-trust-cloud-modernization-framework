# ADR-005: Centralized Logging and Monitoring Architecture

## Status
Accepted

## Date
2024-12-05

## Context

Zero-trust architecture requires comprehensive visibility into all access requests, data flows, and system events. The logging architecture must support real-time threat detection, forensic investigation, and compliance evidence collection while operating across primary and DR sites.

## Decision

### Log Collection Architecture

```
Data Sources                    Collection         Processing          Storage & Analysis
─────────────                   ──────────         ──────────          ──────────────────
VPC flow logs ──────────┐
Security group logs ────┤
DNS query logs ─────────┤       ┌──────────┐      ┌──────────┐       ┌──────────────┐
API gateway logs ───────┼──────▶│  Log      │─────▶│  Stream   │──────▶│  SIEM        │
Auth/IdP events ────────┤       │  Agents   │      │  Processor│       │  (Wazuh +    │
Hypervisor audit ───────┤       │  (Fluent  │      │  (Kafka)  │       │   Elastic)   │
Storage access logs ────┤       │   Bit)    │      │           │       │              │
Application logs ───────┤       └──────────┘      └──────────┘       │  Hot: 30 days│
Container runtime ──────┤                                             │  Warm: 90 days│
Certificate events ─────┘                                             │  Cold: 7 years│
                                                                      └──────────────┘
```

### Log Categories and Retention

| Category | Sources | Volume (est.) | Retention | Compliance Driver |
|----------|---------|---------------|-----------|-------------------|
| Authentication | IdP, MFA, PIV/CAC | ~50 GB/day | 7 years | NIST AU-3, IA-2 |
| Authorization | Policy engine, RBAC decisions | ~30 GB/day | 7 years | NIST AC-2, AC-6 |
| Network flow | VPC flow logs, DVF logs | ~200 GB/day | 1 year | NIST SC-7, SI-4 |
| API access | Gateway, service mesh | ~80 GB/day | 3 years | NIST AC-4, AU-12 |
| Data access | Database audit, object store | ~40 GB/day | 7 years | NIST AU-12, SC-28 |
| System events | OS audit, hypervisor | ~60 GB/day | 1 year | NIST CM-3, SI-7 |
| Certificate lifecycle | CA, SPIRE, TLS events | ~5 GB/day | 3 years | NIST IA-5, SC-12 |
| Change management | IaC deploys, config changes | ~10 GB/day | 7 years | NIST CM-3, CM-6 |

### Correlation Rules (High Priority)

| Rule ID | Name | Data Sources | Logic | Severity |
|---------|------|-------------|-------|----------|
| ZT-001 | Impossible travel | Auth logs + geo-IP | Same identity authenticates from locations >500 miles apart within 30 minutes | Critical |
| ZT-002 | Lateral movement | Flow logs + auth | New east-west communication path + failed auth attempts on target | Critical |
| ZT-003 | Privilege escalation | IAM events | Role assumption from non-whitelisted source + admin API calls | Critical |
| ZT-004 | Data exfiltration | Flow logs + DLP | Outbound data transfer >95th percentile + sensitive data access | Critical |
| ZT-005 | Service account abuse | Auth logs | Service account used from interactive session or unusual source | High |
| ZT-006 | Certificate anomaly | CA logs | Certificate issued outside automated pipeline or with unusual SANs | High |
| ZT-007 | Config drift | CM logs + baseline | Security group, encryption, or access control settings diverge from IaC | Medium |
| ZT-008 | DNS tunneling | DNS logs | High-entropy subdomain queries >100/minute to single domain | High |

### Alert Response SLAs

| Severity | Initial Triage | Escalation | Resolution Target |
|----------|---------------|------------|-------------------|
| Critical | 5 minutes | CISO within 15 minutes | 4 hours |
| High | 15 minutes | SOC Lead within 30 minutes | 8 hours |
| Medium | 1 hour | Next business day review | 5 business days |
| Low | 4 hours | Weekly SOC review | 30 days |

## Consequences

### Positive
- Complete visibility into all zero-trust decision points
- Forensic capability to trace any access request across the entire stack within 5 minutes
- Compliance evidence generated automatically as a byproduct of operations
- Correlation rules detect multi-stage attacks that individual log sources miss

### Negative
- ~475 GB/day log volume requires significant storage infrastructure
- Kafka cluster adds operational complexity and requires dedicated operations staff
- 7-year retention for audit logs requires cost-effective cold storage tier
- False positive tuning requires 60–90 days of baseline data collection

## Lessons from On-Prem Cloud Deployments

1. **Centralized logging is non-negotiable for zero-trust.** Without centralized log aggregation, security teams cannot correlate events across the stack. In our private cloud deployments, we saw incidents where a compromised API key was used from three different network segments simultaneously — a pattern only visible when API logs, network flow logs, and authentication events were correlated in a single SIEM.

2. **Log pipeline reliability matters more than log analysis sophistication.** We invested heavily in advanced correlation rules, but the highest-impact improvement was making the log pipeline itself reliable — ensuring that FluentBit agents survived host reboots, that Kafka partitions rebalanced gracefully, and that no log events were dropped during peak load. A simple rule on complete data catches more incidents than a complex rule on partial data.

3. **The 5-minute trace test.** We established a benchmark: any SOC analyst should be able to trace a suspicious event from the initial alert through the identity provider, across the network fabric, to the target resource, and back — in under 5 minutes using the SIEM. If this takes longer, the logging architecture has a gap. This benchmark directly translates to federal SOC requirements.
