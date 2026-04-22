# ADR-004: Disaster Recovery Replication Strategy

## Status
Accepted

## Date
2024-12-01

## Context

The federal agency requires disaster recovery capabilities across geographically separated data centers (minimum 100 miles apart per NIST guidelines). The DR architecture must support tiered RPO/RTO objectives based on data criticality while maintaining zero-trust controls during and after failover.

## Decision

### Three-Tier Replication Architecture

**Tier 1 — Synchronous (Mission-Critical)**
- PostgreSQL streaming replication with synchronous commit
- RPO = 0 (zero data loss), RTO < 5 minutes
- Applies to: authentication databases, authorization policy stores, audit logs
- Trade-off: write latency increases by ~2ms per cross-site round trip

**Tier 2 — Asynchronous (Business-Important)**
- Ceph RBD mirroring with journal-based async replication
- RPO < 15 minutes, RTO < 30 minutes
- Applies to: application databases, user data, configuration stores
- Trade-off: potential data loss of up to 15 minutes during unplanned failover

**Tier 3 — Snapshot-Based (Standard)**
- Ceph RGW multi-site replication for object storage
- RPO < 1 hour, RTO < 2 hours
- Applies to: backups, logs, static content, non-critical data
- Trade-off: higher data loss tolerance balanced against lower infrastructure cost

### Failover Decision Matrix

```
Trigger Event                    Automatic?   Approval Required?
─────────────────────────────────────────────────────────────────
Primary DC total loss            Yes          Post-incident notification
Network partition > 15 min       No           CAB emergency approval
Storage cluster degraded (>30%)  No           CAB emergency approval  
Compute capacity < 20%           No           Scheduled maintenance window
Planned maintenance              No           Standard change request
DR test (monthly)                Yes          Pre-approved quarterly
```

### Zero-Trust Continuity During Failover

Critical requirement: zero-trust controls must remain active during failover. This means:

1. **Identity provider** — Active-active across both sites with session token portability
2. **Policy engine** — Policy cache on DR site refreshed every 60 seconds
3. **Certificate authority** — DR site CA can issue certificates independently if primary is unreachable
4. **SIEM** — Log ingestion continues at DR site; alert rules pre-loaded and validated monthly
5. **Security groups** — Replicated via infrastructure-as-code, validated during DR tests

## Consequences

### Positive
- Tiered approach optimizes cost vs. data protection requirements
- Zero-trust controls survive failover — no security regression during incidents
- Monthly automated validation catches drift and configuration issues proactively

### Negative
- Synchronous replication adds write latency on Tier 1 workloads
- Two-site HSM key synchronization adds operational complexity
- DR tests require coordination across application teams (4-hour window monthly)

## Lessons from On-Prem Cloud Deployments

1. **DR testing reveals what architecture diagrams hide.** In every DR test we conducted, we found at least two undocumented dependencies — hardcoded IP addresses in application configs, database connection strings pointing to primary-only endpoints, or DNS records with TTLs too long for acceptable failover times. Federal agencies should treat DR tests as the single most valuable audit of their architecture.

2. **Certificate and credential issues are the #1 cause of DR failures.** On three separate occasions, failover to the DR site succeeded at the infrastructure level but failed at the application level because TLS certificates on standby nodes had expired, service account passwords had been rotated on primary but not replicated, or the DR site's local CA certificate chain was incomplete.

3. **Automated validation must cover the full stack.** Our initial DR tests only validated infrastructure-level connectivity. Application-level health checks, data consistency verification, and monitoring continuity checks were added after incidents where the DR site was "up" but not actually functional for end users.
