# ADR-003: Encryption Standards and Key Management

## Status
Accepted

## Date
2024-11-25

## Context

Federal systems handling CUI (Controlled Unclassified Information) must implement encryption that meets FIPS 140-2/140-3 validation requirements. The encryption architecture must cover data at rest, data in transit, and key lifecycle management across primary and DR sites.

## Decision

### Encryption Standards by Layer

| Layer | Algorithm | Mode | Key Length | Standard |
|-------|-----------|------|------------|----------|
| TLS (north-south) | AES | GCM | 256-bit | TLS 1.3 only (TLS 1.2 deprecated) |
| mTLS (east-west) | AES | GCM | 256-bit | SPIFFE-issued X.509 SVIDs |
| Block storage | AES | XTS | 256-bit | LUKS2 on Ceph OSDs |
| Object storage | AES | GCM | 256-bit | Server-side, customer-managed keys |
| Database (TDE) | AES | CBC | 256-bit | Transparent Data Encryption |
| Database (column) | AES | GCM | 256-bit | Application-level field encryption |
| Backup media | AES | CTR | 256-bit | GPG-encrypted backup streams |

### Key Management Architecture

```
┌─────────────────────────────────────────────────────┐
│                    HSM CLUSTER                       │
│              (FIPS 140-2 Level 3)                    │
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐      │
│  │  HSM #1   │  │  HSM #2   │  │  HSM #3   │      │
│  │ (Primary) │  │ (Primary) │  │ (DR Site) │      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
│        └───────────────┼───────────────┘             │
│                        │                             │
│              ┌─────────▼─────────┐                   │
│              │   Master Key      │                   │
│              │   (Never leaves   │                   │
│              │    HSM boundary)  │                   │
│              └─────────┬─────────┘                   │
│                        │                             │
│         ┌──────────────┼──────────────┐              │
│         │              │              │              │
│  ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐     │
│  │ Storage KEK │ │ DB KEK     │ │ Service KEK│     │
│  │ (rotate 90d)│ │ (rotate 90d│ │ (rotate 30d│     │
│  └──────┬──────┘ └─────┬──────┘ └────┬───────┘     │
│         │              │              │              │
│  ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐     │
│  │ Data DEKs   │ │ Column DEKs│ │ TLS Certs  │     │
│  │ (per-volume)│ │ (per-table)│ │ (per-svc)  │     │
│  └─────────────┘ └────────────┘ └────────────┘     │
└─────────────────────────────────────────────────────┘
```

### Key Rotation Schedule

| Key Type | Rotation Period | Method | Downtime |
|----------|----------------|--------|----------|
| Master key (HSM) | Annual | Ceremony with M-of-N quorum | None (HSM handles) |
| Key Encryption Keys | 90 days | Automated re-wrap of DEKs | None |
| Data Encryption Keys | On-demand | Re-encryption during maintenance | Rolling (per-volume) |
| TLS certificates | 90 days | Automated via internal CA | None (graceful reload) |
| SPIFFE SVIDs | 1 hour | Automatic rotation by SPIRE | None |
| Service API tokens | 24 hours | Automated refresh | None |

## Consequences

### Positive
- All data encrypted with FIPS-validated algorithms at every layer
- Key hierarchy limits blast radius — compromised DEK affects one volume, not all
- HSM cluster provides hardware-backed key protection meeting federal requirements
- Automated rotation eliminates manual key management errors

### Negative
- HSM cluster adds ~$200K to infrastructure cost
- Encryption overhead: 3–5% CPU for storage encryption, 1–2% for TLS
- DR site HSM requires secure key ceremony for initial synchronization
- Column-level encryption requires application code changes

## Lessons from On-Prem Cloud Deployments

1. **Key management is the hardest part of encryption.** The algorithms are straightforward. What fails is key rotation coordination across 200+ storage volumes, certificate expiry tracking across 500+ services, and ensuring the DR site HSM has current key material. We built automated key lifecycle management because manual processes broke within 3 months at scale.

2. **LUKS key caching prevents performance disasters.** Without dm-crypt key caching, every I/O operation hits the key management service. Under load (>10K IOPS), this adds 15ms latency. Caching the DEK in kernel memory after initial unlock reduced this to <0.1ms.

3. **Test DR key availability quarterly.** On two occasions, DR site HSMs had stale key material because the replication link failed silently. The DR failover test caught this — production data would have been inaccessible at the DR site without the correct KEKs.
