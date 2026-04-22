# ADR-002: Identity Provider Selection and Architecture

## Status
Accepted

## Date
2024-11-20

## Context

The zero-trust model requires that every access request is authenticated, authorized, and encrypted regardless of origin. The federal agency needs an identity architecture that:

1. Supports human users (employees, contractors) and machine identities (services, APIs)
2. Integrates with existing PIV/CAC smart card infrastructure
3. Provides context-aware access decisions (device posture, location, behavior)
4. Meets FIPS 140-2 requirements for cryptographic modules
5. Supports federation with partner agencies
6. Scales to 50,000+ identities with sub-second authentication latency

## Decision

We will implement a **three-tier identity architecture**:

### Tier 1: Primary Identity Provider
Centralized IdP handling all human authentication with:
- PIV/CAC certificate-based primary authentication
- FIDO2 hardware tokens as secondary factor
- Conditional access policies based on device compliance and network location
- Session tokens with 4-hour maximum lifetime and continuous re-evaluation

### Tier 2: Machine Identity (SPIFFE/SPIRE)
Workload identity framework providing:
- Cryptographic identity (SVID) for every service/container
- Automatic certificate issuance and rotation (1-hour validity)
- Attestation based on kernel, container runtime, and orchestrator metadata
- No shared secrets — every workload proves its identity through attestation chain

### Tier 3: API Gateway Identity
Request-level authentication at the API boundary:
- OAuth 2.0 + PKCE for user-delegated API access
- mTLS client certificates for service-to-service API calls
- JWT validation with issuer verification and audience restriction
- Rate limiting per identity (not per IP) to prevent credential abuse

### Trust Score Engine

```
Trust Score = w1(identity_strength) + w2(device_posture) + 
             w3(network_context) + w4(behavioral_baseline) + 
             w5(data_sensitivity) + w6(time_context)

Where:
  identity_strength  = PIV cert (1.0) | FIDO2 (0.9) | MFA app (0.7) | Password only (0.3)
  device_posture     = Managed + compliant (1.0) | Managed (0.7) | BYOD (0.4) | Unknown (0.1)
  network_context    = On-premises (1.0) | Agency VPN (0.8) | Trusted partner (0.6) | Public (0.3)
  behavioral_baseline = Normal patterns (1.0) | Minor deviation (0.7) | Significant anomaly (0.3)
  data_sensitivity   = Public (1.0) | CUI (0.7) | Classified-adjacent (0.4)
  time_context       = Business hours (1.0) | Extended hours (0.8) | Off-hours (0.5)

Weights: w1=0.25, w2=0.20, w3=0.15, w4=0.20, w5=0.10, w6=0.10

Decision thresholds:
  Score ≥ 0.80 → Full access granted
  Score 0.50–0.79 → Limited access + step-up authentication prompt
  Score < 0.50 → Deny access + generate SOC alert
```

## Consequences

### Positive
- Every access decision is context-aware and risk-scored
- Machine identities eliminate shared credentials and API key sprawl
- PIV/CAC integration leverages existing federal PKI investment
- Sub-second authentication latency through local policy caching

### Negative
- SPIFFE/SPIRE deployment requires kernel-level attestation plugins per platform
- Trust score tuning requires 30–60 days of baseline behavioral data
- Legacy applications without OAuth/SAML support need reverse proxy shims
- Increased operational complexity in identity provider HA configuration

## Lessons from On-Prem Cloud Deployments

1. **API key sprawl is the silent killer.** In multi-tenant cloud environments, we found that shared API keys proliferated across development and production environments. One compromised key could access resources across multiple tenants. SPIFFE-based workload identity eliminated this entire class of vulnerability.

2. **Service account governance requires automation.** Manual service account management at scale (500+ services) led to orphaned accounts with excessive privileges. Automated lifecycle management — create on deploy, rotate hourly, revoke on decommission — reduced the attack surface measurably.

3. **Authentication latency kills adoption.** Early identity provider deployments added 800ms per request. Development teams bypassed the IdP with hardcoded credentials "for performance." Reducing latency to <50ms through local policy caching was essential for organizational adoption.
