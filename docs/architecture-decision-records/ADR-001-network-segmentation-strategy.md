# ADR-001: Network Segmentation Strategy

## Status
Accepted

## Date
2024-11-15

## Context

Federal data center environments typically operate on flat network architectures where all systems share the same broadcast domain. Once an attacker breaches the perimeter, lateral movement is essentially unrestricted. The federal agency requires a segmentation strategy that:

1. Isolates workloads by trust level and data classification
2. Controls both north-south (ingress/egress) and east-west (internal) traffic
3. Scales across multiple availability zones and DR sites
4. Supports legacy applications that cannot be immediately refactored
5. Aligns with NIST SP 800-207 zero-trust principles

## Decision

We will implement a **three-layer segmentation architecture**:

### Layer 1: VXLAN-Based Network Isolation

Each trust zone receives a dedicated VXLAN segment (VNI), providing Layer 2 isolation over shared physical infrastructure. This approach was validated in our multi-tenant private cloud deployments where tenants with different security requirements shared the same physical compute and network hardware.

**VXLAN allocation scheme:**

| VNI Range | Purpose | Example |
|-----------|---------|---------|
| 1000–1099 | Web tier (DMZ) | Public-facing services |
| 2000–2099 | Application tier | Internal microservices |
| 3000–3099 | Data tier | Databases, object storage |
| 4000–4099 | Management plane | Hypervisors, controllers, monitoring |
| 5000–5099 | DR replication | Cross-site replication traffic |
| 9000–9099 | Out-of-band management | IPMI, console access |

### Layer 2: Distributed Virtual Firewall (Security Groups)

Security groups applied at the hypervisor level (OVS/OVN) provide stateful, per-workload firewall rules. Critical design rules:

- **Default deny** — no traffic allowed unless explicitly permitted
- **Reference by identity, not IP** — security group rules reference group IDs or service identity labels, not CIDR blocks
- **Propagation SLA** — rule changes must propagate to all compute hosts within 30 seconds
- **Logging** — all denied packets logged to SIEM with source/destination metadata

### Layer 3: Application-Level Segmentation

Service mesh (Istio) provides mTLS between all services, with authorization policies enforced at the sidecar proxy level. API gateway enforces request-level authorization before traffic reaches the service mesh.

## Consequences

### Positive
- Lateral movement contained to the compromised segment
- Full visibility into east-west traffic patterns
- Security group identity-based rules survive failover and auto-scaling events
- Compliance with NIST 800-53 SC-7 (Boundary Protection) and AC-4 (Information Flow Enforcement)

### Negative
- Increased network complexity and operational overhead
- VXLAN encapsulation adds 50 bytes of overhead per packet (MTU adjustment required)
- Security group rule management requires dedicated tooling at scale (>500 rules)
- Legacy applications that hardcode IP addresses require compensating controls

### Risks
- Misconfigured security groups can cause production outages — mitigated by change management process and automated validation
- VXLAN flooding in large segments — mitigated by limiting segment size to <500 endpoints
- Performance impact of distributed firewall — mitigated by kernel-level datapath (OVS DPDK)

## Lessons from On-Prem Cloud Deployments

During multi-tenant private cloud deployments, we learned:

1. **Security groups that reference IP addresses break during failover.** When VMs migrated between compute hosts during maintenance or DR events, IP-based rules would temporarily deny legitimate traffic. Switching to identity-based references eliminated this class of incidents entirely.

2. **Default-allow is a debt that compounds.** Several tenants initially requested default-allow security groups for "ease of development." Within 6 months, the implicit allow rules had grown to the point where no one could identify which connections were intentional. Starting with default-deny and explicit allow rules was more work upfront but saved significant incident response time.

3. **VXLAN segment size matters.** Segments with >1000 endpoints generated enough BUM (broadcast, unknown unicast, multicast) traffic to impact performance. We established a soft limit of 500 endpoints per segment, with monitoring alerts at 80% capacity.
