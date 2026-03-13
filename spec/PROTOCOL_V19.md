# The v-19 Protocol — Version 1.0

**Author:** Vyugard Systems  
**Date:** March 2026  
**Status:** Stable

---

## Abstract

The v-19 protocol defines a deterministic, six-phase methodology for detecting cross-cloud identity risk in federated environments spanning AWS, Azure, GCP, and Kubernetes. The protocol is named for its latency constraint: every scan phase must complete in ≤19ms per cloud domain.

This document specifies the technical constraints, scan phases, and latency guarantees that constitute the v-19 standard.

---

## 1. Design Principles

### 1.1 Memory-Resident Scanning

All identity enumeration and classification occurs in-memory. No scan data is written to disk during execution. Credentials are held in transient sessions that are discarded after each scan phase.

```
┌──────────────────────────────────────────────────────┐
│                   v-19 RUNTIME                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ AWS Session│ │Azure Sess│  │GCP Sess  │  Transient│
│  │  (STS)    │ │ (MSAL)   │  │ (OAuth)  │  Sessions │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘           │
│        │              │              │                │
│        ▼              ▼              ▼                │
│  ┌──────────────────────────────────────────┐        │
│  │       IN-MEMORY IDENTITY GRAPH           │        │
│  │  (discarded after scan completes)        │        │
│  └──────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────┘
```

### 1.2 The 19ms Constraint

Each cloud domain scan must complete within 19 milliseconds. This constraint is achieved through:

| Technique | Description |
|-----------|-------------|
| **Batch API calls** | Single list call per resource type (roles, users, SAs) |
| **Parallel enumeration** | All four cloud scans run concurrently |
| **Zero-copy classification** | Risk scoring applied during enumeration, not as a second pass |
| **No disk I/O** | Results held in memory until explicit export |

**Total scan budget:** 4 clouds × 19ms = 76ms max. Typical observed: **<19ms** for a 200-identity environment.

### 1.3 Transient Sessions

v-19 never stores credentials. Each scan creates short-lived sessions using the platform's native credential chain:

| Cloud | Credential Source | Session Lifetime |
|-------|-------------------|------------------|
| AWS | STS `AssumeRole` / env vars / `~/.aws/credentials` | Scan duration only |
| Azure | MSAL / `az login` / managed identity | Scan duration only |
| GCP | Application Default Credentials / service account JSON | Scan duration only |
| Kubernetes | kubeconfig / in-cluster service account | Scan duration only |

---

## 2. Protocol Phases

The v-19 protocol executes six sequential phases. Phases 1–3 are available in the open-source release. Phases 4–6 require an Enterprise license.

```
Phase 1       Phase 2       Phase 3       Phase 4       Phase 5       Phase 6
ENUMERATE ──▶ CLASSIFY ──▶ CORRELATE ──▶ CHAIN ──▶ QUANTIFY ──▶ REMEDIATE
   │              │              │           │           │            │
   │  Free ───────┼──────────────┤           │           │            │
   │              │              │           │           │            │
   │              │              │  Enterprise ──────────┼────────────┤
```

### Phase 1: ENUMERATE

List all IAM principals across configured clouds.

- **AWS:** `iam.list_users()`, `iam.list_roles()`, `sts.get_caller_identity()`
- **Azure:** `GraphServiceClient.users.list()`, `authorization.role_assignments.list()`
- **GCP:** `iam.projects.serviceAccounts.list()`
- **Kubernetes:** `v1.list_service_account_for_all_namespaces()`

**Output:** Array of identity objects with cloud, name, type, permissions.

### Phase 2: CLASSIFY

Assign a severity level to each identity based on its permissions configuation:

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Admin/Owner with no MFA, cluster-admin, cross-cloud federation to production |
| **HIGH** | Broad role assumptions, federated credentials, contributor access |
| **MEDIUM** | Token automounting, edit-level bindings, stale >90-day service accounts |
| **LOW** | View-only, default service accounts with no bindings |

### Phase 3: CORRELATE

Detect cross-cloud bridges — trust relationships that allow an identity in one cloud to authenticate in another.

**Bridge types detected:**

| Bridge Type | Source | Target |
|-------------|--------|--------|
| OIDC Federation | AWS IAM Role | Azure AD App Registration |
| Workload Identity | GCP Service Account | Kubernetes Pod |
| Federated Credential | Azure Managed Identity | AWS IAM Role |
| Cross-Account Assumption | AWS Account A | AWS Account B |
| Service Account Key Binding | GCP SA | External System |

**Free tier output:** Bridge count + cloud pairs (e.g., `aws → azure: 3`).  
**Enterprise output:** Full per-identity chain with traversal paths.

### Phase 4: CHAIN (Enterprise)

Build multi-hop attack paths by linking Phase 3 bridges into directed graphs. Identifies Triple Jumps — attack chains that cross three or more cloud provider boundaries.

### Phase 5: QUANTIFY (Enterprise)

Calculate financial exposure in ZAR/USD for each attack path based on blast radius — the data, compute, and compliance assets reachable from a compromised identity.

### Phase 6: REMEDIATE (Enterprise)

Generate provider-specific fix code (Terraform, ARM, gcloud CLI) and compliance reports (POPIA, CIS, SOC2).

---

## 3. Latency Benchmarks

Measured on a standard 4-core VM with residential internet:

| Environment | Identities | Clouds | Scan Time |
|------------|-----------|--------|-----------|
| Startup (10 IAM users) | 10 | 1 | 2ms |
| Mid-market (50 identities) | 50 | 2 | 8ms |
| Enterprise (200 identities) | 200 | 4 | 17ms |
| Large enterprise (500+) | 500 | 4 | 34ms |

The 19ms target is met for environments up to ~250 identities across all four clouds. Larger environments scale linearly.

---

## 4. Security Model

- **No credential persistence** — sessions discarded after scan
- **Read-only API access** — v-19 never modifies cloud resources
- **No telemetry** — no data leaves the machine unless explicitly exported
- **No network calls** except to configured cloud provider APIs

---

## 5. Versioning

The v-19 protocol follows semantic versioning. The protocol version is independent of the scanner software version. Protocol changes that alter scan behavior increment the major version.

| Protocol Version | Scanner Version | Date |
|-----------------|-----------------|------|
| 1.0 | 1.0.0 | March 2026 |

---

*Vyugard Systems — Sovereign Multi-Cloud Risk Quantification*
