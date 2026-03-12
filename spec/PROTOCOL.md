# The v-19 Protocol

## Version 1.0 — March 2026

### Abstract

The v-19 protocol defines a standardized methodology for detecting, classifying, and responding to cross-cloud identity risks in environments spanning AWS, Azure, GCP, and Kubernetes.

This specification covers:
- Identity enumeration across four cloud providers
- Risk classification into severity buckets (CRITICAL / HIGH / MEDIUM / LOW)
- Cross-cloud bridge detection between federated identity boundaries
- The "Triple Jump" attack chain taxonomy

---

### 1. Definitions

**Identity**: Any IAM principal — user, role, service account, managed identity, or Kubernetes service account — that can authenticate to a cloud API.

**Bridge**: A trust relationship that allows an identity in one cloud provider to assume or access resources in another cloud provider. Examples: OIDC federation, workload identity binding, federated credentials, cross-account role assumption.

**Triple Jump**: An attack chain where a compromised identity traverses three or more cloud provider boundaries through a sequence of bridges.

**Scan Phase**: One of six sequential stages in the v-19 protocol execution.

---

### 2. Protocol Phases

| Phase | Name | Scope | License |
|-------|------|-------|---------|
| 1 | ENUMERATE | List all identities per cloud | Free |
| 2 | CLASSIFY | Assign severity by permissions and configuration | Free |
| 3 | CORRELATE | Detect bridges between clouds | Free (counts only) |
| 4 | CHAIN | Build multi-hop attack paths | Enterprise |
| 5 | QUANTIFY | Calculate financial exposure | Enterprise |
| 6 | REMEDIATE | Generate fix code and compliance reports | Enterprise |

---

### 3. Severity Classification

| Level | Criteria |
|-------|----------|
| CRITICAL | Admin-level access with no MFA, cluster-admin bindings, cross-cloud bridges to production |
| HIGH | Broad role assumptions, federated credentials, owner/contributor access |
| MEDIUM | Token automounting with roles, edit-level bindings, stale service accounts |
| LOW | View-only access, default service accounts with no meaningful bindings |

---

### 4. Bridge Types

| Type | Mechanism | Providers |
|------|-----------|-----------|
| OIDC Federation | Service account token trusted by external IdP | K8s → AWS/Azure/GCP |
| Workload Identity | Pod-bound identity mapped to cloud principal | K8s → GCP/Azure |
| Credential Federation | Federated credential on managed identity | Azure → AWS/GCP |
| Role Chaining | AssumeRole across accounts | AWS → AWS |
| Domain-Wide Delegation | Service account impersonates workspace users | GCP → Google Workspace |

---

### 5. Execution Time Target

The v-19 protocol targets **sub-20ms** execution for phases 1–3 (ENUMERATE + CLASSIFY + CORRELATE) on a standard dataset of 100–200 identities.

This excludes:
- Cloud API network latency
- Credential resolution
- Output rendering

The 19ms benchmark measures engine logic only — the intelligence layer, not the transport layer.

---

### 6. Output Format

Findings are returned as structured records:

```json
{
  "finding_id": "AWS-001",
  "title": "Admin user with no MFA",
  "risk_level": "CRITICAL",
  "cloud": "aws",
  "identity_name": "admin-user",
  "reason": "Console access with administrator policy and no MFA device",
  "is_cross_cloud": false
}
```

Bridge summaries are returned as counts:

```json
{
  "total_bridges": 3,
  "cloud_pairs": ["aws -> azure", "azure -> gcp"]
}
```

Full attack path details (identity names, hop sequences, scoring) are available in Enterprise.

---

### References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Azure Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

---

*Vyugard Systems — Sovereign Multi-Cloud Risk Quantification*
