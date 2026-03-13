# The Triple Jump — Cross-Cloud Attack Chain Taxonomy

**Author:** Vyugard Systems  
**Date:** March 2026  
**Protocol:** v-19 1.0

---

## Abstract

A **Triple Jump** is an attack chain in which a compromised identity traverses three or more cloud provider boundaries through a sequence of identity bridges. This document defines the mathematical model, bridge taxonomy, and detection methodology used by the v-19 protocol.

---

## 1. Definitions

### 1.1 Identity Graph

A multi-cloud environment is modelled as a directed graph G = (V, E), where:

- **V** (vertices): IAM principals across all cloud providers
- **E** (edges): Trust relationships ("bridges") between principals

An **identity** $v \in V$ belongs to exactly one cloud domain $d \in \{AWS, Azure, GCP, K8s\}$.

A **bridge** $e = (v_i, v_j)$ exists when identity $v_i$ in domain $d_a$ can authenticate as or escalate to identity $v_j$ in domain $d_b$, where $d_a \neq d_b$.

### 1.2 Jump

A **jump** is a single bridge traversal from one cloud domain to another:

```
  Jump: v_i ──bridge──▶ v_j
        (domain A)       (domain B)
```

### 1.3 Triple Jump

A **Triple Jump** is a path P = (v₁, v₂, v₃, ..., vₙ) where n ≥ 4 and the path crosses at least three distinct cloud domains:

$$|\\{domain(v) : v \in P\\}| \geq 3$$

The canonical Triple Jump crosses exactly three domains:

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    THE TRIPLE JUMP                          │
  │                                                             │
  │  AWS                   Azure                  GCP           │
  │  ┌──────────┐         ┌──────────┐          ┌──────────┐   │
  │  │ IAM Role │──OIDC──▶│ AD App   │──Fed────▶│ Svc Acct │   │
  │  │ (Compromised)│     │ Principal│          │ (Data)   │   │
  │  └──────────┘         └──────────┘          └──────────┘   │
  │       ▲                                          │          │
  │       │                                          ▼          │
  │   Attacker                              Data Exfiltration   │
  └─────────────────────────────────────────────────────────────┘
```

---

## 2. Bridge Taxonomy

v-19 classifies six categories of cross-cloud identity bridges:

### 2.1 OIDC Federation

```
  AWS IAM Role ──trust policy──▶ Azure AD Application
  
  Mechanism: The AWS role's trust policy accepts tokens from
  Azure AD's OIDC issuer endpoint. Any Azure AD principal
  with the correct audience claim can assume the AWS role.
```

**Detection signal:** `AssumeRoleWithWebIdentity` trust policy with `sts.windows.net` or `login.microsoftonline.com` issuer.

### 2.2 Workload Identity Binding

```
  GCP Service Account ──annotation──▶ Kubernetes Pod
  
  Mechanism: GKE Workload Identity binds a GCP service account
  to a Kubernetes service account. Any pod using that KSA
  receives GCP credentials automatically.
```

**Detection signal:** `iam.gke.io/gcp-service-account` annotation on Kubernetes service account.

### 2.3 Federated Credential

```
  Azure Managed Identity ──federated credential──▶ External IdP
  
  Mechanism: Azure AD accepts tokens from an external IdP
  (AWS STS, GCP, GitHub Actions) as proof of identity for
  a managed identity or app registration.
```

**Detection signal:** `federatedIdentityCredentials` on Azure AD application with external `issuer`.

### 2.4 Cross-Account Role Assumption

```
  AWS Account A ──AssumeRole──▶ AWS Account B
  
  Mechanism: A role in Account B trusts principals from
  Account A. While same-provider, this is a domain boundary
  crossing relevant to Bridge chains.
```

**Detection signal:** `sts:AssumeRole` trust policy with external account ID.

### 2.5 Service Account Key Export

```
  GCP Service Account ──exported key──▶ External System
  
  Mechanism: A JSON key file for a GCP SA can be used from
  any network location. If stored in AWS S3 or Azure Blob,
  it creates an implicit bridge.
```

**Detection signal:** `iam.serviceAccountKeys.list()` returns user-managed keys.

### 2.6 Kubernetes OIDC Projection

```
  Kubernetes Service Account ──projected token──▶ AWS/Azure/GCP
  
  Mechanism: Projected service account tokens with custom
  audiences can be exchanged for cloud provider credentials
  via OIDC federation.
```

**Detection signal:** Pod spec with `projected` volume source and custom `audience`.

---

## 3. Triple Jump Scenarios

### 3.1 The Classic Triple Jump

```
  SCENARIO: "K8s → Azure → AWS"
  
  Step 1: Attacker compromises Kubernetes pod running with
          a service account bound to Azure Managed Identity
          
  Step 2: Azure Managed Identity has federated credential
          trusting AWS STS tokens → attacker assumes AWS role
          
  Step 3: AWS role has S3 access to data lake
  
  ┌─────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
  │ K8s Pod  │────▶│Azure MI  │────▶│AWS Role  │────▶│ S3 Data │
  │(pwned)   │     │(bridge 1)│     │(bridge 2)│     │  Lake   │
  └─────────┘     └──────────┘     └──────────┘     └─────────┘
       │                                                  │
       └──────── 3 DOMAINS CROSSED ───────────────────────┘
```

### 3.2 The Reverse Jump

```
  SCENARIO: "AWS → GCP → K8s"
  
  Step 1: Compromised AWS role with OIDC trust to GCP
  Step 2: GCP service account bound to GKE Workload Identity
  Step 3: K8s service account has cluster-admin binding
  
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │ AWS Role │────▶│ GCP SA   │────▶│ K8s SA   │
  │(stolen   │     │(Workload │     │(cluster  │
  │ creds)   │     │ Identity)│     │ admin)   │
  └──────────┘     └──────────┘     └──────────┘
```

### 3.3 The Corporate Scenario (R196.7M Exposure)

```
  SCENARIO: "Financial Services — 4-Domain Jump"
  
  Entry:   Compromised CI/CD service account in GCP
  Jump 1:  GCP SA → Kubernetes cluster via Workload Identity
  Jump 2:  K8s admin → Azure AD via projected OIDC token
  Jump 3:  Azure AD → AWS via federated credential
  Terminal: AWS production account with PII data stores
  
  ┌──────────┐   ┌─────────┐   ┌──────────┐   ┌────────────┐
  │ GCP CI/CD│──▶│ K8s     │──▶│ Azure AD │──▶│ AWS Prod   │
  │ SA       │   │ Admin   │   │ SP       │   │ (PII Data) │
  └──────────┘   └─────────┘   └──────────┘   └────────────┘
       │                                             │
       │         4 DOMAINS — R196.7M AT RISK         │
       └─────────────────────────────────────────────┘
  
  Exposure Calculation:
    PII records at risk:     2.4M customers
    POPIA fine (max):        R10M
    Breach notification:     R3.2M  
    Business interruption:   R48M
    Reputational (est):      R135.5M
    ─────────────────────────────────
    Total exposure:          R196.7M
```

---

## 4. Detection Methodology

### 4.1 Bridge Detection (Phase 3 — Free Tier)

The free tier identifies bridges by scanning trust policies, federation configurations, and workload bindings. Output is limited to:

- **Count:** Total number of bridges detected
- **Cloud pairs:** Which domains are connected (e.g., `aws → azure: 3`)

### 4.2 Chain Construction (Phase 4 — Enterprise)

The Enterprise engine constructs the full identity graph and applies depth-first traversal to identify all paths P where $|domains(P)| \geq 3$.

Each chain is scored by:

$$risk(P) = \sum_{i=1}^{n} severity(v_i) \times \prod_{j=1}^{|bridges|} exploitability(e_j)$$

Where:
- $severity(v_i)$ is the CRITICAL/HIGH/MEDIUM/LOW score of each identity in the chain
- $exploitability(e_j)$ is the difficulty factor of traversing each bridge (0.0–1.0)

### 4.3 Financial Quantification (Phase 5 — Enterprise)

Blast radius is calculated by mapping terminal identities to accessible data stores, compute resources, and compliance-regulated assets.

---

## 5. Why Existing Tools Miss This

| Tool Category | What It Sees | What It Misses |
|--------------|-------------|----------------|
| AWS Security Hub | AWS IAM misconfigurations | Azure/GCP bridges from those identities |
| Azure Defender | Azure AD risky sign-ins | GCP service accounts federated to Azure |
| GCP SCC | GCP SA key exposure | K8s pods using those SAs via Workload Identity |
| Kubernetes Falco | Runtime anomalies in pods | The cloud credentials those pods carry |

**v-19 sees the bridges between all of them.**

---

*Vyugard Systems — Sovereign Multi-Cloud Risk Quantification*
