# v-19 | The Vyugard Standard

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Sovereign](https://img.shields.io/badge/Protocol-v--19-black)](https://vyugard.tech)
[![Speed](https://img.shields.io/badge/Latency-19ms-green)](https://vyugard.tech)

**v-19** is a high-velocity, multi-cloud sovereignty engine. It is designed to quantify and visualize the "Triple Jump" attack chains that exist between fragmented cloud domains.

In a world of perimeter-less infrastructure, **v-19** provides the definitive view of your digital borders in **19ms**.

---

## The Triple Jump Problem

Current security tools audit clouds in isolation. **v-19** audits the **Identity Bridges** between them.

A "Triple Jump" occurs when a compromised identity in **AWS** leads to lateral movement in **Azure**, finally terminating in a **GCP** data exfiltration point. v-19 identifies these bridges before they are crossed.

```
  AWS IAM Role ──OIDC──▶ Azure AD SP ──Federation──▶ GCP Service Account
       ▲                                                      │
       │              THE TRIPLE JUMP                         ▼
   Compromised                                        Data Exfiltration
```

---

## What You Get (Free — Apache 2.0)

- **Multi-cloud scanning** — AWS IAM, Azure AD, GCP service accounts, Kubernetes RBAC
- **Risk classification** — CRITICAL / HIGH / MEDIUM / LOW severity buckets
- **Cross-cloud bridge detection** — counts and cloud pairs (e.g., "aws → azure: 3 bridges")
- **Export** — JSON and CSV reports
- **19ms** — scans run in under 20 milliseconds

## What Requires a License

Enterprise Edition (via API key) adds:
- Full cross-cloud attack path analysis (identity chains, Triple Jump detection)
- Automated remediation code generation
- Financial exposure quantification (ZAR / USD)
- POPIA compliance reporting

---

## Installation

### Option 1: pip install (recommended)

```bash
pip install v19-scanner
```

### Option 2: From source

```bash
git clone https://github.com/vyugard-systems/v-19.git
cd v-19
pip install -e .
```

### Requirements

- Python 3.9+
- Cloud credentials configured for whichever clouds you want to scan:
  - **AWS**: `~/.aws/credentials` or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
  - **Azure**: `az login` or service principal env vars
  - **GCP**: `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS`
  - **Kubernetes**: `~/.kube/config` or in-cluster config

---

## Quick Start

```bash
# Scan all clouds (auto-detects available credentials)
v-19 analyze

# Scan specific clouds
v-19 analyze --aws
v-19 analyze --azure --gcp
v-19 analyze --k8s

# View classified risks
v-19 risks
v-19 risks --severity critical --top 10

# Export results
v-19 export --format json
v-19 export --format csv -o my_report.csv
```

### Example Output

```
  v1.0.0  |  2026-03-12 14:30:00

  [AWS] Credentials: profile
  [AWS] Scanned 47 identities in 4.2ms
  [Azure] Credentials: cli
  [Azure] Scanned 23 identities in 3.8ms

  ----------------------------------------------------------------------
  Scan complete in 19ms
  Clouds scanned: aws, azure
  Identities found: 70
  ----------------------------------------------------------------------

  ========================================================================
  FINDINGS: 12 total  (2 critical, 4 high, 6 medium)
  ========================================================================

  #    LEVEL      CLOUD        TITLE
  --------------------------------------------------------------------
  1    CRITICAL   aws          Admin user with no MFA
  2    CRITICAL   azure        Global Admin with federated creds
  3    HIGH       aws          Cross-account role assumption
  ...

  ========================================================================
  CROSS-CLOUD BRIDGES: 3 detected
  ========================================================================

    aws -> azure
    azure -> gcp

  Full attack path analysis available with Enterprise license:
    v-19 bridges --api-key KEY
```

---

## All Commands

| Command | License | Description |
|---------|---------|-------------|
| `v-19 analyze` | Free | Scan clouds and classify risks |
| `v-19 risks` | Free | Show classified findings (sorted) |
| `v-19 export` | Free | Export to JSON or CSV |
| `v-19 bridges` | Enterprise | Full cross-cloud attack path analysis |
| `v-19 remediate` | Enterprise | Generate fix code |
| `v-19 exposure` | Enterprise | Financial exposure & ROI report |
| `v-19 compliance` | Enterprise | POPIA compliance report |

---

## Enterprise Edition

```bash
# Set your API key
export V19_API_KEY=your-key-here

# Or pass it per command
v-19 bridges --api-key YOUR_KEY
v-19 remediate --api-key YOUR_KEY
v-19 exposure --api-key YOUR_KEY
v-19 compliance --api-key YOUR_KEY
```

Get a license at [vyugard.tech/enterprise](https://vyugard.tech/enterprise).

---

## Use as a Library

Integrate the v-19 engine into your own application:

```python
from v19 import Scanner, BridgeDetector
from v19.engine import V19RiskScorer, RiskLevel
from v19.providers import AWSScanner, AzureScanner

# Scan and score
scorer = Scanner()
findings = scorer.score_all(aws_identities=aws_ids, azure_identities=az_ids)

# Detect cross-cloud bridges
detector = BridgeDetector()
bridges = detector.detect(aws_ids + az_ids)
```

---

## Contributing

We welcome contributions — scanner improvements, bug fixes, docs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Specification

The v-19 protocol and the Triple Jump taxonomy are formally defined in [`spec/`](spec/):

- [**PROTOCOL_V19.md**](spec/PROTOCOL_V19.md) — The 19ms standard: technical constraints, scan phases, and latency guarantees
- [**TRIPLE_JUMP.md**](spec/TRIPLE_JUMP.md) — Mathematical definition of cross-cloud attack bridges

## License

Copyright (c) 2026 Vyugard Systems. All rights reserved.

Apache 2.0 — see [LICENSE](LICENSE).

