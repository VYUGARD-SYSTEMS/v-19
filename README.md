# v-19 Scanner: Open-Source Multi-Cloud Identity Scanner

**Detect cross-cloud identity risks across AWS, Azure, GCP, and Kubernetes.**

---

## What You Get (Free — Apache 2.0)

- **Multi-cloud scanning** — AWS IAM, Azure AD, GCP service accounts, Kubernetes RBAC
- **Risk classification** — CRITICAL / HIGH / MEDIUM / LOW severity buckets
- **Cross-cloud bridge detection** — counts and cloud pairs (e.g., "aws → azure: 3 bridges")
- **Export** — JSON and CSV reports
- **Fast** — scans run in milliseconds

## What Requires a License

Enterprise Edition (via API key) adds:
- Full cross-cloud attack path analysis (identity chains, Triple Jump detection)
- Automated remediation code generation
- Financial exposure calculation
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

## Contributing

We welcome contributions — scanner improvements, bug fixes, docs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

