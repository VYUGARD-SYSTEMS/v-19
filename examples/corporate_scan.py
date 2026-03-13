#!/usr/bin/env python3
"""
Corporate Scenario — v-19 Example

Simulates a complex multi-cloud environment for a mid-market
financial services company with ~200 identities across all
four cloud domains.

Demonstrates:
  - Full 4-cloud scan
  - Risk classification output
  - Bridge detection summary
  - Export to JSON

Total exposure in this scenario: R196.7M
"""

import json
import time
from datetime import datetime


def mock_corporate_environment():
    """
    Simulates the identity landscape of a 200-person
    financial services company with:
      - AWS: 47 IAM users/roles (production + CI/CD)
      - Azure: 63 AD principals (corporate directory)
      - GCP: 28 service accounts (data pipeline)
      - Kubernetes: 85 service accounts (microservices)

    Returns mock scan results that mirror real v-19 output.
    """
    scan_start = time.perf_counter()

    results = {
        "meta": {
            "scanner": "v-19",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "scan_time_ms": 0,
        },
        "clouds": {
            "aws": {
                "status": "scanned",
                "credential_source": "sts",
                "identities": 47,
                "scan_time_ms": 4.2,
            },
            "azure": {
                "status": "scanned",
                "credential_source": "cli",
                "identities": 63,
                "scan_time_ms": 5.1,
            },
            "gcp": {
                "status": "scanned",
                "credential_source": "adc",
                "identities": 28,
                "scan_time_ms": 3.7,
            },
            "kubernetes": {
                "status": "scanned",
                "credential_source": "kubeconfig",
                "identities": 85,
                "scan_time_ms": 4.8,
            },
        },
        "findings": [
            {
                "severity": "CRITICAL",
                "cloud": "aws",
                "title": "Admin user 'deploy-prod' with no MFA",
                "description": "IAM user has AdministratorAccess policy attached with no MFA device configured.",
            },
            {
                "severity": "CRITICAL",
                "cloud": "azure",
                "title": "Global Admin SP with federated credential to AWS",
                "description": "Service principal with Directory.ReadWrite.All has federated credential accepting AWS STS tokens.",
            },
            {
                "severity": "CRITICAL",
                "cloud": "kubernetes",
                "title": "cluster-admin binding on default service account",
                "description": "Default SA in 'payments' namespace has cluster-admin ClusterRoleBinding.",
            },
            {
                "severity": "HIGH",
                "cloud": "aws",
                "title": "Cross-account role assumption to production",
                "description": "Role 'cicd-deploy' can AssumeRole into production account 112233445566.",
            },
            {
                "severity": "HIGH",
                "cloud": "gcp",
                "title": "Service account key exported — data-pipeline-sa",
                "description": "User-managed key exists for SA with BigQuery Admin and Storage Admin roles.",
            },
            {
                "severity": "HIGH",
                "cloud": "azure",
                "title": "Stale app registration with Contributor role",
                "description": "App 'legacy-etl-2024' last sign-in 284 days ago, has Contributor on production subscription.",
            },
            {
                "severity": "HIGH",
                "cloud": "kubernetes",
                "title": "Privileged pod with automounted token",
                "description": "Pod 'analytics-worker' runs privileged with automounted SA token bound to GCP via Workload Identity.",
            },
            {
                "severity": "MEDIUM",
                "cloud": "aws",
                "title": "IAM role with wildcard resource policy",
                "description": "Role 'lambda-exec' has s3:* on Resource '*'.",
            },
            {
                "severity": "MEDIUM",
                "cloud": "gcp",
                "title": "Default compute SA with Editor role",
                "description": "Default Compute Engine SA has roles/editor — inherited by all VMs without explicit SA.",
            },
            {
                "severity": "MEDIUM",
                "cloud": "azure",
                "title": "Guest user with Security Reader role",
                "description": "External guest user from partner domain has Security Reader on production subscription.",
            },
            {
                "severity": "MEDIUM",
                "cloud": "kubernetes",
                "title": "Token automounting in kube-system",
                "description": "46 pods in kube-system have automountServiceAccountToken: true (default).",
            },
            {
                "severity": "MEDIUM",
                "cloud": "aws",
                "title": "Access key older than 180 days",
                "description": "IAM user 'svc-reporting' has access key AKIA... created 214 days ago.",
            },
        ],
        "bridges": {
            "total": 7,
            "pairs": [
                {"source": "aws", "target": "azure", "count": 2},
                {"source": "azure", "target": "gcp", "count": 1},
                {"source": "gcp", "target": "kubernetes", "count": 2},
                {"source": "kubernetes", "target": "azure", "count": 1},
                {"source": "aws", "target": "gcp", "count": 1},
            ],
            "note": "Full attack path analysis available with Enterprise license: v-19 bridges --api-key KEY",
        },
        "summary": {
            "total_identities": 223,
            "total_findings": 12,
            "critical": 3,
            "high": 4,
            "medium": 5,
            "low": 0,
            "bridges_detected": 7,
            "clouds_scanned": 4,
        },
    }

    scan_ms = (time.perf_counter() - scan_start) * 1000
    results["meta"]["scan_time_ms"] = round(scan_ms, 1)

    return results


def print_report(results):
    """Print formatted v-19 scan report."""
    meta = results["meta"]
    summary = results["summary"]

    print(f"\n  v-19 {meta['version']}  |  {meta['timestamp'][:19]}")
    print()

    # Cloud status
    for cloud, info in results["clouds"].items():
        print(f"  [{cloud.upper()}] Credentials: {info['credential_source']}")
        print(f"  [{cloud.upper()}] Scanned {info['identities']} identities in {info['scan_time_ms']}ms")

    total_ms = sum(c["scan_time_ms"] for c in results["clouds"].values())
    print(f"\n  {'─' * 70}")
    print(f"  Scan complete in {total_ms:.0f}ms")
    print(f"  Clouds scanned: {summary['clouds_scanned']}")
    print(f"  Identities found: {summary['total_identities']}")
    print(f"  {'─' * 70}")

    # Findings
    print(f"\n  {'=' * 72}")
    print(f"  FINDINGS: {summary['total_findings']} total  ({summary['critical']} critical, {summary['high']} high, {summary['medium']} medium)")
    print(f"  {'=' * 72}")
    print(f"\n  {'#':<5}{'LEVEL':<12}{'CLOUD':<12}TITLE")
    print(f"  {'─' * 68}")

    for i, f in enumerate(results["findings"], 1):
        print(f"  {i:<5}{f['severity']:<12}{f['cloud']:<12}{f['title']}")

    # Bridges
    bridges = results["bridges"]
    print(f"\n  {'=' * 72}")
    print(f"  CROSS-CLOUD BRIDGES: {bridges['total']} detected")
    print(f"  {'=' * 72}")
    print()
    for pair in bridges["pairs"]:
        print(f"    {pair['source']} → {pair['target']}: {pair['count']}")
    print(f"\n  {bridges['note']}")

    # Exposure teaser
    print(f"\n  {'=' * 72}")
    print(f"  ESTIMATED EXPOSURE (Enterprise)")
    print(f"  {'=' * 72}")
    print(f"    PII Records at Risk:       2.4M customers")
    print(f"    POPIA Fine (max):          R 10,000,000")
    print(f"    Breach Notification:       R  3,200,000")
    print(f"    Business Interruption:     R 48,000,000")
    print(f"    Reputational (est):        R135,500,000")
    print(f"    {'─' * 40}")
    print(f"    Total Exposure:            R196,700,000")
    print(f"\n    Run 'v-19 exposure --api-key KEY' for full quantification.\n")


def main():
    print("\n  v-19 Corporate Scan — Mock Environment")
    print("  Financial Services, 223 identities, 4 clouds\n")

    results = mock_corporate_environment()
    print_report(results)

    # Export
    out_path = "v19_corporate_report.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Report exported to {out_path}\n")


if __name__ == "__main__":
    main()
