#!/usr/bin/env python3
"""
Triple Jump Scenario — v-19 Example

Demonstrates how v-19 detects cross-cloud identity bridges
that form a potential "Triple Jump" attack chain:

  Kubernetes Pod → Azure AD → AWS IAM Role

This example shows how to use the v-19 engine programmatically
(outside of the CLI).
"""

from pkg.engine.scanner import V19RiskScorer, RiskLevel
from pkg.engine.bridges import BridgeDetector
from internal.auth.credentials import CredentialChain


def main():
    # ── Resolve credentials ────────────────────────────────────
    chain = CredentialChain(verbose=True)

    aws_creds = chain.resolve_aws_credentials()
    azure_creds = chain.resolve_azure_credentials()
    k8s_creds = chain.resolve_kubernetes_credentials()

    if not any([aws_creds, azure_creds, k8s_creds]):
        print("No cloud credentials found. Configure at least two clouds.")
        return

    # ── Scan available clouds ──────────────────────────────────
    aws_identities = []
    azure_identities = []
    k8s_identities = []

    if aws_creds:
        from pkg.providers.aws import AWSScanner
        scanner = AWSScanner(aws_creds)
        aws_identities, dur = scanner.scan()
        print(f"[AWS] {len(aws_identities)} identities ({dur:.1f}ms)")

    if azure_creds:
        from pkg.providers.azure import AzureScanner
        scanner = AzureScanner(azure_creds)
        azure_identities, dur = scanner.scan()
        print(f"[Azure] {len(azure_identities)} identities ({dur:.1f}ms)")

    if k8s_creds:
        from pkg.providers.kubernetes import KubernetesScanner
        scanner = KubernetesScanner(k8s_creds)
        k8s_identities, dur = scanner.scan()
        print(f"[K8s] {len(k8s_identities)} identities ({dur:.1f}ms)")

    # ── Classify risks ─────────────────────────────────────────
    scorer = V19RiskScorer()
    findings = scorer.score_all(
        aws_identities=aws_identities or None,
        azure_identities=azure_identities or None,
        k8s_identities=k8s_identities or None,
    )

    # ── Detect bridges ─────────────────────────────────────────
    detector = BridgeDetector()
    bridges = detector.detect_bridges(
        aws_identities=aws_identities or None,
        azure_identities=azure_identities or None,
        k8s_identities=k8s_identities or None,
    )
    summary = detector.get_summary(bridges)

    # ── Report ─────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Findings: {len(findings)}")
    print(f"  Critical: {sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)}")
    print(f"  Bridges:  {summary.get('total_bridges', 0)}")

    for pair in summary.get("cloud_pairs", []):
        print(f"    {pair}")

    if summary.get("total_bridges", 0) > 0:
        print(f"\n  Cross-cloud bridges detected.")
        print(f"  Full attack path analysis requires Enterprise license.")
        print(f"  → https://vyugard.tech/enterprise")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
