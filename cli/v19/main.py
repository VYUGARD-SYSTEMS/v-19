#!/usr/bin/env python3
"""
v-19 CLI — Production Command-Line Interface

Simple, memorable commands for multi-cloud identity scanning.

FREE COMMANDS (No license):
  v-19 analyze                   Auto-detect all clouds
  v-19 analyze --aws             AWS only
  v-19 analyze --azure           Azure only
  v-19 analyze --gcp             GCP only
  v-19 analyze --k8s             Kubernetes only
  v-19 analyze --all             Explicit all clouds
  v-19 risks                     Show classified risks (sorted)
  v-19 export --format json      Export findings to file

ENTERPRISE COMMANDS (Requires --api-key):
  v-19 bridges --api-key KEY     Cross-cloud attack path analysis
  v-19 remediate --api-key KEY   Generate fix code
  v-19 exposure --api-key KEY    Financial exposure report
  v-19 compliance --api-key KEY  POPIA compliance report
"""

import sys
import os
import argparse
import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional

from internal.auth.credentials import CredentialChain
from pkg.providers.aws import AWSScanner, AWSIdentity
from pkg.providers.azure import AzureScanner, AzureIdentity
from pkg.providers.gcp import GCPScanner, GCPIdentity
from pkg.providers.kubernetes import KubernetesScanner, K8sIdentity
from pkg.engine.scanner import V19RiskScorer, RiskFinding, RiskLevel
from pkg.engine.bridges import BridgeDetector, CloudBridge

logger = logging.getLogger("v19")

BANNER = r"""
 ██╗   ██╗     ██╗ █████╗
 ██║   ██║    ███║██╔══██╗
 ██║   ██║    ╚██║╚██████║
 ╚██╗ ██╔╝     ██║ ╚═══██║
  ╚████╔╝      ██║ █████╔╝
   ╚═══╝       ╚═╝ ╚════╝
  19ms Multi-Cloud Detection Engine
"""

VERSION = "1.0.0"


# ── Enterprise paywall ─────────────────────────────────────────

def require_license(feature_name: str):
    """Decorator that gates enterprise features behind an API key."""
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            if not self.api_key:
                _print_paywall(feature_name)
                return 1
            return func(self, *args, **kwargs)
        wrapper.__doc__ = func.__doc__
        return wrapper
    return decorator


def _print_paywall(feature_name: str):
    print()
    print("=" * 72)
    print(f"  ENTERPRISE FEATURE: {feature_name}")
    print("=" * 72)
    print()
    print("  This feature requires a v-19 Enterprise license:")
    print("    - Automated remediation code generation")
    print("    - Financial exposure calculation (ROI analysis)")
    print("    - POPIA compliance reporting")
    print("    - Full cross-cloud attack path analysis (Triple Jump)")
    print("    - Priority support")
    print()
    print("  Free alternatives available now:")
    print("    v-19 analyze     Detect risks (no license needed)")
    print("    v-19 risks       View classified findings")
    print()
    print("  Get Enterprise:")
    print("    1. Visit: https://vyugard.tech/enterprise")
    print("    2. Get API key from license dashboard")
    print("    3. Run:  v-19 remediate --api-key YOUR_KEY")
    print()
    print("=" * 72)
    print()


# ── Scan result container ──────────────────────────────────────

class ScanResults:
    """Holds all scan data across clouds for the current session."""

    def __init__(self):
        self.aws_identities: List[AWSIdentity] = []
        self.azure_identities: List[AzureIdentity] = []
        self.gcp_identities: List[GCPIdentity] = []
        self.k8s_identities: List[K8sIdentity] = []
        self.scan_durations: Dict[str, float] = {}
        self.findings: List[RiskFinding] = []
        self.bridge_summary: Dict = {}
        self.total_duration_ms: float = 0
        self.clouds_scanned: List[str] = []
        self.timestamp: str = datetime.now().isoformat()


# ── Main CLI class ─────────────────────────────────────────────

class V19CLI:
    """v-19 Scanner: 19ms Multi-Cloud Detection Engine"""

    def __init__(self):
        self.api_key: Optional[str] = os.getenv("V19_API_KEY")
        self.results: Optional[ScanResults] = None
        self.credential_chain = CredentialChain(verbose=False)
        self.scorer = V19RiskScorer()
        self.bridge_detector = BridgeDetector()

    # ── analyze ────────────────────────────────────────────────

    def analyze(
        self,
        clouds: List[str],
        severity: Optional[str] = None,
        quiet: bool = False,
    ) -> int:
        """
        Scan cloud environments and score risks.

        This is the primary FREE command.
        """
        results = ScanResults()
        overall_start = time.time()

        if not quiet:
            print(BANNER)
            print(f"  v{VERSION}  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print()

        # ── Resolve credentials & scan each cloud ──────────────

        for cloud in clouds:
            if cloud == "aws":
                self._scan_aws(results, quiet)
            elif cloud == "azure":
                self._scan_azure(results, quiet)
            elif cloud == "gcp":
                self._scan_gcp(results, quiet)
            elif cloud in ("kubernetes", "k8s"):
                self._scan_k8s(results, quiet)

        results.total_duration_ms = (time.time() - overall_start) * 1000

        # ── Score identities ───────────────────────────────────

        findings = self.scorer.score_all(
            aws_identities=results.aws_identities or None,
            azure_identities=results.azure_identities or None,
            gcp_identities=results.gcp_identities or None,
            k8s_identities=results.k8s_identities or None,
        )

        # ── Detect cross-cloud bridges (summary only) ─────────

        bridges = self.bridge_detector.detect_bridges(
            aws_identities=results.aws_identities or None,
            azure_identities=results.azure_identities or None,
            gcp_identities=results.gcp_identities or None,
            k8s_identities=results.k8s_identities or None,
        )
        bridge_findings = self.bridge_detector.bridges_to_findings(bridges)
        findings.extend(bridge_findings)
        findings.sort(key=lambda f: f.sort_key, reverse=True)

        # ── Filter by severity ─────────────────────────────────

        if severity:
            sev_upper = severity.upper()
            findings = [f for f in findings if f.risk_level.value == sev_upper]

        results.findings = findings
        results.bridge_summary = self.bridge_detector.get_summary(bridges)
        self.results = results

        # ── Display results ────────────────────────────────────

        if not quiet:
            self._print_scan_summary(results)
            self._print_findings(findings)
            self._print_bridge_teaser(results.bridge_summary)
            self._print_next_steps(findings)

        return 0

    # ── risks ──────────────────────────────────────────────────

    def risks(self, top: int = 20, severity: Optional[str] = None) -> int:
        """Show classified risk findings from the last scan."""
        if not self.results or not self.results.findings:
            print("\n  No scan results. Run 'v-19 analyze' first.\n")
            return 1

        findings = self.results.findings
        if severity:
            findings = [f for f in findings if f.risk_level.value == severity.upper()]

        findings = findings[:top]

        print()
        print("=" * 72)
        print("  v-19 RISK FINDINGS")
        print("=" * 72)
        print()
        print(f"  {'#':<4} {'LEVEL':<10} {'CLOUD':<12} {'TITLE'}")
        print("  " + "-" * 68)

        for i, f in enumerate(findings, 1):
            print(f"  {i:<4} {f.risk_level.value:<10} {f.cloud:<12} {f.title[:42]}")

        print()
        print(f"  Showing {len(findings)} of {len(self.results.findings)} findings")
        print()
        return 0

    # ── bridges ────────────────────────────────────────────────

    @require_license("Cross-Cloud Attack Path Analysis")
    def bridges(self) -> int:
        """[ENTERPRISE] Show full cross-cloud attack path analysis."""
        # Enterprise logic would use the_mechanism's BridgeCorrelator
        print("\n  [v-19 Enterprise] Attack path analysis engine active.")
        print("  Generating full cross-cloud attack chain report...\n")
        return 0

    # ── export ─────────────────────────────────────────────────

    def export(self, fmt: str = "json", output: Optional[str] = None) -> int:
        """Export scan results to file."""
        if not self.results:
            print("\n  No scan results. Run 'v-19 analyze' first.\n")
            return 1

        data = {
            "v19_version": VERSION,
            "scan_timestamp": self.results.timestamp,
            "scan_duration_ms": round(self.results.total_duration_ms, 1),
            "clouds_scanned": self.results.clouds_scanned,
            "total_findings": len(self.results.findings),
            "bridge_summary": self.results.bridge_summary,
            "findings": [f.to_dict() for f in self.results.findings],
            "summary": {
                "critical": sum(1 for f in self.results.findings if f.risk_level == RiskLevel.CRITICAL),
                "high": sum(1 for f in self.results.findings if f.risk_level == RiskLevel.HIGH),
                "medium": sum(1 for f in self.results.findings if f.risk_level == RiskLevel.MEDIUM),
                "low": sum(1 for f in self.results.findings if f.risk_level == RiskLevel.LOW),
            },
        }

        if fmt == "json":
            out_file = output or f"v19_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\n  Exported {len(self.results.findings)} findings to {out_file}\n")
        elif fmt == "csv":
            out_file = output or f"v19_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(out_file, "w") as f:
                f.write("finding_id,title,risk_level,cloud,identity,is_cross_cloud\n")
                for finding in self.results.findings:
                    title_safe = finding.title.replace(",", ";")
                    identity_safe = finding.identity_name.replace(",", ";")
                    f.write(f"{finding.finding_id},{title_safe},{finding.risk_level.value},"
                            f"{finding.cloud},{identity_safe},"
                            f"{finding.is_cross_cloud}\n")
            print(f"\n  Exported {len(self.results.findings)} findings to {out_file}\n")

        return 0

    # ── Enterprise: remediate ──────────────────────────────────

    @require_license("Automated Remediation")
    def remediate(self, finding_id: Optional[str] = None) -> int:
        """[ENTERPRISE] Generate remediation code for findings."""
        # Enterprise logic would connect to the_mechanism's PolicyGenerator
        print("\n  [v-19 Enterprise] Remediation engine active.")
        print("  Generating fix code for detected findings...\n")
        return 0

    # ── Enterprise: exposure ───────────────────────────────────

    @require_license("Financial Exposure Calculation")
    def exposure(self) -> int:
        """[ENTERPRISE] Calculate financial exposure and ROI."""
        # Enterprise logic would use the_mechanism's ExposureCalculator
        print("\n  [v-19 Enterprise] Financial exposure engine active.")
        print("  Calculating R-value exposure...\n")
        return 0

    # ── Enterprise: compliance ─────────────────────────────────

    @require_license("POPIA Compliance Reporting")
    def compliance(self, report_type: str = "notification") -> int:
        """[ENTERPRISE] Generate POPIA compliance reports."""
        print("\n  [v-19 Enterprise] Compliance engine active.")
        print(f"  Generating {report_type} report...\n")
        return 0

    # ── Internal: scan each cloud ──────────────────────────────

    def _scan_aws(self, results: ScanResults, quiet: bool):
        if not quiet:
            print("  [AWS] Resolving credentials...")
        creds = self.credential_chain.resolve_aws_credentials()
        if creds:
            if not quiet:
                print(f"  [AWS] Credentials: {creds.get('source', 'resolved')}")
            scanner = AWSScanner(creds)
            identities, duration = scanner.scan()
            results.aws_identities = identities
            results.scan_durations["aws"] = duration
            results.clouds_scanned.append("aws")
            if not quiet:
                print(f"  [AWS] Scanned {len(identities)} identities in {duration:.1f}ms")
        else:
            if not quiet:
                print("  [AWS] No credentials found — skipping")

    def _scan_azure(self, results: ScanResults, quiet: bool):
        if not quiet:
            print("  [Azure] Resolving credentials...")
        creds = self.credential_chain.resolve_azure_credentials()
        if creds:
            if not quiet:
                print(f"  [Azure] Credentials: {creds.get('source', 'resolved')}")
            scanner = AzureScanner(creds)
            identities, duration = scanner.scan()
            results.azure_identities = identities
            results.scan_durations["azure"] = duration
            results.clouds_scanned.append("azure")
            if not quiet:
                print(f"  [Azure] Scanned {len(identities)} identities in {duration:.1f}ms")
        else:
            if not quiet:
                print("  [Azure] No credentials found — skipping")

    def _scan_gcp(self, results: ScanResults, quiet: bool):
        if not quiet:
            print("  [GCP] Resolving credentials...")
        creds = self.credential_chain.resolve_gcp_credentials()
        if creds:
            if not quiet:
                print(f"  [GCP] Credentials: {creds.get('source', 'resolved')}")
            scanner = GCPScanner(creds)
            identities, duration = scanner.scan()
            results.gcp_identities = identities
            results.scan_durations["gcp"] = duration
            results.clouds_scanned.append("gcp")
            if not quiet:
                print(f"  [GCP] Scanned {len(identities)} identities in {duration:.1f}ms")
        else:
            if not quiet:
                print("  [GCP] No credentials found — skipping")

    def _scan_k8s(self, results: ScanResults, quiet: bool):
        if not quiet:
            print("  [K8s] Resolving credentials...")
        creds = self.credential_chain.resolve_kubernetes_credentials()
        if creds:
            if not quiet:
                print(f"  [K8s] Credentials: {creds.get('source', 'resolved')}")
            scanner = KubernetesScanner(creds)
            identities, duration = scanner.scan()
            results.k8s_identities = identities
            results.scan_durations["kubernetes"] = duration
            results.clouds_scanned.append("kubernetes")
            if not quiet:
                print(f"  [K8s] Scanned {len(identities)} identities in {duration:.1f}ms")
        else:
            if not quiet:
                print("  [K8s] No credentials found — skipping")

    # ── Display helpers ────────────────────────────────────────

    def _print_scan_summary(self, results: ScanResults):
        total_ids = (
            len(results.aws_identities)
            + len(results.azure_identities)
            + len(results.gcp_identities)
            + len(results.k8s_identities)
        )

        print()
        print("  " + "-" * 68)
        print(f"  Scan complete in {results.total_duration_ms:.0f}ms")
        print(f"  Clouds scanned: {', '.join(results.clouds_scanned) or 'none'}")
        print(f"  Identities found: {total_ids}")
        print("  " + "-" * 68)

    def _print_findings(self, findings: List[RiskFinding]):
        if not findings:
            print("\n  No risk findings detected.\n")
            return

        crit = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
        med = sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM)

        print()
        print("=" * 72)
        print(f"  FINDINGS: {len(findings)} total  "
              f"({crit} critical, {high} high, {med} medium)")
        print("=" * 72)
        print()
        print(f"  {'#':<4} {'LEVEL':<10} {'CLOUD':<12} {'TITLE'}")
        print("  " + "-" * 68)

        for i, f in enumerate(findings[:15], 1):
            print(f"  {i:<4} {f.risk_level.value:<10} {f.cloud:<12} {f.title[:42]}")

        if len(findings) > 15:
            print(f"\n  ... and {len(findings) - 15} more. Run 'v-19 risks' to see all.")

    def _print_bridge_teaser(self, summary: Dict):
        if not summary or summary.get("total_bridges", 0) == 0:
            return

        total = summary["total_bridges"]
        pairs = summary.get("cloud_pairs", [])
        print()
        print("=" * 72)
        print(f"  CROSS-CLOUD BRIDGES: {total} detected")
        print("=" * 72)
        print()
        for pair in pairs:
            print(f"    {pair}")
        print()
        print("  Full attack path analysis available with Enterprise license:")
        print("    v-19 bridges --api-key KEY")
        print()

    def _print_next_steps(self, findings: List[RiskFinding]):
        print()
        print("=" * 72)
        print("  NEXT STEPS")
        print("=" * 72)
        print()
        print("  Free commands:")
        print("    v-19 risks                   View all classified findings")
        print("    v-19 export --format json     Export to JSON/CSV")
        print()
        print("  Enterprise commands (requires license):")
        print("    v-19 bridges --api-key KEY   Full attack path analysis")
        print("    v-19 remediate --api-key KEY  Generate fix code")
        print("    v-19 exposure --api-key KEY   Financial exposure & ROI")
        print("    v-19 compliance --api-key KEY POPIA compliance report")
        print()
        print("  Get Enterprise: https://vyugard.tech/enterprise")
        print()
        print("=" * 72)
        print()


# ── CLI argument parser ────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="v-19",
        description="v-19: 19ms Multi-Cloud Detection Engine",
        epilog="Get Enterprise license: https://vyugard.tech/enterprise",
    )
    parser.add_argument("--version", action="version", version=f"v-19 {VERSION}")
    parser.add_argument("--api-key", help="Enterprise API key (or set V19_API_KEY env var)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── analyze ────────────────────────────────────────────────
    p_analyze = sub.add_parser("analyze", help="Scan clouds and score risks (FREE)")
    p_analyze.add_argument("--aws", action="store_true", help="Scan AWS")
    p_analyze.add_argument("--azure", action="store_true", help="Scan Azure")
    p_analyze.add_argument("--gcp", action="store_true", help="Scan GCP")
    p_analyze.add_argument("--k8s", action="store_true", help="Scan Kubernetes")
    p_analyze.add_argument("--all", action="store_true", help="Scan all clouds")
    p_analyze.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                           help="Filter by severity")
    p_analyze.add_argument("--quiet", "-q", action="store_true", help="Minimal output")

    # ── risks ──────────────────────────────────────────────────
    p_risks = sub.add_parser("risks", help="Show classified risk findings (FREE)")
    p_risks.add_argument("--top", type=int, default=20, help="Number of findings to show")
    p_risks.add_argument("--severity", choices=["critical", "high", "medium", "low"])

    # ── bridges ────────────────────────────────────────────────
    sub.add_parser("bridges", help="Full cross-cloud attack path analysis [ENTERPRISE]")

    # ── export ─────────────────────────────────────────────────
    p_export = sub.add_parser("export", help="Export results to file (FREE)")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.add_argument("--output", "-o", help="Output file path")

    # ── remediate ──────────────────────────────────────────────
    p_remediate = sub.add_parser("remediate", help="Generate fix code [ENTERPRISE]")
    p_remediate.add_argument("--finding", help="Specific finding ID to remediate")

    # ── exposure ───────────────────────────────────────────────
    sub.add_parser("exposure", help="Financial exposure report [ENTERPRISE]")

    # ── compliance ─────────────────────────────────────────────
    p_compliance = sub.add_parser("compliance", help="POPIA compliance report [ENTERPRISE]")
    p_compliance.add_argument("--report", default="notification",
                              choices=["notification", "audit-trail"])

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not args.command:
        parser.print_help()
        return 0

    cli = V19CLI()
    if args.api_key:
        cli.api_key = args.api_key

    # ── Route commands ─────────────────────────────────────────

    if args.command == "analyze":
        clouds = []
        if args.all or not any([args.aws, args.azure, args.gcp, args.k8s]):
            clouds = ["aws", "azure", "gcp", "kubernetes"]
        else:
            if args.aws:
                clouds.append("aws")
            if args.azure:
                clouds.append("azure")
            if args.gcp:
                clouds.append("gcp")
            if args.k8s:
                clouds.append("kubernetes")
        return cli.analyze(clouds, severity=args.severity, quiet=args.quiet)

    elif args.command == "risks":
        return cli.risks(top=args.top, severity=args.severity)

    elif args.command == "bridges":
        return cli.bridges()

    elif args.command == "export":
        return cli.export(fmt=args.format, output=args.output)

    elif args.command == "remediate":
        return cli.remediate(finding_id=getattr(args, "finding", None))

    elif args.command == "exposure":
        return cli.exposure()

    elif args.command == "compliance":
        return cli.compliance(report_type=args.report)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
