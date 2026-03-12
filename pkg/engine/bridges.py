"""
v-19 Cross-Cloud Bridge Detector

Detects cross-cloud identity trust relationships between
AWS, Azure, GCP, and Kubernetes environments.

FREE TIER: Detects individual bridges and shows summary counts.
ENTERPRISE: Full attack path chaining, Triple Jump analysis,
            blast radius calculation, and automated remediation.
"""

import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

from pkg.engine.scanner import RiskFinding, RiskLevel

logger = logging.getLogger(__name__)


@dataclass
class CloudBridge:
    """A detected trust relationship between two cloud providers."""
    source_cloud: str
    target_cloud: str
    bridge_type: str  # "federation", "assume_role", "workload_identity", "oidc"
    risk_level: RiskLevel


class BridgeDetector:
    """
    Detects cross-cloud identity bridges from scanner results.

    Free tier detects individual A→B bridges and provides summary counts.
    Enterprise unlocks multi-hop path chaining and full attack path analysis.
    """

    def __init__(self):
        self._bridge_counter = 0

    def _next_id(self) -> str:
        self._bridge_counter += 1
        return f"BRIDGE_{self._bridge_counter:04d}"

    def detect_bridges(
        self,
        aws_identities: Optional[list] = None,
        azure_identities: Optional[list] = None,
        gcp_identities: Optional[list] = None,
        k8s_identities: Optional[list] = None,
    ) -> List[CloudBridge]:
        """
        Detect individual cross-cloud trust bridges.

        Returns a flat list of bridges. Multi-hop path chaining
        and attack path analysis require Enterprise license.
        """
        bridges: List[CloudBridge] = []

        if aws_identities:
            bridges.extend(self._detect_aws_bridges(aws_identities))

        if azure_identities:
            bridges.extend(self._detect_azure_bridges(azure_identities))

        if gcp_identities:
            bridges.extend(self._detect_gcp_bridges(gcp_identities))

        if k8s_identities and aws_identities:
            bridges.extend(self._detect_k8s_aws_bridges(k8s_identities, aws_identities))

        if k8s_identities and azure_identities:
            bridges.extend(self._detect_k8s_azure_bridges(k8s_identities, azure_identities))

        return bridges

    def get_summary(self, bridges: List[CloudBridge]) -> Dict:
        """
        Get bridge detection summary for free-tier output.

        Shows counts and cloud pairs — no identity details or scoring.
        Full attack path analysis requires Enterprise.
        """
        cloud_pairs = set()
        by_type: Dict[str, int] = {}
        for b in bridges:
            cloud_pairs.add((b.source_cloud, b.target_cloud))
            by_type[b.bridge_type] = by_type.get(b.bridge_type, 0) + 1

        unique_clouds: set = set()
        for src, tgt in cloud_pairs:
            unique_clouds.add(src)
            unique_clouds.add(tgt)

        return {
            "total_bridges": len(bridges),
            "cloud_pairs": [f"{s} -> {t}" for s, t in sorted(cloud_pairs)],
            "clouds_involved": sorted(unique_clouds),
            "bridge_types": by_type,
            "multi_cloud_risk": len(unique_clouds) >= 3,
            "critical_count": sum(1 for b in bridges if b.risk_level == RiskLevel.CRITICAL),
            "high_count": sum(1 for b in bridges if b.risk_level == RiskLevel.HIGH),
        }

    def bridges_to_findings(self, bridges: List[CloudBridge]) -> List[RiskFinding]:
        """Convert individual bridges to risk findings for unified output."""
        findings: List[RiskFinding] = []
        for bridge in bridges:
            findings.append(RiskFinding(
                finding_id=self._next_id(),
                title=f"Cross-cloud bridge: {bridge.source_cloud} -> {bridge.target_cloud}",
                risk_level=bridge.risk_level,
                cloud="multi-cloud",
                identity_name=f"{bridge.source_cloud} -> {bridge.target_cloud}",
                reason=f"Trust chain detected via {bridge.bridge_type}",
                is_cross_cloud=True,
                related_clouds=[bridge.source_cloud, bridge.target_cloud],
            ))
        return findings

    # ── Individual bridge detection ────────────────────────────────

    def _detect_aws_bridges(self, aws_identities: list) -> List[CloudBridge]:
        """Detect federation and cross-account bridges on AWS roles."""
        bridges: List[CloudBridge] = []
        seen_pairs: set = set()

        for identity in aws_identities:
            provider = (identity.federation_provider or "").lower()
            trusts = identity.trust_relationships or []

            if ("sts.windows.net" in provider or "azure" in provider) and ("azure", "aws") not in seen_pairs:
                bridges.append(CloudBridge(
                    source_cloud="azure", target_cloud="aws",
                    bridge_type="federation", risk_level=RiskLevel.HIGH,
                ))
                seen_pairs.add(("azure", "aws"))

            if "accounts.google.com" in provider and ("gcp", "aws") not in seen_pairs:
                bridges.append(CloudBridge(
                    source_cloud="gcp", target_cloud="aws",
                    bridge_type="federation", risk_level=RiskLevel.HIGH,
                ))
                seen_pairs.add(("gcp", "aws"))

            if identity.external_account_id and ("aws", "aws-cross") not in seen_pairs:
                bridges.append(CloudBridge(
                    source_cloud="aws", target_cloud="aws",
                    bridge_type="assume_role", risk_level=RiskLevel.MEDIUM,
                ))
                seen_pairs.add(("aws", "aws-cross"))

            for trust in trusts:
                trust_lower = trust.lower()
                if "federated:" in trust_lower and "oidc" in trust_lower and ("kubernetes", "aws") not in seen_pairs:
                    bridges.append(CloudBridge(
                        source_cloud="kubernetes", target_cloud="aws",
                        bridge_type="oidc", risk_level=RiskLevel.HIGH,
                    ))
                    seen_pairs.add(("kubernetes", "aws"))

        return bridges

    def _detect_azure_bridges(self, azure_identities: list) -> List[CloudBridge]:
        """Detect federated credential bridges on Azure identities."""
        bridges: List[CloudBridge] = []
        seen_pairs: set = set()

        for identity in azure_identities:
            for cred in (identity.federated_credentials or []):
                cred_lower = cred.lower()
                if ("kubernetes" in cred_lower or "oidc" in cred_lower) and ("kubernetes", "azure") not in seen_pairs:
                    bridges.append(CloudBridge(
                        source_cloud="kubernetes", target_cloud="azure",
                        bridge_type="workload_identity", risk_level=RiskLevel.HIGH,
                    ))
                    seen_pairs.add(("kubernetes", "azure"))
                elif ("google" in cred_lower or "gcp" in cred_lower) and ("gcp", "azure") not in seen_pairs:
                    bridges.append(CloudBridge(
                        source_cloud="gcp", target_cloud="azure",
                        bridge_type="federation", risk_level=RiskLevel.MEDIUM,
                    ))
                    seen_pairs.add(("gcp", "azure"))

        return bridges

    def _detect_gcp_bridges(self, gcp_identities: list) -> List[CloudBridge]:
        """Detect workload identity pool bridges on GCP service accounts."""
        bridges: List[CloudBridge] = []
        seen_pairs: set = set()

        for identity in gcp_identities:
            for pool in (identity.workload_id_pools or []):
                pool_lower = pool.lower()
                if "aws" in pool_lower and ("aws", "gcp") not in seen_pairs:
                    bridges.append(CloudBridge(
                        source_cloud="aws", target_cloud="gcp",
                        bridge_type="workload_identity", risk_level=RiskLevel.MEDIUM,
                    ))
                    seen_pairs.add(("aws", "gcp"))
                elif "azure" in pool_lower and ("azure", "gcp") not in seen_pairs:
                    bridges.append(CloudBridge(
                        source_cloud="azure", target_cloud="gcp",
                        bridge_type="workload_identity", risk_level=RiskLevel.MEDIUM,
                    ))
                    seen_pairs.add(("azure", "gcp"))

        return bridges

    def _detect_k8s_aws_bridges(self, k8s_identities: list, aws_identities: list) -> List[CloudBridge]:
        """Detect if K8s → AWS bridge potential exists."""
        has_oidc_roles = any(
            any("oidc" in t.lower() or "eks" in t.lower() for t in (a.trust_relationships or []))
            for a in aws_identities
        )
        has_k8s_sas = any(k.role_bindings for k in k8s_identities)

        if has_oidc_roles and has_k8s_sas:
            return [CloudBridge(
                source_cloud="kubernetes", target_cloud="aws",
                bridge_type="oidc", risk_level=RiskLevel.HIGH,
            )]
        return []

    def _detect_k8s_azure_bridges(self, k8s_identities: list, azure_identities: list) -> List[CloudBridge]:
        """Detect if K8s → Azure bridge potential exists."""
        has_fed_azure = any(a.federated_credentials for a in azure_identities)
        has_k8s_sas = any(k.role_bindings for k in k8s_identities)

        if has_fed_azure and has_k8s_sas:
            return [CloudBridge(
                source_cloud="kubernetes", target_cloud="azure",
                bridge_type="workload_identity", risk_level=RiskLevel.HIGH,
            )]
        return []
