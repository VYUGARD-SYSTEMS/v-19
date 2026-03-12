"""
v-19 Free-Tier Risk Scorer

Classifies identity risks into severity buckets (CRITICAL / HIGH / MEDIUM / LOW).
Shows users WHAT is dangerous and drives them to remediate.

This is the FREE analysis layer — it shows the problem.
Enterprise license unlocks detailed scoring, financial exposure, and remediation.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Internal sort weights — not exposed in output
_LEVEL_WEIGHT = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RiskFinding:
    """A risk finding from the free-tier analyzer."""
    finding_id: str
    title: str
    risk_level: RiskLevel
    cloud: str  # aws, azure, gcp, kubernetes
    identity_name: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    is_cross_cloud: bool = False
    related_clouds: List[str] = field(default_factory=list)

    @property
    def sort_key(self) -> int:
        """Internal sort weight for ordering findings."""
        return _LEVEL_WEIGHT.get(self.risk_level.value, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "risk_level": self.risk_level.value,
            "cloud": self.cloud,
            "identity_name": self.identity_name,
            "reason": self.reason,
            "is_cross_cloud": self.is_cross_cloud,
            "related_clouds": self.related_clouds,
        }


class V19RiskScorer:
    """
    Free-tier risk classification engine for v-19.

    Classifies identities into CRITICAL / HIGH / MEDIUM / LOW buckets.
    Detailed risk scoring and financial exposure require Enterprise.
    """

    def __init__(self):
        self._finding_counter = 0

    def _next_id(self, prefix: str = "V19") -> str:
        self._finding_counter += 1
        return f"{prefix}_{self._finding_counter:04d}"

    # ── AWS scoring ────────────────────────────────────────────────

    def score_aws_identities(self, identities: list) -> List[RiskFinding]:
        """Classify AWS identities into risk levels."""
        findings: List[RiskFinding] = []

        for identity in identities:
            perms = identity.permissions or []
            trusts = identity.trust_relationships or []

            # Wildcard admin
            if any(p == "*" or p == "managed:AdministratorAccess" for p in perms):
                findings.append(RiskFinding(
                    finding_id=self._next_id("AWS"),
                    title=f"Admin permissions on {identity.type}: {identity.name}",
                    risk_level=RiskLevel.CRITICAL,
                    cloud="aws",
                    identity_name=identity.name,
                    reason="Wildcard (*) or AdministratorAccess grants full account control",
                    evidence=[f"Permission: {p}" for p in perms if "*" in p or "Admin" in p],
                ))

            # iam:* or sts:*
            elif any("iam:*" in p.lower() or "sts:*" in p.lower() for p in perms):
                findings.append(RiskFinding(
                    finding_id=self._next_id("AWS"),
                    title=f"IAM/STS full access on {identity.name}",
                    risk_level=RiskLevel.HIGH,
                    cloud="aws",
                    identity_name=identity.name,
                    reason="Full IAM or STS access enables privilege escalation",
                    evidence=[p for p in perms if "iam:" in p.lower() or "sts:" in p.lower()],
                ))

            # Public trust (Principal: *)
            if any("Public" in t or t == "*" for t in trusts):
                findings.append(RiskFinding(
                    finding_id=self._next_id("AWS"),
                    title=f"Public trust policy on role {identity.name}",
                    risk_level=RiskLevel.CRITICAL,
                    cloud="aws",
                    identity_name=identity.name,
                    reason="Role can be assumed by ANY AWS principal — open to all accounts",
                ))

            # Cross-account access
            if identity.external_account_id:
                findings.append(RiskFinding(
                    finding_id=self._next_id("AWS"),
                    title=f"Cross-account trust on {identity.name}",
                    risk_level=RiskLevel.HIGH,
                    cloud="aws",
                    identity_name=identity.name,
                    reason="External account can assume this role — verify if intentional",
                ))

            # Federation (OIDC, SAML)
            if identity.federation_provider:
                findings.append(RiskFinding(
                    finding_id=self._next_id("AWS"),
                    title=f"Federated trust on {identity.name}",
                    risk_level=RiskLevel.HIGH,
                    cloud="aws",
                    identity_name=identity.name,
                    reason="Federation creates external trust chain — verify provider",
                    is_cross_cloud=True,
                    related_clouds=["aws"],
                ))

        return findings

    # ── Azure scoring ──────────────────────────────────────────────

    def score_azure_identities(self, identities: list) -> List[RiskFinding]:
        """Classify Azure identities into risk levels."""
        findings: List[RiskFinding] = []

        for identity in identities:
            roles = identity.role_assignments or []
            fed_creds = identity.federated_credentials or []

            for role in roles:
                if "Owner" in role:
                    findings.append(RiskFinding(
                        finding_id=self._next_id("AZR"),
                        title=f"Owner role for {identity.name[:30]}",
                        risk_level=RiskLevel.CRITICAL,
                        cloud="azure",
                        identity_name=identity.name,
                        reason="Owner at subscription scope grants full control including role assignment",
                    ))
                elif "Contributor" in role:
                    findings.append(RiskFinding(
                        finding_id=self._next_id("AZR"),
                        title=f"Contributor role for {identity.name[:30]}",
                        risk_level=RiskLevel.HIGH,
                        cloud="azure",
                        identity_name=identity.name,
                        reason="Contributor can modify all resources in the subscription",
                    ))
                elif "User Access Administrator" in role:
                    findings.append(RiskFinding(
                        finding_id=self._next_id("AZR"),
                        title=f"User Access Admin for {identity.name[:30]}",
                        risk_level=RiskLevel.HIGH,
                        cloud="azure",
                        identity_name=identity.name,
                        reason="Can assign any role to any principal — privilege escalation vector",
                    ))

            if fed_creds:
                findings.append(RiskFinding(
                    finding_id=self._next_id("AZR"),
                    title=f"Federated credential on {identity.name[:30]}",
                    risk_level=RiskLevel.MEDIUM,
                    cloud="azure",
                    identity_name=identity.name,
                    reason="Federated credential creates external trust — verify issuer",
                    is_cross_cloud=True,
                    related_clouds=["azure"],
                ))

        return findings

    # ── GCP scoring ────────────────────────────────────────────────

    def score_gcp_identities(self, identities: list) -> List[RiskFinding]:
        """Classify GCP identities into risk levels."""
        findings: List[RiskFinding] = []

        for identity in identities:
            gcp_roles = identity.roles or []
            pools = identity.workload_id_pools or []

            for role in gcp_roles:
                role_lower = role.lower()
                if "owner" in role_lower or "roles/owner" == role_lower:
                    findings.append(RiskFinding(
                        finding_id=self._next_id("GCP"),
                        title=f"Project Owner: {identity.email}",
                        risk_level=RiskLevel.CRITICAL,
                        cloud="gcp",
                        identity_name=identity.email,
                        reason="Owner role grants full project control including IAM",
                    ))
                elif "editor" in role_lower or "admin" in role_lower:
                    findings.append(RiskFinding(
                        finding_id=self._next_id("GCP"),
                        title=f"Elevated role on {identity.email}: {role}",
                        risk_level=RiskLevel.HIGH,
                        cloud="gcp",
                        identity_name=identity.email,
                        reason="Admin/Editor roles grant broad modification permissions",
                    ))

            if pools:
                findings.append(RiskFinding(
                    finding_id=self._next_id("GCP"),
                    title=f"Workload Identity Federation on {identity.email}",
                    risk_level=RiskLevel.MEDIUM,
                    cloud="gcp",
                    identity_name=identity.email,
                    reason="External workload identity creates cross-cloud trust chain",
                    is_cross_cloud=True,
                    related_clouds=["gcp"],
                ))

        return findings

    # ── Kubernetes scoring ─────────────────────────────────────────

    def score_k8s_identities(self, identities: list) -> List[RiskFinding]:
        """Classify Kubernetes identities into risk levels."""
        findings: List[RiskFinding] = []

        for identity in identities:
            bindings = identity.role_bindings or []

            for binding in bindings:
                if binding == "cluster-admin":
                    findings.append(RiskFinding(
                        finding_id=self._next_id("K8S"),
                        title=f"cluster-admin binding: {identity.namespace}/{identity.name}",
                        risk_level=RiskLevel.CRITICAL,
                        cloud="kubernetes",
                        identity_name=f"{identity.namespace}/{identity.name}",
                        reason="cluster-admin grants unrestricted control over entire cluster",
                    ))
                elif binding in ("admin", "edit"):
                    findings.append(RiskFinding(
                        finding_id=self._next_id("K8S"),
                        title=f"Elevated binding ({binding}): {identity.namespace}/{identity.name}",
                        risk_level=RiskLevel.HIGH,
                        cloud="kubernetes",
                        identity_name=f"{identity.namespace}/{identity.name}",
                        reason=f"'{binding}' role grants broad namespace-level access",
                    ))

            automount = getattr(identity, "automount_service_account_token", True)
            if automount and bindings:
                findings.append(RiskFinding(
                    finding_id=self._next_id("K8S"),
                    title=f"Automounted token with roles: {identity.namespace}/{identity.name}",
                    risk_level=RiskLevel.MEDIUM,
                    cloud="kubernetes",
                    identity_name=f"{identity.namespace}/{identity.name}",
                    reason="Token auto-mounted into pods — any compromised pod inherits these roles",
                ))

        return findings

    # ── Aggregate scoring ──────────────────────────────────────────

    def score_all(
        self,
        aws_identities: Optional[list] = None,
        azure_identities: Optional[list] = None,
        gcp_identities: Optional[list] = None,
        k8s_identities: Optional[list] = None,
    ) -> List[RiskFinding]:
        """Classify identities across all clouds and return sorted findings."""
        all_findings: List[RiskFinding] = []

        if aws_identities:
            all_findings.extend(self.score_aws_identities(aws_identities))
        if azure_identities:
            all_findings.extend(self.score_azure_identities(azure_identities))
        if gcp_identities:
            all_findings.extend(self.score_gcp_identities(gcp_identities))
        if k8s_identities:
            all_findings.extend(self.score_k8s_identities(k8s_identities))

        # Sort by severity descending
        all_findings.sort(key=lambda f: f.sort_key, reverse=True)
        return all_findings
