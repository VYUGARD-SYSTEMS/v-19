"""
v-19 Licensing — The "Blast Radius" Pricing Model

Tier resolution based on license key and identity count:

  COMMUNITY (Free)
    - Single-cloud or mock data
    - Manual remediation only
    - Identity limit: 25
    - Bridge detection: counts only

  PRO ($900–$2,500/month)
    - Multi-cloud ingestion
    - Visual dashboard export
    - Identity limit: per key (50 / 150 / 500)
    - Bridge detection: full pairs + severity

  ENTERPRISE ($100,000+ annual)
    - Unlimited identities
    - CI/CD remediation, blast radius scoring
    - SOC 2 / HIPAA / POPIA compliance
    - Full Triple Jump chain analysis
"""

import os
import hashlib
import json
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class Tier(str, Enum):
    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# Features available at each tier
TIER_FEATURES = {
    Tier.COMMUNITY: {
        "analyze": True,
        "risks": True,
        "export": True,
        "bridges": False,
        "remediate": False,
        "exposure": False,
        "compliance": False,
        "dashboard": False,
        "identity_limit": 25,
        "clouds": 1,
        "label": "Community (Free)",
    },
    Tier.PRO: {
        "analyze": True,
        "risks": True,
        "export": True,
        "bridges": True,
        "remediate": False,
        "exposure": True,
        "compliance": False,
        "dashboard": True,
        "identity_limit": 500,
        "clouds": 4,
        "label": "Pro",
    },
    Tier.ENTERPRISE: {
        "analyze": True,
        "risks": True,
        "export": True,
        "bridges": True,
        "remediate": True,
        "exposure": True,
        "compliance": True,
        "dashboard": True,
        "identity_limit": None,  # unlimited
        "clouds": 4,
        "label": "Enterprise",
    },
}

# Map features to human-readable names for paywall messages
FEATURE_NAMES = {
    "bridges": "Cross-Cloud Attack Path Analysis",
    "remediate": "Automated Remediation",
    "exposure": "Financial Exposure & Blast Radius",
    "compliance": "Compliance Reporting (SOC 2 / HIPAA / POPIA)",
    "dashboard": "Visual Dashboard Export",
}

# Minimum tier required for each feature
FEATURE_MIN_TIER = {
    "analyze": Tier.COMMUNITY,
    "risks": Tier.COMMUNITY,
    "export": Tier.COMMUNITY,
    "bridges": Tier.PRO,
    "exposure": Tier.PRO,
    "dashboard": Tier.PRO,
    "remediate": Tier.ENTERPRISE,
    "compliance": Tier.ENTERPRISE,
}


@dataclass
class License:
    """Resolved license state for the current session."""
    tier: Tier
    key: Optional[str]
    identity_limit: Optional[int]
    clouds_allowed: int
    label: str

    def can(self, feature: str) -> bool:
        """Check if this license permits a given feature."""
        features = TIER_FEATURES.get(self.tier, TIER_FEATURES[Tier.COMMUNITY])
        return features.get(feature, False)

    def identities_exceeded(self, count: int) -> bool:
        """Check if identity count exceeds the tier limit."""
        if self.identity_limit is None:
            return False
        return count > self.identity_limit


def resolve_license(api_key: Optional[str] = None) -> License:
    """
    Resolve the license tier from an API key.

    Key format determines tier:
      - None / empty       → Community
      - V19-PRO-*          → Pro
      - V19-ENT-*          → Enterprise

    In production, this would validate against a license server.
    For now, tier is derived from the key prefix.
    """
    key = api_key or os.getenv("V19_API_KEY")

    if not key:
        features = TIER_FEATURES[Tier.COMMUNITY]
        return License(
            tier=Tier.COMMUNITY,
            key=None,
            identity_limit=features["identity_limit"],
            clouds_allowed=features["clouds"],
            label=features["label"],
        )

    key_upper = key.strip().upper()

    if key_upper.startswith("V19-ENT-"):
        tier = Tier.ENTERPRISE
    elif key_upper.startswith("V19-PRO-"):
        tier = Tier.PRO
    else:
        # Treat any other key as Pro (backward compat)
        tier = Tier.PRO

    features = TIER_FEATURES[tier]
    return License(
        tier=tier,
        key=key,
        identity_limit=features["identity_limit"],
        clouds_allowed=features["clouds"],
        label=features["label"],
    )


def print_license_status(license: License):
    """Print current license tier and capabilities."""
    t = license.tier
    features = TIER_FEATURES[t]

    print()
    print("=" * 72)
    print(f"  v-19 LICENSE: {license.label}")
    print("=" * 72)
    print()

    # Identity limit
    if license.identity_limit is None:
        print("  Identities:   Unlimited")
    else:
        print(f"  Identities:   {license.identity_limit} per scan")

    print(f"  Clouds:       {license.clouds_allowed}")
    print()

    # Feature matrix
    print("  FEATURE                                AVAILABLE")
    print("  " + "-" * 56)

    all_features = ["analyze", "risks", "export", "bridges",
                    "exposure", "dashboard", "remediate", "compliance"]

    for feat in all_features:
        enabled = features.get(feat, False)
        icon = "YES" if enabled else " — "
        min_tier = FEATURE_MIN_TIER.get(feat, Tier.COMMUNITY)
        suffix = ""
        if not enabled:
            suffix = f"  (requires {TIER_FEATURES[min_tier]['label']})"
        name = FEATURE_NAMES.get(feat, feat.title())
        print(f"  {name:<40} {icon}{suffix}")

    print()

    # Upgrade prompt
    if t == Tier.COMMUNITY:
        print("  ┌─────────────────────────────────────────────────────┐")
        print("  │  UPGRADE TO PRO                                     │")
        print("  │  Multi-cloud scanning, bridge analysis, dashboards  │")
        print("  │  $900/mo for up to 50 identities                   │")
        print("  │  https://vyugard.tech/pro                           │")
        print("  └─────────────────────────────────────────────────────┘")
    elif t == Tier.PRO:
        print("  ┌─────────────────────────────────────────────────────┐")
        print("  │  UPGRADE TO ENTERPRISE                              │")
        print("  │  Unlimited identities, auto-remediation, compliance │")
        print("  │  $100,000+/yr site license                          │")
        print("  │  https://vyugard.tech/enterprise                    │")
        print("  └─────────────────────────────────────────────────────┘")

    print()
    print("=" * 72)
    print()


def print_upgrade_prompt(feature: str, current_tier: Tier):
    """Print a targeted upgrade message when a gated feature is accessed."""
    min_tier = FEATURE_MIN_TIER.get(feature, Tier.ENTERPRISE)
    target = TIER_FEATURES[min_tier]
    feat_name = FEATURE_NAMES.get(feature, feature.title())

    print()
    print("=" * 72)
    print(f"  {feat_name}")
    print("=" * 72)
    print()
    print(f"  This feature requires v-19 {target['label']}.")
    print(f"  You are currently on: {TIER_FEATURES[current_tier]['label']}")
    print()

    if min_tier == Tier.PRO:
        print("  v-19 Pro — $900 to $2,500/month")
        print("  Tiered by active IAM identities:")
        print()
        print("    Up to 50 identities     $900/mo")
        print("    Up to 150 identities    $1,500/mo")
        print("    Up to 500 identities    $2,500/mo")
        print()
        print("  Includes:")
        print("    - Multi-cloud ingestion (AWS + Azure + GCP + K8s)")
        print("    - Cross-cloud bridge analysis")
        print("    - Financial exposure reports")
        print("    - Visual dashboard export")
        print()
        print("  Start: https://vyugard.tech/pro")
    else:
        print("  v-19 Enterprise — $100,000+/year site license")
        print()
        print("  Includes everything in Pro, plus:")
        print("    - Unlimited identities")
        print("    - CI/CD auto-remediation code generation")
        print("    - Blast radius scoring per attack chain")
        print("    - SOC 2 / HIPAA / POPIA compliance reports")
        print("    - Triple Jump chain analysis")
        print("    - Priority support + dedicated onboarding")
        print()
        print("  Contact: https://vyugard.tech/enterprise")

    print()
    print("  Free alternatives available now:")
    print("    v-19 analyze     Detect risks across clouds")
    print("    v-19 risks       View classified findings")
    print("    v-19 export      Export to JSON / CSV")
    print()
    print("=" * 72)
    print()


def print_identity_limit_warning(count: int, limit: int, tier: Tier):
    """Warn when identity count approaches or exceeds tier limit."""
    print()
    print("=" * 72)
    print(f"  IDENTITY LIMIT: {count} scanned / {limit} allowed ({TIER_FEATURES[tier]['label']})")
    print("=" * 72)
    print()
    print(f"  Your scan found {count} identities, exceeding your tier limit of {limit}.")
    print(f"  Results are truncated to the first {limit} identities.")
    print()

    if tier == Tier.COMMUNITY:
        print("  Upgrade to Pro to scan up to 500 identities:")
        print("    https://vyugard.tech/pro")
    elif tier == Tier.PRO:
        print("  Upgrade to Enterprise for unlimited identities:")
        print("    https://vyugard.tech/enterprise")

    print()
    print("=" * 72)
    print()
