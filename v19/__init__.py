"""
v19 — Public Python API

Use this package to integrate the v-19 engine into your own applications:

    from v19 import Scanner, BridgeDetector
    from v19.engine import V19RiskScorer, RiskLevel
    from v19.providers import AWSScanner, AzureScanner
"""

from pkg.engine.scanner import V19RiskScorer, RiskFinding, RiskLevel
from pkg.engine.bridges import BridgeDetector, CloudBridge
from pkg.providers.aws import AWSScanner, AWSIdentity
from pkg.providers.azure import AzureScanner, AzureIdentity
from pkg.providers.gcp import GCPScanner, GCPIdentity
from pkg.providers.kubernetes import KubernetesScanner, K8sIdentity

Scanner = V19RiskScorer  # convenience alias

__version__ = "1.0.0"
__all__ = [
    "Scanner",
    "V19RiskScorer",
    "RiskFinding",
    "RiskLevel",
    "BridgeDetector",
    "CloudBridge",
    "AWSScanner",
    "AWSIdentity",
    "AzureScanner",
    "AzureIdentity",
    "GCPScanner",
    "GCPIdentity",
    "KubernetesScanner",
    "K8sIdentity",
]
