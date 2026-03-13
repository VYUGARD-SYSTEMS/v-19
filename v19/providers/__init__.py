"""v19.providers — Cloud provider scanners."""

from pkg.providers.aws import AWSScanner, AWSIdentity
from pkg.providers.azure import AzureScanner, AzureIdentity
from pkg.providers.gcp import GCPScanner, GCPIdentity
from pkg.providers.kubernetes import KubernetesScanner, K8sIdentity

__all__ = [
    "AWSScanner", "AWSIdentity",
    "AzureScanner", "AzureIdentity",
    "GCPScanner", "GCPIdentity",
    "KubernetesScanner", "K8sIdentity",
]
