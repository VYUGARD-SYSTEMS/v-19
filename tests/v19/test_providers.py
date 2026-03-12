"""
Tests for pkg.providers — Cloud Scanner Imports
"""

import pytest


def test_aws_scanner_import():
    from pkg.providers.aws import AWSScanner, AWSIdentity
    assert AWSScanner is not None
    assert AWSIdentity is not None


def test_azure_scanner_import():
    from pkg.providers.azure import AzureScanner, AzureIdentity
    assert AzureScanner is not None
    assert AzureIdentity is not None


def test_gcp_scanner_import():
    from pkg.providers.gcp import GCPScanner, GCPIdentity
    assert GCPScanner is not None
    assert GCPIdentity is not None


def test_kubernetes_scanner_import():
    from pkg.providers.kubernetes import KubernetesScanner, K8sIdentity
    assert KubernetesScanner is not None
    assert K8sIdentity is not None
