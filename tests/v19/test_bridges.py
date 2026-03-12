"""
Tests for pkg.engine.bridges — Bridge Detection
"""

import pytest
from pkg.engine.bridges import BridgeDetector, CloudBridge


class TestBridgeDetector:
    def test_init(self):
        detector = BridgeDetector()
        assert detector is not None

    def test_detect_no_identities(self):
        detector = BridgeDetector()
        bridges = detector.detect_bridges()
        assert bridges == []

    def test_get_summary_empty(self):
        detector = BridgeDetector()
        summary = detector.get_summary([])
        assert summary["total_bridges"] == 0
        assert summary["cloud_pairs"] == []


class TestCloudBridge:
    def test_dataclass(self):
        bridge = CloudBridge(
            source_cloud="aws",
            target_cloud="azure",
            bridge_type="federation",
            risk_level="HIGH",
        )
        assert bridge.source_cloud == "aws"
        assert bridge.target_cloud == "azure"
