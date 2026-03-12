"""
Tests for pkg.engine — Scanner and Bridge Detection
"""

import pytest
from pkg.engine.scanner import V19RiskScorer, RiskFinding, RiskLevel


class TestRiskLevel:
    def test_severity_values(self):
        assert RiskLevel.CRITICAL.value == "CRITICAL"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.LOW.value == "LOW"


class TestRiskFinding:
    def test_sort_key_ordering(self):
        critical = RiskFinding(
            finding_id="T-001", title="Critical",
            risk_level=RiskLevel.CRITICAL, cloud="aws",
            identity_name="admin", reason="test",
        )
        low = RiskFinding(
            finding_id="T-002", title="Low",
            risk_level=RiskLevel.LOW, cloud="aws",
            identity_name="viewer", reason="test",
        )
        assert critical.sort_key > low.sort_key

    def test_to_dict(self):
        f = RiskFinding(
            finding_id="T-001", title="Test",
            risk_level=RiskLevel.HIGH, cloud="gcp",
            identity_name="sa-test", reason="testing",
        )
        d = f.to_dict()
        assert d["finding_id"] == "T-001"
        assert d["risk_level"] == "HIGH"
        assert "risk_score" not in d


class TestV19RiskScorer:
    def test_init(self):
        scorer = V19RiskScorer()
        assert scorer is not None

    def test_score_all_empty(self):
        scorer = V19RiskScorer()
        findings = scorer.score_all()
        assert findings == []
