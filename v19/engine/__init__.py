"""v19.engine — Detection and scoring engine."""

from pkg.engine.scanner import V19RiskScorer, RiskFinding, RiskLevel
from pkg.engine.bridges import BridgeDetector, CloudBridge

Scanner = V19RiskScorer

__all__ = ["Scanner", "V19RiskScorer", "RiskFinding", "RiskLevel", "BridgeDetector", "CloudBridge"]
