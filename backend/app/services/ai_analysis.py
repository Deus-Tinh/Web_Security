from app.models.scan import Severity
from app.scanners.base import Finding


class AIAnalysisEngine:
    """Rule-based adapter designed so hosted AI APIs can be plugged in later."""

    async def enrich(self, finding: Finding) -> Finding:
        if finding.category == "SQL Injection":
            finding.recommendation += " Add regression tests that prove malicious input is treated as data."
        if finding.severity in {Severity.CRITICAL, Severity.HIGH}:
            finding.metadata = {**(finding.metadata or {}), "ai_priority": "Immediate triage recommended"}
        return finding

    async def summarize_risk(self, severities: list[Severity]) -> int:
        weights = {
            Severity.CRITICAL: 35,
            Severity.HIGH: 25,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }
        return min(100, sum(weights[item] for item in severities))

