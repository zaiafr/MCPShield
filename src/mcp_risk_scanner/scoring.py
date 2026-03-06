from __future__ import annotations

from .models import Finding, SEVERITY_WEIGHTS


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHTS.get(finding.severity, 0)
    score = max(0, score)
    return score, _risk_level(score)


def _risk_level(score: int) -> str:
    if score >= 85:
        return "low"
    if score >= 65:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"
