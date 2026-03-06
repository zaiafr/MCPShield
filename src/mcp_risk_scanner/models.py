from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
}


@dataclass(slots=True)
class ScanInput:
    target: str
    source_type: str
    server_json: dict[str, Any]
    package_json: dict[str, Any] | None = None
    root_dir: str | None = None
    raw_sources: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    check_id: str
    title: str
    severity: str
    category: str
    message: str
    evidence: str
    remediation: str
    evidence_data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanResult:
    target: str
    source_type: str
    score: int
    risk_level: str
    findings: list[Finding]
    rules_source: str | None = None
