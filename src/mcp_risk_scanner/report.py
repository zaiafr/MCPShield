from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ScanResult


def render_json(result: ScanResult) -> str:
    payload = {
        "target": result.target,
        "source_type": result.source_type,
        "rules_source": result.rules_source,
        "score": result.score,
        "risk_level": result.risk_level,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "message": f.message,
                "evidence": f.evidence,
                "evidence_data": f.evidence_data,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# MCP Server Risk Report",
        "",
        f"- Target: `{result.target}`",
        f"- Source: `{result.source_type}`",
        f"- Rules: `{result.rules_source or 'default'}`",
        f"- Score: **{result.score}/100**",
        f"- Risk Level: **{result.risk_level.upper()}**",
        "",
    ]

    if not result.findings:
        lines.extend(["No findings detected.", ""])
        return "\n".join(lines)

    lines.extend([
        "## Findings",
        "",
        "| Severity | Check | Category | Evidence |",
        "|---|---|---|---|",
    ])

    for finding in result.findings:
        evidence = finding.evidence.replace("|", "\\|")
        lines.append(
            f"| {finding.severity} | {finding.title} | {finding.category} | {evidence} |"
        )

    lines.extend(["", "## Recommended Next Actions", ""])

    top = sorted(result.findings, key=lambda f: _severity_rank(f.severity), reverse=True)[:3]
    for idx, finding in enumerate(top, start=1):
        lines.append(f"{idx}. **{finding.title}**: {finding.remediation}")

    lines.append("")
    return "\n".join(lines)


def _severity_rank(severity: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return ranks.get(severity, 0)
