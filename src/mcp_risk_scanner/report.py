from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

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


def render_sarif(result: ScanResult) -> str:
    return render_batch_sarif([result])


def render_batch_sarif(results: list[ScanResult]) -> str:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for result in results:
        artifact_uri = _artifact_uri(result.target)
        for finding in result.findings:
            rules.setdefault(
                finding.check_id,
                {
                    "id": finding.check_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.message},
                    "help": {"text": finding.remediation},
                    "defaultConfiguration": {"level": _sarif_level(finding.severity)},
                    "properties": {
                        "category": finding.category,
                        "severity": finding.severity,
                    },
                },
            )
            sarif_results.append(
                {
                    "ruleId": finding.check_id,
                    "level": _sarif_level(finding.severity),
                    "message": {
                        "text": f"{finding.message} Evidence: {finding.evidence}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri}
                            }
                        }
                    ],
                    "properties": {
                        "target": result.target,
                        "risk_level": result.risk_level,
                        "score": result.score,
                        "category": finding.category,
                        "evidence_data": finding.evidence_data,
                    },
                }
            )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPShield",
                        "informationUri": "https://github.com/zaiafr/MCPShield",
                        "rules": sorted(rules.values(), key=lambda item: item["id"]),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _severity_rank(severity: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return ranks.get(severity, 0)


def _sarif_level(severity: str) -> str:
    levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return levels.get(severity, "warning")


def _artifact_uri(target: str) -> str:
    path = Path(target)
    return path.as_posix() if path.exists() else target
