from __future__ import annotations

from mcp_risk_scanner.models import Finding


def check(scan_input):
    text = str(scan_input.server_json)
    if "TODO" not in text:
        return []

    return [
        Finding(
            check_id="plugin_todo_tag",
            title="TODO marker found in server metadata",
            severity="low",
            category="plugin",
            message="Server metadata includes a TODO marker.",
            evidence="TODO token detected in server.json content",
            remediation="Remove TODO markers or track them outside production metadata.",
            evidence_data={"token": "TODO"},
        )
    ]


CHECKS = [
    {
        "check_id": "plugin_todo_tag",
        "default_severity": "low",
        "runner": check,
    }
]
