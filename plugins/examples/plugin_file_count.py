from __future__ import annotations

from pathlib import Path

from mcp_risk_scanner.models import Finding


def check(scan_input):
    if not scan_input.root_dir:
        return []

    root = Path(scan_input.root_dir)
    py_count = len(list(root.glob("**/*.py")))
    if py_count <= 20:
        return []

    return [
        Finding(
            check_id="plugin_file_count",
            title="Large plugin/project footprint detected",
            severity="low",
            category="plugin",
            message="Project contains many Python files.",
            evidence=f"python_file_count={py_count}",
            remediation="Consider splitting modules and reviewing plugin surface area.",
            evidence_data={"python_file_count": py_count},
        )
    ]


CHECKS = [
    {
        "check_id": "plugin_file_count",
        "default_severity": "low",
        "runner": check,
    }
]
