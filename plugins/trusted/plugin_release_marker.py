from mcp_risk_scanner.models import Finding


def check(scan_input):
    # Demo trusted plugin: emits an informational finding proving plugin path works.
    return [
        Finding(
            check_id="plugin_release_marker",
            title="Trusted Plugin Loaded",
            severity="low",
            category="plugin",
            message="Trusted plugin executed successfully.",
            evidence="plugin_release_marker executed",
            remediation="None required.",
            evidence_data={"plugin": "release_marker"},
        )
    ]


CHECKS = [
    {
        "check_id": "plugin_release_marker",
        "default_severity": "low",
        "runner": check,
    }
]
