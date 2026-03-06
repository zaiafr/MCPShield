from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Finding, ScanInput


DANGEROUS_KEYWORDS = {
    "exec": "Command execution capability",
    "shell": "Shell execution capability",
    "bash": "Shell command reference",
    "powershell": "Shell command reference",
    "terminal": "Terminal access capability",
    "filesystem": "Filesystem capability",
    "file write": "File write capability",
    "delete": "Destructive operation keyword",
    "fetch": "Network fetch capability",
    "http": "Network access capability",
    "git_init": "Git initialization on arbitrary path is risky",
}

KNOWN_VULNERABLE_PACKAGES = [
    {
        "name": "@modelcontextprotocol/server-git",
        "constraint": "<2025.9.25",
        "severity": "critical",
        "cve": "CVE-2025-68143",
        "reason": "Known path handling vulnerability in git_init",
    },
    {
        "name": "lodash",
        "constraint": "<4.17.21",
        "severity": "high",
        "cve": "Multiple advisories",
        "reason": "Known vulnerable lodash versions",
    },
    {
        "name": "minimist",
        "constraint": "<1.2.6",
        "severity": "high",
        "cve": "Prototype pollution advisories",
        "reason": "Known vulnerable minimist versions",
    },
]


def run_checks(scan_input: ScanInput) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_check_dangerous_tools(scan_input.server_json))
    findings.extend(_check_runtime_command(scan_input.server_json))
    findings.extend(_check_auth_presence(scan_input.server_json))
    findings.extend(_check_broad_scopes(scan_input.server_json))
    findings.extend(_check_dependencies(scan_input.package_json))
    findings.extend(_check_security_metadata(scan_input.server_json))
    findings.extend(_check_local_hygiene(scan_input.root_dir))
    return findings


def _check_dangerous_tools(server_json: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    tools = server_json.get("tools", [])
    if not isinstance(tools, list):
        return findings

    hit_tools: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        blob = " ".join(
            str(v).lower() for v in [tool.get("name", ""), tool.get("description", "")]
        )
        if any(keyword in blob for keyword in DANGEROUS_KEYWORDS):
            hit_tools.append(str(tool.get("name", "unknown")))

    if hit_tools:
        findings.append(
            Finding(
                check_id="dangerous_tools",
                title="Potentially dangerous tools exposed",
                severity="high",
                category="capability",
                message="Tool metadata indicates privileged or risky capabilities.",
                evidence=f"Flagged tools: {', '.join(hit_tools[:10])}",
                remediation=(
                    "Restrict high-risk tools by default, add allowlists, and enforce explicit approval "
                    "for write/exec/network operations."
                ),
            )
        )

    return findings


def _check_runtime_command(server_json: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    command = str(server_json.get("command", "")).lower()
    args = " ".join(map(str, server_json.get("args", []))).lower()
    combined = f"{command} {args}".strip()

    risky_runtimes = ["bash", "sh", "powershell", "cmd.exe", "python -c", "node -e"]
    if any(runtime in combined for runtime in risky_runtimes):
        findings.append(
            Finding(
                check_id="runtime_command",
                title="Potentially risky runtime command",
                severity="medium",
                category="runtime",
                message="Server launch command includes shell-style execution patterns.",
                evidence=f"Command: {combined}",
                remediation="Use direct executable entrypoints and avoid dynamic shell evaluation.",
            )
        )

    return findings


def _check_auth_presence(server_json: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    auth = server_json.get("auth") or server_json.get("oauth") or server_json.get("security")
    if not auth:
        findings.append(
            Finding(
                check_id="auth_missing",
                title="Missing auth metadata",
                severity="medium",
                category="auth",
                message="No auth or OAuth metadata detected in server descriptor.",
                evidence="Fields auth/oauth/security are absent",
                remediation="Define OAuth metadata, supported flows, and minimum required scopes.",
            )
        )
    return findings


def _check_broad_scopes(server_json: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    auth_blob = str(server_json.get("auth", "")) + " " + str(server_json.get("oauth", ""))
    auth_blob = auth_blob.lower()
    broad_markers = ["*", "admin", "write:all", "full_access", "root"]
    matches = [marker for marker in broad_markers if marker in auth_blob]
    if matches:
        findings.append(
            Finding(
                check_id="broad_scopes",
                title="Overly broad scopes detected",
                severity="high",
                category="auth",
                message="Auth metadata appears to include broad privilege scopes.",
                evidence=f"Matched scope markers: {', '.join(matches)}",
                remediation="Split scopes by action/resource and default to least privilege.",
            )
        )
    return findings


def _check_dependencies(package_json: dict[str, Any] | None) -> list[Finding]:
    if not package_json:
        return []

    findings: list[Finding] = []
    deps: dict[str, str] = {}
    for section in ["dependencies", "devDependencies", "optionalDependencies"]:
        section_map = package_json.get(section, {})
        if isinstance(section_map, dict):
            deps.update({k: str(v) for k, v in section_map.items()})

    if not deps:
        return findings

    unpinned = [name for name, version in deps.items() if _is_unpinned(version)]
    if unpinned:
        findings.append(
            Finding(
                check_id="unpinned_deps",
                title="Unpinned dependency versions",
                severity="medium",
                category="supply_chain",
                message="Broad dependency ranges reduce reproducibility and can pull risky updates.",
                evidence=f"Examples: {', '.join(unpinned[:10])}",
                remediation="Pin production dependencies to exact versions and update via controlled bumps.",
            )
        )

    for advisory in KNOWN_VULNERABLE_PACKAGES:
        dep_version = deps.get(advisory["name"])
        if dep_version and _matches_constraint(dep_version, advisory["constraint"]):
            findings.append(
                Finding(
                    check_id=f"cve_{advisory['name']}",
                    title="Known vulnerable dependency version",
                    severity=advisory["severity"],
                    category="supply_chain",
                    message=advisory["reason"],
                    evidence=(
                        f"{advisory['name']}@{dep_version} matched {advisory['constraint']} "
                        f"({advisory['cve']})"
                    ),
                    remediation="Upgrade to a patched version and add dependency scanning in CI.",
                )
            )

    return findings


def _check_security_metadata(server_json: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    has_security = any(k in server_json for k in ["security", "securityPolicy", "contact"])
    if not has_security:
        findings.append(
            Finding(
                check_id="security_metadata",
                title="Missing security metadata",
                severity="low",
                category="governance",
                message="No security policy/contact metadata was found.",
                evidence="Expected one of: security, securityPolicy, contact",
                remediation="Add a security contact and disclosure policy reference.",
            )
        )
    return findings


def _check_local_hygiene(root_dir: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not root_dir:
        return findings

    root = Path(root_dir)
    required_docs = {
        "SECURITY.md": "Add SECURITY.md with disclosure/reporting workflow.",
        "CHANGELOG.md": "Add CHANGELOG.md to track security-impacting releases.",
    }

    missing = [name for name in required_docs if not (root / name).exists()]
    if missing:
        findings.append(
            Finding(
                check_id="missing_docs",
                title="Missing security/release hygiene docs",
                severity="low",
                category="governance",
                message="Local project is missing recommended security/release documents.",
                evidence=f"Missing files: {', '.join(missing)}",
                remediation=" ".join(required_docs[name] for name in missing),
            )
        )

    return findings


def _is_unpinned(version: str) -> bool:
    lowered = version.strip().lower()
    if lowered in {"*", "latest"}:
        return True
    return lowered.startswith("^") or lowered.startswith("~")


def _matches_constraint(version: str, constraint: str) -> bool:
    # Minimal semver comparison for constraints of shape <x.y.z[.w]
    if not constraint.startswith("<"):
        return False

    threshold = constraint[1:]
    version_core = _extract_version_numbers(version)
    threshold_core = _extract_version_numbers(threshold)
    if not version_core or not threshold_core:
        return False

    length = max(len(version_core), len(threshold_core))
    version_tuple = tuple(version_core + [0] * (length - len(version_core)))
    threshold_tuple = tuple(threshold_core + [0] * (length - len(threshold_core)))
    return version_tuple < threshold_tuple


def _extract_version_numbers(raw: str) -> list[int]:
    cleaned = raw.strip()
    while cleaned and cleaned[0] in "^~<>=v":
        cleaned = cleaned[1:]

    token = cleaned.split("-")[0].split("+")[0]
    parts = token.split(".")
    numbers: list[int] = []
    for part in parts:
        if not part.isdigit():
            return []
        numbers.append(int(part))
    return numbers
