# MCP Risk Scanner (Phase 1)

A narrow MVP scanner that analyzes MCP server metadata and package manifests to generate:
- risk findings
- a numeric risk score (0-100)
- JSON and Markdown reports

## Quick start

```bash
python -m mcp_risk_scanner.cli scan ./samples/insecure-server.json --format both --out ./out
```

Or install as editable:

```bash
pip install -e .
mcp-risk-scan scan ./samples/insecure-server.json --format both --out ./out
```

## Supported inputs
- Local `server.json` file path
- Local directory containing `server.json` (optionally `package.json`)
- HTTP(S) URL to `server.json`
- npm package name (best-effort fetch from npm registry)

## Current checks (v1)
- Known vulnerable dependency versions (small built-in advisory set)
- Dangerous tool/capability keywords
- Potentially dangerous runtime commands
- SSRF-prone URL fetch hints
- Missing outbound network allowlist metadata
- Token passthrough behavior hints
- Missing auth metadata
- Overly broad OAuth scopes
- Stale release metadata (older than 180 days)
- Unpinned dependencies (`*`, `latest`, broad ranges)
- Missing security metadata
- Missing changelog/security policy files (local directory scans)

## Notes
This is a first-pass static scanner. It does not execute code and can produce false positives.
