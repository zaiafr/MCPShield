# MCP Risk Scanner (Phase 1)

A narrow MVP scanner that analyzes MCP server metadata and package manifests to generate:
- risk findings
- a numeric risk score (0-100)
- JSON and Markdown reports

## Quick start

```bash
python -m mcp_risk_scanner.cli scan ./samples/insecure-server.json --format both --out ./out
```

Show CLI version:

```bash
python -m mcp_risk_scanner.cli --version
```

Use custom rules:

```bash
python -m mcp_risk_scanner.cli scan ./samples --rules ./rules.yml --format both --out ./out
```

List checks under current rules:

```bash
python -m mcp_risk_scanner.cli scan --list-checks --rules ./rules.yml
```

Or install as editable:

```bash
pip install -e .
mcp-risk-scan scan ./samples/insecure-server.json --format both --out ./out
```

Batch scan local fixtures:

```bash
python -m mcp_risk_scanner.cli scan-batch ./fixtures --format both --out ./out
```

Summary-only batch scan:

```bash
python -m mcp_risk_scanner.cli scan-batch ./fixtures --summary-only --out ./out
```

Batch scan with quality gates:

```bash
python -m mcp_risk_scanner.cli scan-batch ./fixtures --out ./out --fail-on-critical --min-score 70
```

Compare two batch summary CSV files:

```bash
python -m mcp_risk_scanner.cli compare-summaries ./baseline/summary.csv ./current/summary.csv --out ./out
```

## Supported inputs
- Local `server.json` file path
- Local directory containing `server.json` (optionally `package.json`)
- HTTP(S) URL to `server.json`
- npm package name (best-effort fetch from npm registry)
- Batch mode: directory with subdirectories that contain `server.json`

## Current checks (v1)
- Known vulnerable dependency versions (small built-in advisory set)
- Dangerous tool/capability keywords
- Potentially dangerous runtime commands
- SSRF-prone URL fetch hints
- Missing outbound network allowlist metadata
- Token passthrough behavior hints
- Missing auth metadata
- Overly broad OAuth scopes
- Missing least-privilege scope policy metadata
- Missing tenant-isolation metadata
- Missing audit logging metadata
- Destructive tools without explicit confirmation metadata
- Stale release metadata (older than 180 days)
- Unpinned dependencies (`*`, `latest`, broad ranges)
- Missing security metadata
- Missing changelog/security policy files (local directory scans)

## Notes
This is a first-pass static scanner. It does not execute code and can produce false positives.
Findings are output in deterministic order (severity, then check id) for stable diffs.
Batch mode also writes `summary.csv` with per-target score/risk rows.
Use `--fail-on-critical` and `--min-score` for CI-style pass/fail gates.
`compare-summaries` writes `delta.json` and `delta.md` for release-over-release tracking.
Rule config file defaults are in `rules.yml`; reports include the applied rules source path.
Rules validation rejects unknown `check_id`s in `checks` and `severity_overrides`.
Rules parsing uses `PyYAML` (`yaml.safe_load`) with clear validation errors.
