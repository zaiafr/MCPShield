# MCPShield

Offline-first MCP policy and trust scanner for CI and local review.

It produces:
- ordered findings
- a numeric score from `0-100`
- a risk level: `low`, `medium`, `high`, or `critical`
- JSON, Markdown, CSV, and delta reports for local review or CI

## Table of Contents

- [What It Checks](#what-it-checks)
- [Positioning](#positioning)
- [Install](#install)
- [Quick Start](#quick-start)
- [Detailed Process](#detailed-process)
- [Supported Inputs](#supported-inputs)
- [Rules and Tuning](#rules-and-tuning)
- [Plugins](#plugins)
- [Outputs](#outputs)
- [Development](#development)

## What It Checks

The current scanner focuses on static signals that are easy to automate and useful in triage:

- dangerous tools and capability keywords
- risky runtime command hints
- SSRF-style URL fetch behavior
- token passthrough and auth gaps
- overly broad OAuth scopes
- missing least-privilege, tenant isolation, and audit logging metadata
- destructive tools without explicit confirmation metadata
- stale release metadata
- unpinned or vulnerable dependency versions
- missing security metadata and local documentation files

This is a first-pass static scanner. It does not execute server code and it can produce false positives.

## Positioning

MCPShield is strongest as an offline-first policy and trust scanner, not as a generic "scan everything MCP" product.

- Primary wedge: local and CI-friendly policy gates for MCP inventories
- Strong differentiators: offline-first workflow, configurable rules, batch summaries/diffs, and plugin trust controls
- Competitive landscape and rationale: [docs/positioning.md](docs/positioning.md)

## Install

### Run from this repo

```bash
pip install 'PyYAML>=6.0'
PYTHONPATH=src python3 -m mcpshield.cli --version
```

### Install as a CLI

```bash
pip install -e .
mcpshield --version
```

## Quick Start

Scan the included sample directory:

```bash
python -m mcpshield.cli scan ./samples --format both --out ./out
```

List available checks:

```bash
python -m mcpshield.cli scan --list-checks --rules ./rules.yml
```

Use custom rules:

```bash
python -m mcpshield.cli scan ./samples --rules ./rules.yml --format both --out ./out
```

If you installed the package, replace `python -m mcpshield.cli` with `mcpshield`.

## Detailed Process

This project works best when you use it as a small review pipeline instead of a single command.

### 1. Point the scanner at a target

Use one of the supported target types:

- a local directory containing `server.json`
- a local `server.json` file
- an HTTP(S) URL to `server.json`
- an npm package name

Example:

```bash
python -m mcpshield.cli scan ./samples --out ./out
```

### 2. Review the findings and score

Built-in check catalog:
- [docs/checks.md](docs/checks.md)

The scanner writes deterministic reports so diffs stay stable across runs:

- `*.risk.json` for machine processing
- `*.risk.md` for human review

Example output files:

```text
out/
  samples.risk.json
  samples.risk.md
```

### 3. Tune the policy with `rules.yml`

Use a rules file to:

- disable checks
- override severities
- change thresholds such as stale release age
- customize keyword lists

Example:

```bash
python -m mcpshield.cli scan ./samples --rules ./rules.yml --out ./out
```

### 4. Scale to multiple targets

`scan-batch` expects a directory where each immediate child directory is a scan target and contains its own `server.json`.

Expected layout:

```text
batch-input/
  alpha/
    server.json
  beta/
    server.json
    package.json
```

Run it like this:

```bash
python -m mcpshield.cli scan-batch ./batch-input --format both --out ./out
```

For batch runs, the scanner also writes:

- `summary.json`
- `summary.md`
- `summary.csv`

### 5. Add CI-style quality gates

Use batch mode to fail when risk crosses a threshold:

```bash
python -m mcpshield.cli scan-batch ./batch-input --out ./out --fail-on-critical --min-score 70
```

### 6. Track regressions between runs

Compare two `summary.csv` files to generate a delta report:

```bash
python -m mcpshield.cli compare-summaries ./baseline/summary.csv ./current/summary.csv --out ./out
```

This writes:

- `delta.json`
- `delta.md`

### 7. Extend checks with plugins only when trust is explicit

Plugin loading is opt-in because plugin code runs as Python code.

Generate a plugin lock file:

```bash
python -m mcpshield.cli plugin-manifest ./plugins/trusted --out ./plugins.lock
```

Run with trust controls enabled:

```bash
python -m mcpshield.cli scan ./samples \
  --allow-plugins \
  --plugins ./plugins/trusted \
  --allow-plugin-origin ./plugins/trusted \
  --plugin-lock ./plugins.lock \
  --out ./out
```

## Supported Inputs

### Local directory

The directory must contain `server.json`. If `package.json` is present, it is used automatically.

```bash
python -m mcpshield.cli scan ./samples --out ./out
```

### Local file

Only files named `server.json` are accepted for direct file scans.

```bash
python -m mcpshield.cli scan ./samples/server.json --out ./out
```

Reports include the applied rules source path so review output remains attributable.

### Remote URL

```bash
python -m mcpshield.cli scan https://example.com/server.json --out ./out
```

### npm package

The scanner fetches npm metadata and uses the latest tagged package version as a best-effort source.

```bash
python -m mcpshield.cli scan @scope/package-name --out ./out
```

## Rules and Tuning

`rules.yml` lets you adjust built-in policy without changing code.

Supported sections:

- `checks`: enable or disable individual checks
- `severity_overrides`: remap check severity
- `thresholds`: adjust numeric thresholds
- `keywords`: extend keyword-based detectors

Example:

```yaml
checks:
  dangerous_tools:
    enabled: true

severity_overrides:
  missing_docs: medium

thresholds:
  stale_release_days: 180
```

## Plugins

The plugin system is for custom checks that are not appropriate to hard-code into the base scanner.

Security model:

- plugin execution is disabled unless `--allow-plugins` is set
- plugin paths can be restricted with `--allow-plugin-origin`
- plugin contents can be pinned with `--plugin-lock`
- plugin failures are isolated into findings instead of crashing the full scan

A plugin module must expose either:

- `CHECKS`
- `get_checks()`

Each check must define:

- `check_id`
- `default_severity`
- `runner`

See [docs/plugins.md](/home/zaina/personal/mcp/docs/plugins.md) and `plugins/examples/`.

## Outputs

### Single target

- `<target>.risk.json`
- `<target>.risk.md`

### Batch mode

- per-target reports unless `--summary-only` is used
- `summary.json`
- `summary.md`
- `summary.csv`

### Summary comparison

- `delta.json`
- `delta.md`

Findings are written in deterministic order: severity first, then `check_id`.

## Development

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -q
```

Project docs:

- [CONTRIBUTING.md](/home/zaina/personal/mcp/CONTRIBUTING.md)
- [SECURITY.md](/home/zaina/personal/mcp/SECURITY.md)
- [CHANGELOG.md](/home/zaina/personal/mcp/CHANGELOG.md)
