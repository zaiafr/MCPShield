# Changelog

All notable changes to this project will be documented in this file.

## [0.2.2] - 2026-03-07
### Added
- SARIF export for `scan` and `scan-batch` via `--sarif`.
- Per-target `.risk.sarif` artifacts for single scans and non-summary batch runs.
- Aggregate `summary.sarif` output for batch workflows.

### Changed
- CI quality-gate examples now validate SARIF artifact generation.
- README now documents SARIF output as the preferred machine-readable CI artifact.

## [0.2.1] - 2026-03-07
### Added
- Built-in check catalog in `docs/checks.md`.
- Documentation tests that keep README and check-catalog references aligned.
- Example plugin coverage through direct tests and end-to-end CLI flows.

### Changed
- Public docs and CI examples now default to the `mcpshield` CLI command.
- README examples were cleaned up to favor the installed CLI over Python module invocation.

### Removed
- Internal-only positioning notes from the public repository docs.

## [0.2.0] - 2026-03-06
### Added
- Plugin support for custom checks via `--plugins`.
- Plugin opt-in safety gate via `--allow-plugins`.
- Plugin trust controls:
  - `--allow-plugin-origin` path prefix restrictions
  - `--plugin-lock` sha256 hash pinning
  - `plugin-manifest` command to generate lock manifests
- Plugin safety isolation:
  - check timeout handling
  - exception isolation to findings
  - namespace validation for plugin `check_id`
- Check registry architecture and `scan --list-checks` introspection.
- Rules validation support for plugin check ids.
- Structured `evidence_data` in JSON findings.
- End-to-end CLI tests and trusted-plugin CI path.

### Changed
- Rules parsing now uses `PyYAML` with clearer malformed-config errors.
- CI now runs package install smoke checks and plugin trust-path scans.

## [0.1.1] - 2026-03-06
### Added
- Configurable `rules.yml` with check toggles, severity overrides, and threshold controls.
- Batch summary CSV export and summary-only batch mode.
- Batch quality gates (`--fail-on-critical`, `--min-score`).
- Summary delta comparison command (`compare-summaries`).

## [0.1.0] - 2026-03-06
### Added
- Initial offline-first MCP scanner CLI.
- Single-target and batch risk reporting.
- Core rule checks for auth, network, dependency, and governance hygiene.
