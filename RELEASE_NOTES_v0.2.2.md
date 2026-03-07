## MCPShield v0.2.2

This release adds SARIF export for CI and code-scanning workflows.

### Highlights

- Added `--sarif` support to both `scan` and `scan-batch`
- Single-target scans can now write `<target>.risk.sarif`
- Batch scans can now write `summary.sarif` for machine-readable CI consumption
- CI examples now exercise SARIF generation directly

### Example

```bash
mcpshield scan ./samples --sarif --out ./out
mcpshield scan-batch ./fixtures --summary-only --sarif --out ./out
```

### Notes

- SARIF complements existing JSON and Markdown outputs; it does not replace them
- The preferred public CLI remains `mcpshield`
