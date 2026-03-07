## MCPShield v0.2.1

This release tightens the public interface and documentation around MCPShield without changing the core scanner model.

### Highlights

- Added a built-in check catalog in `docs/checks.md`
- Added regression tests to keep documentation and check listings aligned
- Added stronger coverage for example plugins through direct and CLI-level tests
- Standardized public docs and CI examples around the `mcpshield` CLI command
- Removed internal-only positioning notes from the public docs

### Notes

- MCPShield remains an offline-first static scanner for MCP server metadata and package hygiene
- The preferred public interface is now:

```bash
mcpshield scan ./samples --format both --out ./out
```

- The Python module form remains available for local development fallback:

```bash
PYTHONPATH=src python3 -m mcpshield.cli scan ./samples --format both --out ./out
```
