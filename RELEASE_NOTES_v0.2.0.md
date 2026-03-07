## MCPShield v0.2.0

This release introduces extensible plugin checks with layered trust controls, plus stronger release and security documentation.

### Highlights

- Added plugin check support (`--plugins`) for both `scan` and `scan-batch`
- Added explicit plugin opt-in gate:
  - `--allow-plugins` required before any plugin loading
- Added plugin trust controls:
  - `--allow-plugin-origin` path-prefix allowlist
  - `--plugin-lock` SHA256 lockfile enforcement
  - `plugin-manifest` command to generate lock manifests
- Added plugin safety isolation:
  - plugin exceptions are converted into findings (scan continues)
  - plugin timeouts are converted into findings (scan continues)
  - invalid plugin return types are converted into findings
- Added plugin check-id namespace validation:
  - must start with `plugin_` or `<module>_`
- Added trusted plugin CI path:
  - committed trusted demo plugin
  - committed `plugins.lock`
  - CI now validates plugin run with allowlist + lock enforcement

### Architecture / Validation Improvements

- Added check registry integration for plugin checks
- Rules validation now supports plugin check IDs
- `scan --list-checks` reflects active plugin checks as well
- Expanded automated tests for plugin loading, safety, trust controls, and CLI end-to-end plugin flows

### Documentation / Release Hygiene

- Added root `CHANGELOG.md`
- Added root `SECURITY.md` with plugin threat model and recommended controls
- Updated package/repo version metadata to `0.2.0`

### Recommended Secure Plugin Usage

```bash
python -m mcpshield.cli plugin-manifest ./plugins/trusted --out ./plugins.lock

python -m mcpshield.cli scan-batch ./fixtures \
  --allow-plugins \
  --plugins ./plugins/trusted \
  --allow-plugin-origin ./plugins/trusted \
  --plugin-lock ./plugins.lock \
  --summary-only --out ./out
```

### Notes

- MCPShield remains offline-first and static-analysis oriented.
- Plugin execution is powerful and should be treated as privileged code; use allowlists and lockfiles by default.
