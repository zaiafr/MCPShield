# Security Policy

## Reporting a Vulnerability

If you believe you found a security issue in MCPShield, report it privately via repository security advisories or direct maintainer contact.

Please include:
- Affected version/tag
- Reproduction steps
- Impact assessment
- Suggested mitigation (if known)

## Plugin Security Model

Plugin execution is a high-risk extension point. Treat plugin code as privileged code.

Recommended controls:
- Require explicit opt-in with `--allow-plugins`.
- Restrict plugin source paths using `--allow-plugin-origin`.
- Pin plugin file hashes with `--plugin-lock` and regenerate only through review (`plugin-manifest`).
- Keep trusted plugins in a reviewed directory (for example `./plugins/trusted`).
- Run plugin-enabled scans in isolated CI/runtime environments.

Built-in safeguards:
- Plugin check id namespace validation.
- Per-plugin failure isolation (exceptions become findings).
- Plugin timeout isolation (slow plugins become findings).

## Supported Versions

- `0.2.x`: active
- `<0.2.0`: best-effort only
