# Plugin Guide

MCPShield supports custom checks through Python plugin modules.

## Security First

Plugin code is privileged code. Always use trust controls when loading plugins:

```bash
python -m mcp_risk_scanner.cli scan ./samples \
  --allow-plugins \
  --plugins ./plugins/trusted \
  --allow-plugin-origin ./plugins/trusted \
  --plugin-lock ./plugins.lock \
  --out ./out
```

Recommended defaults:
- Keep trusted plugins under a reviewed directory (`./plugins/trusted`).
- Use `plugin-manifest` to generate and update `plugins.lock`.
- Require PR review for plugin changes.

## Plugin Module Format

A plugin module must expose either:
- `CHECKS` (list), or
- `get_checks()` returning a list.

Each check entry must include:
- `check_id` (string): must start with `plugin_` or `<module>_`
- `default_severity` (`critical|high|medium|low`)
- `runner` (callable): signature `runner(scan_input) -> list[Finding]`

## Runner Behavior

Plugin runners are sandboxed by policy in the scanner runtime:
- Exceptions are converted into findings (scan continues).
- Slow checks are timeout-isolated into findings.
- Invalid return types are converted into findings.

## Example Layout

- `plugins/examples/plugin_todo_tag.py`
- `plugins/examples/plugin_file_count.py`

## Generate Lock File

```bash
python -m mcp_risk_scanner.cli plugin-manifest ./plugins/trusted --out ./plugins.lock
```

## List All Checks (Built-in + Plugin)

```bash
python -m mcp_risk_scanner.cli scan --list-checks \
  --allow-plugins \
  --plugins ./plugins/trusted
```
