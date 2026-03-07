# Built-in Checks

This catalog covers the built-in `check_id` values returned by `scan --list-checks`. Plugin checks are intentionally excluded.

## `dangerous_tools`
Flags tool names or descriptions that imply risky capabilities such as shell execution, file writes, destructive actions, or arbitrary network access. False-positive caveats: broad wording in demo or placeholder tool descriptions can trigger this check.

## `runtime_command`
Flags launch commands and arguments that contain risky execution patterns such as `bash`, `sh`, `powershell`, `cmd.exe`, `python -c`, or `node -e`. False-positive caveats: some development-only wrappers look risky in metadata even when disabled in production.

## `ssrf_hint`
Flags tool metadata that suggests fetching arbitrary or user-supplied URLs. False-positive caveats: documentation text can mention URL behavior without exposing a true arbitrary fetch path.

## `missing_network_allowlist`
Flags network-capable tools when no `networkAllowlist` or `allowedHosts` metadata is present. False-positive caveats: enforcement may exist in code even if it is not declared in metadata.

## `token_passthrough_hint`
Flags text that suggests forwarding bearer or access tokens downstream. False-positive caveats: explanatory security docs can mention token forwarding without enabling it.

## `destructive_tool_confirmation_missing`
Flags destructive operations such as delete, remove, drop, destroy, refund, or cancel when no confirmation marker is declared. False-positive caveats: external confirmation steps are not visible unless they are described in metadata.

## `auth_missing`
Flags targets that omit `auth`, `oauth`, and `security` metadata entirely. False-positive caveats: a private server can still enforce auth outside of metadata, but the scanner treats missing declarations as risk.

## `broad_scopes`
Flags auth metadata that includes broad markers such as `*`, `admin`, `write:all`, `full_access`, or `root`. False-positive caveats: some legacy scope names are broad by label but narrower in implementation.

## `least_privilege_missing`
Flags auth-enabled targets that do not declare least-privilege guidance or metadata. False-positive caveats: teams may follow least-privilege in practice without expressing it in `server.json`.

## `tenant_isolation_missing`
Flags auth-enabled targets that do not declare tenant isolation metadata. False-positive caveats: single-tenant systems may not need explicit tenant isolation, but the scanner cannot infer deployment model.

## `audit_logging_missing`
Flags auth-enabled targets that do not declare audit logging or event logging metadata. False-positive caveats: logging may exist operationally but remain undocumented in metadata.

## `stale_release`
Flags `releaseDate` or `updatedAt` values older than the configured threshold in `rules.yml`. False-positive caveats: a stable server with low change velocity can still be healthy while appearing stale.

## `dependency_hygiene`
Flags unpinned dependencies and built-in known vulnerable package versions from `package.json`. False-positive caveats: lockfiles or external dependency controls are not considered unless reflected in package metadata.

## `security_metadata`
Flags targets that omit `security`, `securityPolicy`, and `contact` metadata. False-positive caveats: organizations sometimes publish security contacts elsewhere, but that is not machine-readable here.

## `missing_docs`
Flags local directory scans that do not contain `SECURITY.md` or `CHANGELOG.md`. False-positive caveats: remote or packaged targets may document these elsewhere, and single-file scans do not carry directory context.
