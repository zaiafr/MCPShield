# Positioning

MCPShield should not compete as a generic "MCP security scanner." That category already has credible products and open-source projects. The stronger wedge is: **offline-first MCP policy and trust scanning for CI and local review**.

## Market Snapshot

| Project | Overlap | Where MCPShield should differ |
| --- | --- | --- |
| [MCPSafe](https://mcpsafe.org/) | Hosted MCP security scanning, registry, and CI-oriented scanning | Stay lighter-weight, offline-first, and easier to self-run in CI without a hosted dependency |
| [MCP_Scanner](https://github.com/beejak/MCP_Scanner) | Deep open-source MCP security scanning with AST and supply-chain checks | Focus on policy gates, metadata triage, and trust controls instead of deeper code-analysis breadth |
| [mcpserver-audit](https://github.com/ModelContextProtocol-Security/mcpserver-audit) | MCP server auditing from the CSA MCP security ecosystem | Position as a practical operator tool for continuous local review and gating, not a research/audit utility |
| [mcp-watch](https://github.com/kapilduraphe/mcp-watch) | MCP-specific security scanning and monitoring | Stay opinionated about local inventories, batch diffs, and plugin trust enforcement |

## Recommended Wedge

Use this positioning consistently:

- `MCPShield is an offline-first MCP policy and trust scanner for CI and local review.`
- `It helps teams gate MCP server inventories with deterministic findings, configurable rules, batch summaries, and plugin trust controls.`

## What To Avoid

- Avoid leading with "MCP security scanner" alone.
- Avoid implying runtime sandboxing or deep code-execution analysis.
- Avoid competing head-on with hosted registries or full AST-analysis suites unless you plan to build those directly.

## Messaging Priorities

1. Offline-first and self-serve
2. CI quality gates and batch diffs
3. Configurable policy over generic severity feeds
4. Explicit plugin trust controls
