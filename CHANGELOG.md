# Changelog

## 2.0.0 (2026-03-15)

### Breaking Changes
- Scan engine moved to private API service. This package is now a thin MCP/CLI proxy.
- Removed `lib/` directory and all in-process scan modules.
- Requires a running agent-security audit API (default: http://127.0.0.1:3091).

### Added
- Tool spoofing detection (CWE-290) — duplicate tool names, namespace collision
- Rug pull detection (CWE-829) — unpinned packages, version drift
- Credential hygiene checks — inline secrets, missing rotation
- 9 MCP tools for comprehensive agent security auditing
- CLI with formatted output and --json mode
- Rate limiting on MCP server (30 req/min)

### Removed
- All in-process scan modules (moved to private `mcp-security-audit` package)
- Direct dependencies on better-sqlite3, express, uuid
