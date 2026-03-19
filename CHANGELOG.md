# Changelog

## Unreleased

### Changed
- Clarified the public distribution model in the docs: npm package plus official MCP Registry first, with downstream directories syncing from that source.
- Documented that Glama claim is optional and only needed for page ownership and manual sync controls.

## 2.0.2 (2026-03-19)

### Added
- Added official MCP Registry metadata with `mcpName` and root `server.json`.
- Added registry-ready environment variable metadata for `AGENT_SECURITY_API_KEY` and optional `AGENT_SECURITY_BASE_URL`.

### Changed
- Published package now includes `server.json` for registry/discovery tooling.

## 2.0.1 (2026-03-19)

### Added
- Managed hosted flow now auto-targets `https://mcpaudit.metaltorque.dev` when `AGENT_SECURITY_API_KEY` is set and no explicit endpoint override is configured.
- Clearer CLI and MCP auth guidance when the proxy receives a `401 Unauthorized` response.
- MCP client and CLI docs now show the API-key based hosted setup directly.

### Changed
- Updated the recommended MCP configuration to pass `AGENT_SECURITY_API_KEY` via the client `env` block.

## 2.0.0 (2026-03-15)

### Breaking Changes
- Scan engine moved to private API service. This package is now a thin MCP/CLI proxy.
- Published package renamed to `ledd-mcp-audit-server` to avoid npm namespace collisions while keeping the CLI command as `mcp-audit-server`.
- Removed `lib/` directory and all in-process scan modules.
- Requires access to a private audit API.

### Added
- Tool spoofing detection (CWE-290) — duplicate tool names, namespace collision
- Rug pull detection (CWE-829) — unpinned packages, version drift
- Credential hygiene checks — inline secrets, missing rotation
- 9 MCP tools for comprehensive agent security auditing
- CLI with formatted output and --json mode
- Rate limiting on MCP server (30 req/min)
- `AGENT_SECURITY_BASE_URL` for hosted HTTPS backends

### Removed
- All in-process scan modules (moved to a private backend)
- Direct dependencies on better-sqlite3, express, uuid
