# Changelog

## 3.0.1 (2026-08-23)

- Made the package archive assertion compatible with both npm 11's array-shaped `npm pack --json` output and npm 12's package-keyed output, so the trusted-publishing gate runs under the publisher's npm version.
- This is the first 3.x package submitted to npm; the `v3.0.0` workflow stopped at its pre-publish test gate and did not upload an artifact.

## 3.0.0 (2026-08-23)

### Breaking
- Requires Node.js 20 or newer. Node 18 is end-of-life, and the patched Hono Node adapter used by the MCP SDK requires Node 20.

### Fixed
- Unreachable-backend failures no longer surface as a bare `fetch failed`. The CLI and MCP proxy now report the exact URL that was tried, the underlying transport code (e.g. `ECONNREFUSED`), and the environment variables that point the client somewhere else — this was the first-run experience for anyone without a local audit API on `http://127.0.0.1:3091`.
- `403` responses now tell the user their API key was rejected (or missing) instead of relaying the backend's loopback-client trust wording, which a package user cannot act on.
- Replaced the token-shaped `ghp_…` placeholder in `examples/claude-desktop.json` with `<your-github-token>` so third-party secret scanners and copy-paste users are not misled.

### Changed
- Corrected the README provenance section: no version published so far (2.0.0–2.1.0) carries a provenance attestation. The release workflow is configured for `--provenance` via trusted publishing, but that only takes effect on the first release actually cut from it.
- Switched the managed hosted default from `https://mcpaudit.metaltorque.dev` to `https://audit.leddconsulting.com`.
- Clarified the public distribution model in the docs: npm package plus official MCP Registry first, with downstream directories syncing from that source.
- Documented that Glama claim is optional and only needed for page ownership and manual sync controls.
- Clean installs now drive CI and release verification; package lint and a moderate-or-higher production dependency audit must pass before publication.

### Security
- Pinned patched Hono and Hono Node adapter releases and refreshed the MCP SDK dependency tree to remove current request-routing, parser, and validation advisories.

## 2.0.2 (2026-03-19)

### Added
- Added official MCP Registry metadata with `mcpName` and root `server.json`.
- Added registry-ready environment variable metadata for `AGENT_SECURITY_API_KEY` and optional `AGENT_SECURITY_BASE_URL`.

### Changed
- Published package now includes `server.json` for registry/discovery tooling.

## 2.0.1 (2026-03-19)

### Added
- Managed hosted flow now auto-targets `https://audit.leddconsulting.com` when `AGENT_SECURITY_API_KEY` is set and no explicit endpoint override is configured.
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
