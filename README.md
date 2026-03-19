# mcp-audit-server

Thin MCP server and CLI proxy for AI agent and MCP security auditing. It connects to a private audit API to analyze MCP configurations, test prompt injection resistance, trace data flows, scan packages, and generate security policies.

This package is a thin proxy. All scan logic lives in a private backend operated by you or your provider.

Managed hosted flow:
- set `AGENT_SECURITY_API_KEY`
- the package will automatically target `https://mcpaudit.metaltorque.dev`

Self-hosted or private-network flow:
- set `AGENT_SECURITY_BASE_URL` to your HTTPS API origin
- or set `AGENT_SECURITY_HOST` and `AGENT_SECURITY_PORT` for a loopback/private deployment

Hosted backend access is not bundled with this package. If you want managed access or a licensed private deployment, contact [Ledd Consulting](https://leddconsulting.com).

## Registry and Directories

- npm package: `ledd-mcp-audit-server`
- Official MCP Registry name: `io.github.joepangallo/mcp-audit-server`
- Downstream directories such as Glama and PulseMCP should ingest from the official MCP Registry, so you usually do not need separate manual submissions for each site.
- Glama authorship claim is optional. It only gives you ownership of the Glama page and access to manual sync and re-scan controls.

## Install

```bash
npm install ledd-mcp-audit-server
```

Install package: `ledd-mcp-audit-server`
CLI command after install: `mcp-audit-server`

This is the public package that should be published to npm and listed in public MCP directories. The audit engine itself stays private.

The old package name `mcp-server-agent-security` is retired. See [MIGRATION.md](./MIGRATION.md) for upgrade steps and the deprecation plan.

## Usage as MCP Server

Add to your MCP client configuration (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "mcp-audit-server": {
      "command": "npx",
      "args": ["-y", "ledd-mcp-audit-server", "--mcp"],
      "env": {
        "AGENT_SECURITY_API_KEY": "your-issued-api-key"
      }
    }
  }
}
```

For a self-hosted backend, add `AGENT_SECURITY_BASE_URL` to that same `env` block.

The server exposes 9 tools over stdio:

| Tool | Description |
|------|-------------|
| `audit_mcp_config` | Static analysis of MCP config JSON for privilege, auth, transport, and launch risks |
| `audit_mcp_server` | Active probing of a running MCP server over stdio (requires `AGENT_SECURITY_ADMIN_MODE=1`) |
| `audit_prompt_injection` | Tests a system prompt against a 30+ payload injection catalog |
| `audit_agent_dataflow` | Traces PII and secret exposure through an agent's tool pipeline |
| `scan_mcp_package` | Scans an npm MCP package for dependency vulnerabilities and dangerous patterns |
| `generate_report` | Combines multiple audit results into a composite report with executive summary |
| `fix_mcp_config` | Auto-remediates config issues: removes unsafe flags, upgrades transport, redacts secrets |
| `harden_system_prompt` | Appends injection-resistant guardrails to a system prompt |
| `generate_policy` | Generates an enforceable JSON security policy from an MCP config |

## Usage as CLI

The CLI forwards commands to the private audit API.

```bash
# Hosted quick start
export AGENT_SECURITY_API_KEY=your-issued-api-key

# Audit an MCP configuration file
mcp-audit-server scan-config ./claude_desktop_config.json

# Probe a live MCP server (requires AGENT_SECURITY_ADMIN_MODE=1)
mcp-audit-server scan-server npx -y @modelcontextprotocol/server-filesystem /tmp

# Scan an npm package for vulnerabilities
mcp-audit-server scan-package @modelcontextprotocol/server-shell

# Test a system prompt for injection vulnerabilities
mcp-audit-server scan-injection ./system-prompt.txt

# Trace data flows through an MCP config
mcp-audit-server scan-dataflow ./claude_desktop_config.json

# Auto-fix security issues in an MCP config
mcp-audit-server fix-config ./claude_desktop_config.json

# Harden a system prompt against injection
mcp-audit-server harden-prompt ./system-prompt.txt

# Generate a security policy from an MCP config
mcp-audit-server generate-policy ./claude_desktop_config.json

# Retrieve a previous audit report
mcp-audit-server report <audit-id>

# Output raw JSON instead of formatted tables
mcp-audit-server scan-config ./config.json --json

# Start in MCP stdio server mode
mcp-audit-server --mcp
```

For a self-hosted backend, also set `AGENT_SECURITY_BASE_URL=https://your-audit-host`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_SECURITY_BASE_URL` | (none) | Full audit API origin, e.g. `https://audit.example.com` |
| `AGENT_SECURITY_HOST` | `127.0.0.1` | Self-hosted/private-network audit API host |
| `AGENT_SECURITY_PORT` | `3091` | Self-hosted/private-network audit API port |
| `AGENT_SECURITY_API_KEY` | (none) | API key for authenticated access. If set with no endpoint overrides, the package uses `https://mcpaudit.metaltorque.dev` |
| `AGENT_SECURITY_REQUEST_TIMEOUT_MS` | `15000` | Request timeout for CLI and MCP proxy calls |
| `AGENT_SECURITY_ADMIN_MODE` | (none) | Set to `1` to enable active server probing |

## What It Detects

- **Tool spoofing** -- duplicate tool names, namespace collision (CWE-290)
- **Rug pull** -- unpinned packages, version drift (CWE-829)
- **Prompt injection** -- direct override, instruction hijacking, role-play escape, delimiter injection, encoding bypass, multilingual injection
- **Privilege escalation** -- overprivileged tools, shell execution without allowlists, unrestricted filesystem access
- **Data exfiltration** -- PII leakage through tool pipelines, outbound network paths
- **Insecure transport** -- missing TLS, plaintext credentials in config
- **Missing auth** -- unauthenticated MCP servers, missing API key requirements
- **Shell injection** -- arbitrary command execution via tool configurations
- **Path traversal** -- unrestricted filesystem scope in tool arguments
- **SQL injection** -- raw SQL patterns in tool definitions
- **Rate limiting** -- missing request throttling on exposed tools
- **Package vulnerabilities** -- known CVEs in npm MCP package dependencies
- **Credential exposure** -- inline secrets, missing rotation policies

## Requirements

- Node.js >= 18
- Access to a private audit API. The managed hosted default is `https://mcpaudit.metaltorque.dev` when `AGENT_SECURITY_API_KEY` is set. Use `AGENT_SECURITY_BASE_URL` for other hosted HTTPS deployments, or `AGENT_SECURITY_HOST` and `AGENT_SECURITY_PORT` for local/private-network deployments.

## License

MIT

---

Built by [Ledd Consulting](https://leddconsulting.com)
