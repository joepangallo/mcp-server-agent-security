# mcp-server-agent-security

MCP server and CLI for AI agent and MCP security auditing. Connects to the agent-security audit API to analyze MCP configurations, test prompt injection resistance, trace data flows, scan packages, and generate security policies.

This package is a thin proxy -- all scan logic runs on the private audit API (default: `http://127.0.0.1:3091`).

## Install

```bash
npm install mcp-server-agent-security
```

## Usage as MCP Server

Add to your MCP client configuration (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "agent-security": {
      "command": "npx",
      "args": ["-y", "mcp-server-agent-security", "--mcp"]
    }
  }
}
```

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

The CLI forwards commands to the audit API.

```bash
# Audit an MCP configuration file
agent-security scan-config ./claude_desktop_config.json

# Probe a live MCP server (requires AGENT_SECURITY_ADMIN_MODE=1)
agent-security scan-server npx -y @modelcontextprotocol/server-filesystem /tmp

# Scan an npm package for vulnerabilities
agent-security scan-package @modelcontextprotocol/server-shell

# Test a system prompt for injection vulnerabilities
agent-security scan-injection ./system-prompt.txt

# Trace data flows through an MCP config
agent-security scan-dataflow ./claude_desktop_config.json

# Auto-fix security issues in an MCP config
agent-security fix-config ./claude_desktop_config.json

# Harden a system prompt against injection
agent-security harden-prompt ./system-prompt.txt

# Generate a security policy from an MCP config
agent-security generate-policy ./claude_desktop_config.json

# Retrieve a previous audit report
agent-security report <audit-id>

# Output raw JSON instead of formatted tables
agent-security scan-config ./config.json --json

# Start in MCP stdio server mode
agent-security --mcp
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_SECURITY_HOST` | `127.0.0.1` | Audit API host |
| `AGENT_SECURITY_PORT` | `3091` | Audit API port |
| `AGENT_SECURITY_API_KEY` | (none) | API key for authenticated access |
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
- A running agent-security audit API (default: `http://127.0.0.1:3091`)

## License

MIT

---

Built by [Ledd Consulting](https://leddconsulting.com)
