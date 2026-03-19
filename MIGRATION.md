# Migration Guide

This package replaces the ambiguous `mcp-server-agent-security` name for the thin MCP/CLI proxy.

## What Changed

- Old package name: `mcp-server-agent-security`
- New package name: `ledd-mcp-audit-server`
- Preferred CLI: `mcp-audit-server`

## Upgrade

```bash
npm uninstall mcp-server-agent-security
npm install ledd-mcp-audit-server
```

If you launch the MCP proxy through `npx`, update your client config:

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

If `AGENT_SECURITY_API_KEY` is set and no endpoint override is provided, the proxy will automatically target `https://mcpaudit.metaltorque.dev`. For self-hosted backends, also set `AGENT_SECURITY_BASE_URL`.

## Package Split

The old package name was overloaded across two different repos. The split is now:

- private audit engine: proprietary backend, rules, storage, and remediation logic
- `ledd-mcp-audit-server`: thin MCP/CLI proxy that forwards to that private audit API

Use `ledd-mcp-audit-server` when you want the public client package. It installs the `mcp-audit-server` CLI and should be configured against your hosted or licensed private audit API.

## Registry Publishing

For public distribution, publish only the thin proxy:

1. Publish `ledd-mcp-audit-server` to npm.
2. Publish `io.github.joepangallo/mcp-audit-server` to the official MCP Registry.
3. Keep the private audit engine repo private and do not list it on public directories.
4. Let downstream directories such as Glama and PulseMCP sync from the official registry.
5. Claim the Glama page only if you want page ownership and manual sync controls.

## Publisher Checklist

1. Publish this package under the new name: `npm publish`
2. Publish the package metadata to the official MCP Registry.
3. Deprecate the old package name:

```bash
npm deprecate mcp-server-agent-security@"*" "Deprecated: use ledd-mcp-audit-server. The audit backend is now private and licensed separately."
```

4. Update the public README to point users to your hosted API or sales contact, not to a public engine package.
5. Treat Glama authorship claim as optional post-publish admin work, not as a separate release channel.
