# Migration Guide

This package replaces the ambiguous `mcp-server-agent-security` name for the thin MCP/CLI proxy.

## What Changed

- Old package name: `mcp-server-agent-security`
- New package name: `mcp-audit-server`
- Preferred CLI: `mcp-audit-server`

## Upgrade

```bash
npm uninstall mcp-server-agent-security
npm install mcp-audit-server
```

If you launch the MCP proxy through `npx`, update your client config:

```json
{
  "mcpServers": {
    "mcp-audit-server": {
      "command": "npx",
      "args": ["-y", "mcp-audit-server", "--mcp"]
    }
  }
}
```

## Package Split

The old package name was overloaded across two different repos. The split is now:

- private audit engine: proprietary backend, rules, storage, and remediation logic
- `mcp-audit-server`: thin MCP/CLI proxy that forwards to that private audit API

Use `mcp-audit-server` when you want the public client package. Configure it against your hosted or licensed private audit API.

## Publisher Checklist

1. Publish this package under the new name: `npm publish`
2. Deprecate the old package name:

```bash
npm deprecate mcp-server-agent-security@"*" "Deprecated: use mcp-audit-server. The audit backend is now private and licensed separately."
```

3. Update the public README to point users to your hosted API or sales contact, not to a public engine package.
