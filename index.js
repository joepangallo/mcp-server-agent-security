/**
 * mcp-server-agent-security — public entry point
 *
 * This package is a thin MCP interface to the agent-security audit service.
 * All scan logic runs on the private audit API (default: http://127.0.0.1:3091).
 *
 * Start the MCP server:   node mcp/index.js
 * Use the CLI:             node cli.js scan-config <file>
 */

const PORT = Number.parseInt(process.env.AGENT_SECURITY_PORT || "", 10) || 3091;
const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";

module.exports = { PORT, HOST };
