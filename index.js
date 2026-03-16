/**
 * mcp-audit-server — public entry point
 *
 * This package is a thin MCP interface to a private audit API.
 * By default it targets a local API on http://127.0.0.1:3091, but hosted
 * deployments should prefer AGENT_SECURITY_BASE_URL with an https:// origin.
 *
 * Start the MCP server:   node mcp/index.js
 * Use the CLI:            node cli.js scan-config <file>
 */

const net = require("net");

const PORT = Number.parseInt(process.env.AGENT_SECURITY_PORT || "", 10) || 3091;
const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";

function formatHostForUrl(host) {
  const value = String(host || "").trim();
  if (!value) {
    return "127.0.0.1";
  }

  if (value.startsWith("[") && value.endsWith("]")) {
    return value;
  }

  return net.isIP(value) === 6 ? `[${value}]` : value;
}

function resolveBaseUrl(options = {}) {
  const configuredBaseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : "";
  if (configuredBaseUrl) {
    if (!/^https?:\/\//i.test(configuredBaseUrl)) {
      throw new Error("AGENT_SECURITY_BASE_URL must start with http:// or https://.");
    }
    return configuredBaseUrl.replace(/\/+$/, "");
  }

  const host = typeof options.host === "string" ? options.host : HOST;
  const port = Number.isInteger(options.port) ? options.port : PORT;
  return `http://${formatHostForUrl(host)}:${port}`;
}

const BASE_URL = resolveBaseUrl({
  baseUrl: process.env.AGENT_SECURITY_BASE_URL,
  host: HOST,
  port: PORT
});

module.exports = { PORT, HOST, BASE_URL, formatHostForUrl, resolveBaseUrl };
