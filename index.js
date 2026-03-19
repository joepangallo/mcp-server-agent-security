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

function normalizeHostToken(host) {
  const value = String(host || "").trim();
  if (!value) {
    return "";
  }

  if (value.startsWith("[") && value.endsWith("]")) {
    return value.slice(1, -1).trim();
  }

  return value;
}

function isLoopbackHost(host) {
  const normalized = normalizeHostToken(host).toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized === "localhost") {
    return true;
  }

  if (net.isIP(normalized) === 4) {
    return /^127(?:\.\d{1,3}){3}$/.test(normalized);
  }

  if (net.isIP(normalized) === 6) {
    return normalized === "::1" ||
      normalized === "0:0:0:0:0:0:0:1" ||
      /^::ffff:127(?:\.\d{1,3}){3}$/.test(normalized);
  }

  return false;
}

function formatHostForUrl(host) {
  const value = normalizeHostToken(host);
  if (!value) {
    return "127.0.0.1";
  }

  return net.isIP(value) === 6 ? `[${value}]` : value;
}

function resolveBaseUrl(options = {}) {
  const configuredBaseUrl = typeof options.baseUrl === "string" ? options.baseUrl.trim() : "";
  if (configuredBaseUrl) {
    let parsed;
    try {
      parsed = new URL(configuredBaseUrl);
    } catch (error) {
      throw new Error("AGENT_SECURITY_BASE_URL must be a valid http:// or https:// URL.");
    }

    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== "http:" && protocol !== "https:") {
      throw new Error("AGENT_SECURITY_BASE_URL must start with http:// or https://.");
    }
    if (protocol === "http:" && !isLoopbackHost(parsed.hostname)) {
      throw new Error("AGENT_SECURITY_BASE_URL must use https:// for non-loopback hosts.");
    }
    return configuredBaseUrl.replace(/\/+$/, "");
  }

  const host = typeof options.host === "string" ? options.host : HOST;
  const port = Number.isInteger(options.port) ? options.port : PORT;
  if (!isLoopbackHost(host)) {
    throw new Error("Use AGENT_SECURITY_BASE_URL with an https:// origin for non-loopback audit hosts.");
  }
  return `http://${formatHostForUrl(host)}:${port}`;
}

const BASE_URL = resolveBaseUrl({
  baseUrl: process.env.AGENT_SECURITY_BASE_URL,
  host: HOST,
  port: PORT
});

module.exports = { PORT, HOST, BASE_URL, formatHostForUrl, isLoopbackHost, resolveBaseUrl };
