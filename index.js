/**
 * mcp-audit-server — public entry point
 *
 * This package is a thin MCP interface to a private audit API. Local/self-hosted
 * deployments can target a loopback API on http://127.0.0.1:3091, while the
 * managed hosted flow auto-targets https://audit.leddconsulting.com when an
 * API key is present and no explicit endpoint override is set.
 *
 * Start the MCP server:   node mcp/index.js
 * Use the CLI:            node cli.js scan-config <file>
 */

const net = require("net");

const DEFAULT_HOSTED_BASE_URL = "https://audit.leddconsulting.com";
const RAW_BASE_URL = process.env.AGENT_SECURITY_BASE_URL;
const RAW_HOST = process.env.AGENT_SECURITY_HOST;
const RAW_PORT = process.env.AGENT_SECURITY_PORT;
const RAW_API_KEY = process.env.AGENT_SECURITY_API_KEY || "";

const PORT = Number.parseInt(RAW_PORT || "", 10) || 3091;
const HOST = RAW_HOST || "127.0.0.1";

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

  if (options.useHostedDefault) {
    return DEFAULT_HOSTED_BASE_URL;
  }

  const host = typeof options.host === "string" && options.host.trim()
    ? options.host
    : HOST;
  const port = Number.isInteger(options.port) ? options.port : PORT;
  if (!isLoopbackHost(host)) {
    throw new Error("Use AGENT_SECURITY_BASE_URL with an https:// origin for non-loopback audit hosts.");
  }
  return `http://${formatHostForUrl(host)}:${port}`;
}

// Transport-level failure codes that mean "the audit API was never reached".
// `fetch` (undici) surfaces all of these as a bare `TypeError: fetch failed`
// with the real reason hidden on `error.cause`, which is useless to a user.
const CONNECTION_ERROR_CODES = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTDOWN",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
  "ETIMEDOUT",
  "EPIPE",
  "UND_ERR_SOCKET",
  "UND_ERR_CONNECT_TIMEOUT"
]);

function collectErrorCodes(error) {
  const codes = [];
  let current = error;
  let depth = 0;

  while (current && typeof current === "object" && depth < 5) {
    if (typeof current.code === "string" && current.code) {
      codes.push(current.code);
    }
    if (Array.isArray(current.errors)) {
      for (const nested of current.errors) {
        if (nested && typeof nested.code === "string" && nested.code) {
          codes.push(nested.code);
        }
      }
    }
    current = current.cause;
    depth += 1;
  }

  return codes;
}

function isConnectionError(error) {
  if (!error || typeof error !== "object") {
    return false;
  }
  if (error.name === "AbortError") {
    return false;
  }
  if (collectErrorCodes(error).some((code) => CONNECTION_ERROR_CODES.has(code))) {
    return true;
  }

  return error.name === "TypeError" ||
    String(error.message || "").trim().toLowerCase() === "fetch failed";
}

function describeConnectionCause(error) {
  const codes = collectErrorCodes(error);
  if (codes.length) {
    return codes[0];
  }

  let current = error;
  let depth = 0;
  let detail = "";
  while (current && typeof current === "object" && depth < 5) {
    const message = String(current.message || "").trim();
    if (message && message.toLowerCase() !== "fetch failed") {
      detail = message;
      break;
    }
    current = current.cause;
    depth += 1;
  }

  return detail;
}

function isLoopbackBaseUrl(baseUrl) {
  try {
    return isLoopbackHost(new URL(baseUrl).hostname);
  } catch {
    return false;
  }
}

/**
 * Turn an unreachable-endpoint failure into a message that names the URL that
 * was tried and the environment variable that changes it.
 */
function buildConnectionErrorMessage(error, baseUrl) {
  const target = typeof baseUrl === "string" && baseUrl.trim() ? baseUrl.trim() : "the audit API";
  const cause = describeConnectionCause(error);
  const parts = [`Could not reach the audit API at ${target}${cause ? ` (${cause})` : ""}.`];

  if (isLoopbackBaseUrl(target)) {
    parts.push(
      "Nothing is listening on that address, so no audit backend is running locally.",
      `Set AGENT_SECURITY_API_KEY to use the managed API at ${DEFAULT_HOSTED_BASE_URL}, set AGENT_SECURITY_BASE_URL to your own https:// audit API origin, or start a self-hosted backend on AGENT_SECURITY_HOST/AGENT_SECURITY_PORT.`
    );
  } else {
    parts.push(
      "Check network connectivity to that host, and set AGENT_SECURITY_BASE_URL if the audit API lives somewhere else."
    );
  }

  return parts.join(" ");
}

/**
 * Client-facing 403 text. The backend's own 403 body describes its loopback
 * trust model, which is meaningless to a user of this package — tell them what
 * they can act on instead: their API key was not accepted.
 */
function buildForbiddenMessage(baseUrl, hasApiKey) {
  const target = typeof baseUrl === "string" && baseUrl.trim() ? baseUrl.trim() : "the audit API";

  if (hasApiKey) {
    return `Audit API at ${target} rejected this request (403 Forbidden): the API key in AGENT_SECURITY_API_KEY was not accepted. Confirm the key is correct, still active, and issued for this endpoint.`;
  }

  return `Audit API at ${target} rejected this request (403 Forbidden): no API key was sent. Set AGENT_SECURITY_API_KEY to a key issued for this audit API.`;
}

const BASE_URL = resolveBaseUrl({
  baseUrl: RAW_BASE_URL,
  host: RAW_HOST,
  port: PORT,
  useHostedDefault: !String(RAW_BASE_URL || "").trim() &&
    RAW_HOST === undefined &&
    RAW_PORT === undefined &&
    Boolean(RAW_API_KEY)
});

module.exports = {
  PORT,
  HOST,
  BASE_URL,
  DEFAULT_HOSTED_BASE_URL,
  buildConnectionErrorMessage,
  buildForbiddenMessage,
  formatHostForUrl,
  isConnectionError,
  isLoopbackHost,
  resolveBaseUrl
};
