/**
 * MCP server for agent-security — thin proxy to the private audit API.
 *
 * All scan logic runs on the private agent-security-audit service.
 * This MCP server only exposes tool definitions and forwards requests.
 */

const AUDIT_API_HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";
const AUDIT_API_PORT = process.env.AGENT_SECURITY_PORT || "3091";
const AUDIT_API_KEY = process.env.AGENT_SECURITY_API_KEY || "";
const AUDIT_BASE_URL = `http://${AUDIT_API_HOST}:${AUDIT_API_PORT}`;

const MCP_MAX_REQUESTS_PER_MINUTE = 30;
const MCP_WINDOW_MS = 60_000;
let mcpRequestCount = 0;
let mcpWindowStart = Date.now();

const toolDefinitions = [
  {
    name: "audit_mcp_config",
    description: "Perform static analysis on raw MCP config JSON and identify privilege, auth, transport, and launch risks.",
    inputSchema: {
      type: "object",
      properties: { config: { type: "string", description: "Raw MCP config JSON." } },
      required: ["config"]
    }
  },
  {
    name: "audit_mcp_server",
    description: "Launch a target MCP server over stdio, enumerate tools, and run active security probes against its exposed tools. Requires AGENT_SECURITY_ADMIN_MODE=1.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        args: { type: "array", items: { type: "string" } },
        env: { type: "object", additionalProperties: { type: "string" } }
      },
      required: ["command"]
    }
  },
  {
    name: "audit_prompt_injection",
    description: "Perform a static prompt-hardening review against a 30+ payload prompt-injection catalog.",
    inputSchema: {
      type: "object",
      properties: {
        system_prompt: { type: "string" },
        tools: { type: "array", items: { type: "string" } }
      },
      required: ["system_prompt"]
    }
  },
  {
    name: "audit_agent_dataflow",
    description: "Infer tagged-data exposure and exfiltration paths from MCP config and observed tool capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        mcp_config: { type: "string" },
        test_pii: { type: "string" }
      },
      required: ["mcp_config"]
    }
  },
  {
    name: "scan_mcp_package",
    description: "Scan an npm MCP package for dependency vulnerabilities, dangerous patterns, and permission issues.",
    inputSchema: {
      type: "object",
      properties: { package_name: { type: "string" } },
      required: ["package_name"]
    }
  },
  {
    name: "generate_report",
    description: "Combine multiple stored audit jobs into a composite report with deduplicated findings and an executive summary.",
    inputSchema: {
      type: "object",
      properties: { audit_ids: { type: "array", items: { type: "string" } } },
      required: ["audit_ids"]
    }
  },
  {
    name: "fix_mcp_config",
    description: "Auto-remediate security issues in an MCP config: remove unsafe flags, strip shell wrappers, upgrade transport to TLS, redact inline secrets, add auth placeholders, and constrain filesystem scope.",
    inputSchema: {
      type: "object",
      properties: { config: { type: "string", description: "Raw MCP config JSON to fix." } },
      required: ["config"]
    }
  },
  {
    name: "harden_system_prompt",
    description: "Analyze a system prompt for injection vulnerabilities and return a hardened version with security guardrails appended.",
    inputSchema: {
      type: "object",
      properties: {
        system_prompt: { type: "string", description: "The system prompt to harden." },
        tools: { type: "array", items: { type: "string" }, description: "Tool names available to the agent." }
      },
      required: ["system_prompt"]
    }
  },
  {
    name: "generate_policy",
    description: "Generate a JSON security policy from an MCP config that can be enforced by a proxy or middleware.",
    inputSchema: {
      type: "object",
      properties: {
        mcp_config: { type: "string", description: "Raw MCP config JSON." },
        allowed_destinations: { type: "array", items: { type: "string" } },
        allowed_paths: { type: "array", items: { type: "string" } }
      },
      required: ["mcp_config"]
    }
  }
];

// Route table: MCP tool name → private API endpoint
const toolRoutes = {
  audit_mcp_config:      { method: "POST", path: "/audit/config",    body: (a) => ({ config: a.config }) },
  audit_mcp_server:      { method: "POST", path: "/audit/server",    body: (a) => ({ command: a.command, args: a.args, env: a.env }) },
  audit_prompt_injection: { method: "POST", path: "/audit/injection", body: (a) => ({ system_prompt: a.system_prompt, tools: a.tools }) },
  audit_agent_dataflow:  { method: "POST", path: "/audit/dataflow",  body: (a) => ({ mcp_config: a.mcp_config, test_pii: a.test_pii }) },
  scan_mcp_package:      { method: "POST", path: "/audit/package",   body: (a) => ({ package_name: a.package_name }) },
  fix_mcp_config:        { method: "POST", path: "/fix/config",      body: (a) => ({ config: a.config }) },
  harden_system_prompt:  { method: "POST", path: "/fix/prompt",      body: (a) => ({ system_prompt: a.system_prompt, tools: a.tools }) },
  generate_policy:       { method: "POST", path: "/fix/policy",      body: (a) => ({ mcp_config: a.mcp_config, allowed_destinations: a.allowed_destinations, allowed_paths: a.allowed_paths }) },
};

async function callAuditApi(method, apiPath, payload) {
  const headers = { "Content-Type": "application/json" };
  if (AUDIT_API_KEY) {
    headers["x-api-key"] = AUDIT_API_KEY;
  }

  const response = await fetch(`${AUDIT_BASE_URL}${apiPath}`, {
    method,
    headers,
    body: payload ? JSON.stringify(payload) : undefined,
  });

  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { error: `Audit API returned non-JSON (status ${response.status}): ${text.slice(0, 200)}` };
  }

  if (!response.ok) {
    return { error: body.error || `Audit API returned status ${response.status}` };
  }

  return body;
}

function checkMcpRateLimit() {
  const now = Date.now();
  if (now - mcpWindowStart > MCP_WINDOW_MS) {
    mcpRequestCount = 0;
    mcpWindowStart = now;
  }
  mcpRequestCount++;
  return mcpRequestCount <= MCP_MAX_REQUESTS_PER_MINUTE;
}

async function runAuditTool(toolName, args) {
  if (!checkMcpRateLimit()) {
    return { error: "Rate limit exceeded. Try again later." };
  }

  const safeArgs = args && typeof args === "object" && !Array.isArray(args) ? args : {};

  // generate_report: fetch individual reports by ID
  if (toolName === "generate_report") {
    const ids = Array.isArray(safeArgs.audit_ids) ? safeArgs.audit_ids.map(String) : [];
    if (ids.length === 0) {
      return { error: "audit_ids must be a non-empty array." };
    }
    if (ids.length > 25) {
      return { error: "audit_ids must contain at most 25 entries." };
    }
    if (ids.length === 1) {
      return callAuditApi("GET", `/report/${encodeURIComponent(ids[0])}`);
    }
    const results = await Promise.all(ids.map((id) => callAuditApi("GET", `/report/${encodeURIComponent(id)}`)));
    return { reports: results };
  }

  const route = toolRoutes[toolName];
  if (!route) {
    return { error: `Unknown tool: ${toolName}` };
  }

  return callAuditApi(route.method, route.path, route.body(safeArgs));
}

function importFirst(candidates) {
  for (const id of candidates) {
    try {
      return require(id);
    } catch {}
  }
  throw new Error(`Could not import any of: ${candidates.join(", ")}`);
}

async function main() {
  const serverModule = importFirst([
    "@modelcontextprotocol/sdk/server/index.js",
    "@modelcontextprotocol/sdk/dist/esm/server/index.js",
    "@modelcontextprotocol/sdk/dist/server/index.js",
  ]);
  const stdioModule = importFirst([
    "@modelcontextprotocol/sdk/server/stdio.js",
    "@modelcontextprotocol/sdk/dist/esm/server/stdio.js",
    "@modelcontextprotocol/sdk/dist/server/stdio.js",
  ]);
  const typesModule = importFirst([
    "@modelcontextprotocol/sdk/types.js",
    "@modelcontextprotocol/sdk/dist/esm/types.js",
    "@modelcontextprotocol/sdk/dist/types.js",
  ]);

  const Server = serverModule.Server || (serverModule.default && serverModule.default.Server);
  const StdioServerTransport = stdioModule.StdioServerTransport || (stdioModule.default && stdioModule.default.StdioServerTransport);
  const { ListToolsRequestSchema, CallToolRequestSchema } = typesModule;

  if (!Server || !StdioServerTransport || !ListToolsRequestSchema || !CallToolRequestSchema) {
    throw new Error("Unable to load the MCP server SDK classes.");
  }

  const server = new Server(
    { name: "mcp-server-agent-security", version: "1.2.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefinitions,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      const toolName = request?.params?.name || "";
      const args = request?.params?.arguments || {};
      const result = await runAuditTool(toolName, args);
      const isToolError = Boolean(result?.error);
      return {
        ...(isToolError ? { isError: true } : {}),
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify({ error: error.message }, null, 2) }],
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exit(1);
  });
}

module.exports = { main, runAuditTool };
