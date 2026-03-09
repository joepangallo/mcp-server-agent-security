const { analyzeConfig } = require("../lib/config-analyzer");
const { probeServer } = require("../lib/server-prober");
const { testPromptInjection } = require("../lib/injection-tester");
const { traceDataFlow } = require("../lib/dataflow-tracer");
const { scanPackage } = require("../lib/package-scanner");
const {
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  executeAuditJob,
  generateCombinedReport,
  isAdminModeEnabled
} = require("../index");

const toolDefinitions = [
  {
    name: "audit_mcp_config",
    description: "Perform static analysis on raw MCP config JSON and identify privilege, auth, transport, and launch risks.",
    inputSchema: {
      type: "object",
      properties: {
        config: {
          type: "string",
          description: "Raw MCP config JSON."
        }
      },
      required: ["config"]
    }
  },
  {
    name: "audit_mcp_server",
    description: "Launch a target MCP server over stdio, enumerate tools, and run active security probes against its exposed tools. Requires AGENT_SECURITY_ADMIN_MODE=1.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string"
        },
        args: {
          type: "array",
          items: {
            type: "string"
          }
        },
        env: {
          type: "object",
          additionalProperties: {
            type: "string"
          }
        }
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
        system_prompt: {
          type: "string"
        },
        tools: {
          type: "array",
          items: {
            type: "string"
          }
        }
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
        mcp_config: {
          type: "string"
        },
        test_pii: {
          type: "string"
        }
      },
      required: ["mcp_config"]
    }
  },
  {
    name: "scan_mcp_package",
    description: "Scan an npm MCP package for dependency vulnerabilities, dangerous patterns, and permission issues.",
    inputSchema: {
      type: "object",
      properties: {
        package_name: {
          type: "string"
        }
      },
      required: ["package_name"]
    }
  },
  {
    name: "generate_report",
    description: "Combine multiple stored audit jobs into a composite report with deduplicated findings and an executive summary.",
    inputSchema: {
      type: "object",
      properties: {
        audit_ids: {
          type: "array",
          items: {
            type: "string"
          }
        }
      },
      required: ["audit_ids"]
    }
  }
];

async function importFirst(specifiers) {
  let lastError;

  for (const specifier of specifiers) {
    try {
      return await import(specifier);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError;
}

async function loadServerSdk() {
  const serverModule = await importFirst([
    "@modelcontextprotocol/sdk/server/index.js",
    "@modelcontextprotocol/sdk/dist/esm/server/index.js",
    "@modelcontextprotocol/sdk/dist/server/index.js"
  ]);
  const stdioModule = await importFirst([
    "@modelcontextprotocol/sdk/server/stdio.js",
    "@modelcontextprotocol/sdk/dist/esm/server/stdio.js",
    "@modelcontextprotocol/sdk/dist/server/stdio.js"
  ]);
  const typesModule = await importFirst([
    "@modelcontextprotocol/sdk/types.js",
    "@modelcontextprotocol/sdk/dist/esm/types.js",
    "@modelcontextprotocol/sdk/dist/types.js"
  ]);

  return {
    Server: serverModule.Server || (serverModule.default && serverModule.default.Server),
    StdioServerTransport: stdioModule.StdioServerTransport || (stdioModule.default && stdioModule.default.StdioServerTransport),
    ListToolsRequestSchema: typesModule.ListToolsRequestSchema,
    CallToolRequestSchema: typesModule.CallToolRequestSchema
  };
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sanitizeEnv(envInput) {
  if (!isPlainObject(envInput)) {
    return undefined;
  }

  const env = {};
  for (const [key, value] of Object.entries(envInput)) {
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) && typeof value === "string") {
      env[key] = value;
    }
  }

  return Object.keys(env).length ? env : undefined;
}

async function runAuditTool(toolName, args) {
  const safeArgs = isPlainObject(args) ? args : {};

  switch (toolName) {
    case "audit_mcp_config":
      return executeAuditJob("config", "mcp-config", async () => analyzeConfig(safeArgs.config));
    case "audit_mcp_server": {
      if (!isAdminModeEnabled()) {
        return { error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE };
      }
      const MCP_COMMAND_ALLOWLIST = new Set(["node", "python3", "python", "npx", "uvx", "deno", "bun"]);
      const commandBase = typeof safeArgs.command === "string" ? safeArgs.command.trim().split(/ +/)[0] : "";
      if (!commandBase || !MCP_COMMAND_ALLOWLIST.has(commandBase)) {
        return { error: "Command not allowed. Permitted: " + [...MCP_COMMAND_ALLOWLIST].join(", ") };
      }
      const commandArgs = Array.isArray(safeArgs.args) ? safeArgs.args.map((value) => String(value)) : [];
      const target = [safeArgs.command, ...commandArgs].join(" ").trim();
      return executeAuditJob("server", target, async () => probeServer({
        command: safeArgs.command,
        args: commandArgs,
        env: sanitizeEnv(safeArgs.env)
      }));
    }
    case "audit_prompt_injection":
      return executeAuditJob("injection", "prompt-surface", async () => testPromptInjection(
        safeArgs.system_prompt,
        Array.isArray(safeArgs.tools) ? safeArgs.tools.map((value) => String(value)) : []
      ));
    case "audit_agent_dataflow":
      return executeAuditJob("dataflow", "mcp-pipeline", async () => traceDataFlow(safeArgs.mcp_config, safeArgs.test_pii));
    case "scan_mcp_package":
      return executeAuditJob("package", safeArgs.package_name, async () => scanPackage(safeArgs.package_name));
    case "generate_report":
      return generateCombinedReport(Array.isArray(safeArgs.audit_ids) ? safeArgs.audit_ids.map((value) => String(value)) : []);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

async function dispatchTool(toolName, args) {
  return runAuditTool(toolName, args);
}

async function main() {
  const {
    Server,
    StdioServerTransport,
    ListToolsRequestSchema,
    CallToolRequestSchema
  } = await loadServerSdk();

  if (!Server || !StdioServerTransport || !ListToolsRequestSchema || !CallToolRequestSchema) {
    throw new Error("Unable to load the MCP server SDK classes.");
  }

  const server = new Server(
    {
      name: "mcp-server-agent-security",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefinitions
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      const toolName = request && request.params ? request.params.name : "";
      const args = request && request.params && request.params.arguments ? request.params.arguments : {};
      const result = await dispatchTool(toolName, args);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    } catch (error) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: error.message
            }, null, 2)
          }
        ]
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

module.exports = {
  main,
  runAuditTool
};
