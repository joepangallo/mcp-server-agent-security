const { analyzeConfig } = require("../lib/config-analyzer");
const { probeServer } = require("../lib/server-prober");
const { testPromptInjection } = require("../lib/injection-tester");
const { traceDataFlow } = require("../lib/dataflow-tracer");
const { scanPackage } = require("../lib/package-scanner");
const { generateCombinedReport, PORT } = require("../index");

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
    description: "Launch a target MCP server over stdio, enumerate tools, and run active security probes.",
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
    description: "Evaluate a system prompt against a 30+ payload prompt injection battery.",
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
      required: ["system_prompt", "tools"]
    }
  },
  {
    name: "audit_agent_dataflow",
    description: "Trace tagged test data through MCP tool capabilities and identify exfiltration paths.",
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

async function callLocalApi(pathname, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1500);

  try {
    const response = await fetch(`http://127.0.0.1:${PORT}${pathname}`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify(payload || {}),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function runDirectTool(toolName, args) {
  switch (toolName) {
    case "audit_mcp_config":
      return analyzeConfig(args.config);
    case "audit_mcp_server":
      return probeServer({
        command: args.command,
        args: Array.isArray(args.args) ? args.args : [],
        env: args.env
      });
    case "audit_prompt_injection":
      return testPromptInjection(args.system_prompt, Array.isArray(args.tools) ? args.tools : []);
    case "audit_agent_dataflow":
      return traceDataFlow(args.mcp_config, args.test_pii);
    case "scan_mcp_package":
      return scanPackage(args.package_name);
    case "generate_report":
      return generateCombinedReport(Array.isArray(args.audit_ids) ? args.audit_ids : []);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

async function dispatchTool(toolName, args) {
  const httpMappings = {
    audit_mcp_config: "/audit/config",
    audit_mcp_server: "/audit/server",
    audit_prompt_injection: "/audit/injection",
    audit_agent_dataflow: "/audit/dataflow",
    scan_mcp_package: "/audit/package"
  };

  if (httpMappings[toolName]) {
    try {
      return await callLocalApi(httpMappings[toolName], args);
    } catch (error) {
      return runDirectTool(toolName, args);
    }
  }

  return runDirectTool(toolName, args);
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
  main
};
