const { analyzeConfig, parseConfig, getServerEntries } = require("../lib/config-analyzer");
const { probeServer } = require("../lib/server-prober");
const { testPromptInjection } = require("../lib/injection-tester");
const { traceDataFlow } = require("../lib/dataflow-tracer");
const { scanPackage } = require("../lib/package-scanner");
const { fixConfig } = require("../lib/config-fixer");
const { hardenPrompt } = require("../lib/prompt-hardener");
const { generatePolicy } = require("../lib/policy-generator");
const {
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  executeAuditJob,
  generateCombinedReport,
  isAdminModeEnabled,
  testOnly: {
    isSafeNpmPackageSpec,
    sanitizeConfigLaunchTargets,
    validateServerLaunchSpec
  }
} = require("../index");
const {
  MCP_COMMAND_ALLOWLIST
} = require("../lib/runtime-policy");

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
  },
  {
    name: "fix_mcp_config",
    description: "Auto-remediate security issues in an MCP config: remove unsafe flags, strip shell wrappers, upgrade transport to TLS, redact inline secrets, add auth placeholders, and constrain filesystem scope. Returns the hardened config and a changelog.",
    inputSchema: {
      type: "object",
      properties: {
        config: {
          type: "string",
          description: "Raw MCP config JSON to fix."
        }
      },
      required: ["config"]
    }
  },
  {
    name: "harden_system_prompt",
    description: "Analyze a system prompt for injection vulnerabilities and return a hardened version with security guardrails appended. Shows before/after injection resistance scores.",
    inputSchema: {
      type: "object",
      properties: {
        system_prompt: {
          type: "string",
          description: "The system prompt to harden."
        },
        tools: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Tool names available to the agent (used for risk assessment)."
        }
      },
      required: ["system_prompt"]
    }
  },
  {
    name: "generate_policy",
    description: "Generate a JSON security policy from an MCP config that can be enforced by a proxy or middleware. Includes capability-based rules for shell approval, network egress allowlists, file write constraints, database read-only defaults, and rate limits.",
    inputSchema: {
      type: "object",
      properties: {
        mcp_config: {
          type: "string",
          description: "Raw MCP config JSON to generate policy from."
        },
        allowed_destinations: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Optional list of allowed outbound domains (e.g. ['*.github.com'])."
        },
        allowed_paths: {
          type: "array",
          items: {
            type: "string"
          },
          description: "Optional list of allowed file write paths (e.g. ['./output/'])."
        }
      },
      required: ["mcp_config"]
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

const MAX_JSON_INPUT_CHARS = 1_000_000;
const MAX_SYSTEM_PROMPT_CHARS = 200_000;
const MAX_TOOLS = 64;
const MAX_TOOL_LENGTH = 256;

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function validateStringInput(value, fieldName, maxLength) {
  if (typeof value !== "string") {
    return `${fieldName} must be a string.`;
  }
  if (value.length > maxLength) {
    return `${fieldName} exceeds the maximum allowed length.`;
  }
  return null;
}

function validateToolsArray(tools) {
  if (tools === undefined) {
    return null;
  }
  if (!Array.isArray(tools) || tools.length > MAX_TOOLS) {
    return `tools must be an array of at most ${MAX_TOOLS} strings.`;
  }
  for (const tool of tools) {
    if (typeof tool !== "string" || tool.length > MAX_TOOL_LENGTH) {
      return `Each tool must be a string of at most ${MAX_TOOL_LENGTH} characters.`;
    }
  }
  return null;
}

async function runAuditTool(toolName, args) {
  const safeArgs = isPlainObject(args) ? args : {};

  switch (toolName) {
    case "audit_mcp_config": {
      const configErr = validateStringInput(safeArgs.config, "config", MAX_JSON_INPUT_CHARS);
      if (configErr) {
        return { error: configErr };
      }
      return executeAuditJob("config", "mcp-config", async () => analyzeConfig(safeArgs.config));
    }
    case "audit_mcp_server": {
      if (!isAdminModeEnabled()) {
        return { error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE };
      }
      const validatedLaunch = validateServerLaunchSpec(safeArgs.command, safeArgs.args, safeArgs.env);
      if (validatedLaunch.error) {
        return { error: validatedLaunch.error };
      }
      const target = [validatedLaunch.command, ...validatedLaunch.args].join(" ").trim();
      return executeAuditJob("server", target, async () => probeServer({
        command: validatedLaunch.command,
        args: validatedLaunch.args,
        env: validatedLaunch.env
      }));
    }
    case "audit_prompt_injection": {
      const promptErr = validateStringInput(safeArgs.system_prompt, "system_prompt", MAX_SYSTEM_PROMPT_CHARS);
      if (promptErr) {
        return { error: promptErr };
      }
      const toolsErr = validateToolsArray(safeArgs.tools);
      if (toolsErr) {
        return { error: toolsErr };
      }
      return executeAuditJob("injection", "prompt-surface", async () => testPromptInjection(
        safeArgs.system_prompt,
        Array.isArray(safeArgs.tools) ? safeArgs.tools.map((value) => String(value)) : []
      ));
    }
    case "audit_agent_dataflow": {
      const dfConfigErr = validateStringInput(safeArgs.mcp_config, "mcp_config", MAX_JSON_INPUT_CHARS);
      if (dfConfigErr) {
        return { error: dfConfigErr };
      }
      let parsedConfig;
      try {
        parsedConfig = parseConfig(safeArgs.mcp_config);
      } catch (error) {
        return { error: error.message };
      }

      const serverEntries = getServerEntries(parsedConfig);
      const containsLocalLaunchers = serverEntries.some(([, server]) => server && typeof server.command === "string" && server.command.trim());
      if (containsLocalLaunchers && !isAdminModeEnabled()) {
        return { error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE };
      }

      const sanitizedConfig = sanitizeConfigLaunchTargets(parsedConfig);
      if (sanitizedConfig.error) {
        return { error: sanitizedConfig.error };
      }

      return executeAuditJob("dataflow", "mcp-pipeline", async () => traceDataFlow(sanitizedConfig.parsed, safeArgs.test_pii, {
        adminModeEnabled: isAdminModeEnabled(),
        allowLiveEnumeration: isAdminModeEnabled(),
        commandAllowlist: MCP_COMMAND_ALLOWLIST
      }));
    }
    case "scan_mcp_package": {
      const pkgErr = validateStringInput(safeArgs.package_name, "package_name", MAX_JSON_INPUT_CHARS);
      if (pkgErr) {
        return { error: pkgErr };
      }
      if (!isSafeNpmPackageSpec(safeArgs.package_name.trim())) {
        return { error: "package_name must be a valid npm registry package identifier." };
      }
      return executeAuditJob("package", safeArgs.package_name.trim(), async () => scanPackage(safeArgs.package_name.trim()));
    }
    case "generate_report":
      return generateCombinedReport(Array.isArray(safeArgs.audit_ids) ? safeArgs.audit_ids.map((value) => String(value)) : []);
    case "fix_mcp_config": {
      const fixConfigErr = validateStringInput(safeArgs.config, "config", MAX_JSON_INPUT_CHARS);
      if (fixConfigErr) {
        return { error: fixConfigErr };
      }
      return executeAuditJob("fix", "mcp-config", async () => fixConfig(safeArgs.config));
    }
    case "harden_system_prompt": {
      const hardenPromptErr = validateStringInput(safeArgs.system_prompt, "system_prompt", MAX_SYSTEM_PROMPT_CHARS);
      if (hardenPromptErr) {
        return { error: hardenPromptErr };
      }
      const hardenToolsErr = validateToolsArray(safeArgs.tools);
      if (hardenToolsErr) {
        return { error: hardenToolsErr };
      }
      return executeAuditJob("harden", "prompt-surface", async () => hardenPrompt(
        safeArgs.system_prompt,
        Array.isArray(safeArgs.tools) ? safeArgs.tools.map((value) => String(value)) : []
      ));
    }
    case "generate_policy": {
      const policyConfigErr = validateStringInput(safeArgs.mcp_config, "mcp_config", MAX_JSON_INPUT_CHARS);
      if (policyConfigErr) {
        return { error: policyConfigErr };
      }
      let parsedPolicyConfig;
      try {
        parsedPolicyConfig = parseConfig(safeArgs.mcp_config);
      } catch (error) {
        return { error: error.message };
      }
      return executeAuditJob("policy", "mcp-pipeline", async () => generatePolicy(parsedPolicyConfig, {
        allowed_destinations: Array.isArray(safeArgs.allowed_destinations) ? safeArgs.allowed_destinations : undefined,
        allowed_paths: Array.isArray(safeArgs.allowed_paths) ? safeArgs.allowed_paths : undefined
      }));
    }
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
      version: "1.1.0"
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
      const isToolError = Boolean(result && typeof result === "object" && typeof result.error === "string" && result.error);
      return {
        ...(isToolError ? { isError: true } : {}),
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
