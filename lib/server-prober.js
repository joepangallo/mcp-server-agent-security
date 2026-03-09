const { createFinding, dedupeFindings } = require("./findings");

let sdkPromise;

const probeCases = [
  {
    id: "null-input",
    category: "input_validation",
    label: "Null inputs",
    payload: null
  },
  {
    id: "oversized-input",
    category: "resource_limit",
    label: "Oversized string",
    payload: "A".repeat(100000)
  },
  {
    id: "special-characters",
    category: "input_validation",
    label: "Special characters",
    payload: "\"'`$(){}[]<>\\n\\r\\t"
  },
  {
    id: "path-traversal",
    category: "path_traversal",
    label: "Path traversal",
    payload: "../../etc/passwd"
  },
  {
    id: "sql-injection",
    category: "sql_injection",
    label: "SQL injection",
    payload: "' OR '1'='1' --"
  },
  {
    id: "shell-metacharacters",
    category: "shell_injection",
    label: "Shell metacharacters",
    payload: "; id && uname -a #"
  }
];

const infoDisclosurePatterns = [
  {
    id: "stack-trace",
    regex: /\bat\s+[A-Za-z0-9_.$<>]+\s+\((?:file:\/\/)?[^)]+:\d+:\d+\)/g,
    description: "stack trace"
  },
  {
    id: "unix-path",
    regex: /\/(?:Users|home|var|etc|opt|srv|tmp|root)\/[^\s"'`]+/g,
    description: "filesystem path"
  },
  {
    id: "windows-path",
    regex: /[A-Za-z]:\\(?:Users|Windows|Program Files|Temp)\\[^\s"'`]+/g,
    description: "Windows filesystem path"
  },
  {
    id: "aws-key",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    description: "AWS access key"
  },
  {
    id: "bearer-token",
    regex: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g,
    description: "bearer token"
  },
  {
    id: "openai-key",
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
    description: "API key"
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

async function loadClientSdk() {
  if (!sdkPromise) {
    sdkPromise = (async () => {
      const clientModule = await importFirst([
        "@modelcontextprotocol/sdk/client/index.js",
        "@modelcontextprotocol/sdk/dist/esm/client/index.js",
        "@modelcontextprotocol/sdk/dist/client/index.js"
      ]);
      const stdioModule = await importFirst([
        "@modelcontextprotocol/sdk/client/stdio.js",
        "@modelcontextprotocol/sdk/dist/esm/client/stdio.js",
        "@modelcontextprotocol/sdk/dist/client/stdio.js"
      ]);

      return {
        Client: clientModule.Client || (clientModule.default && clientModule.default.Client),
        StdioClientTransport: stdioModule.StdioClientTransport || (stdioModule.default && stdioModule.default.StdioClientTransport)
      };
    })();
  }

  return sdkPromise;
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise.finally(() => {
      if (timer) {
        clearTimeout(timer);
      }
    }),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
    })
  ]);
}

function normalizeTool(tool) {
  return {
    name: tool && tool.name ? String(tool.name) : "unknown_tool",
    description: tool && tool.description ? String(tool.description) : "",
    inputSchema: tool && (tool.inputSchema || tool.input_schema) ? (tool.inputSchema || tool.input_schema) : { type: "object" }
  };
}

function toolCorpus(tool) {
  return [tool.name || "", tool.description || "", JSON.stringify(tool.inputSchema || {})].join(" ").toLowerCase();
}

function classifyToolRisk(tool) {
  const corpus = toolCorpus(tool);
  if (/(shell|exec|command|terminal|bash|powershell|spawn)/.test(corpus)) {
    return "critical";
  }
  if (/(write|delete|filesystem|file|save|append|chmod|download|upload)/.test(corpus)) {
    return "high";
  }
  if (/(sql|database|query|postgres|sqlite|mysql|mongo)/.test(corpus)) {
    return "high";
  }
  if (/(http|fetch|webhook|request|post|send|email|slack|discord|s3|bucket|web)/.test(corpus)) {
    return "medium";
  }
  return "low";
}

function selectSchema(schema) {
  if (!schema || typeof schema !== "object") {
    return { type: "object" };
  }
  if (schema.anyOf && schema.anyOf.length) {
    return selectSchema(schema.anyOf[0]);
  }
  if (schema.oneOf && schema.oneOf.length) {
    return selectSchema(schema.oneOf[0]);
  }
  return schema;
}

function buildValueFromSchema(schema, payload, depth) {
  const currentDepth = typeof depth === "number" ? depth : 0;
  const effectiveSchema = selectSchema(schema);

  if (currentDepth > 3) {
    return typeof payload === "string" ? payload : null;
  }

  if (!effectiveSchema.type) {
    if (effectiveSchema.properties) {
      return buildValueFromSchema({ type: "object", properties: effectiveSchema.properties, required: effectiveSchema.required }, payload, currentDepth + 1);
    }
    return typeof payload === "string" ? payload : null;
  }

  switch (effectiveSchema.type) {
    case "object": {
      const result = {};
      const properties = effectiveSchema.properties || {};
      const propertyNames = Object.keys(properties);

      if (!propertyNames.length) {
        return {
          input: payload
        };
      }

      for (const propertyName of propertyNames) {
        result[propertyName] = buildValueFromSchema(properties[propertyName], payload, currentDepth + 1);
      }
      return result;
    }
    case "array":
      return [buildValueFromSchema(effectiveSchema.items || { type: "string" }, payload, currentDepth + 1)];
    case "integer":
    case "number":
      return typeof payload === "number" ? payload : payload === null ? 0 : -1;
    case "boolean":
      return false;
    case "null":
      return null;
    case "string":
    default:
      return payload === null ? "" : String(payload);
  }
}

function buildArgumentsForTool(tool, probeCase) {
  const schema = selectSchema(tool.inputSchema);
  if (probeCase.payload === null) {
    if (schema.type === "object" && schema.properties) {
      return Object.fromEntries(Object.keys(schema.properties).map((key) => [key, null]));
    }
    return { input: null };
  }

  const built = buildValueFromSchema(schema, probeCase.payload, 0);
  if (built && typeof built === "object" && !Array.isArray(built)) {
    return built;
  }
  return { input: built };
}

function responseToText(response) {
  if (!response) {
    return "";
  }

  if (typeof response === "string") {
    return response;
  }

  if (Array.isArray(response.content)) {
    return response.content.map((item) => {
      if (!item) {
        return "";
      }
      if (typeof item.text === "string") {
        return item.text;
      }
      return JSON.stringify(item);
    }).join("\n");
  }

  return JSON.stringify(response);
}

function detectInfoDisclosure(output) {
  const text = String(output || "");
  const hits = [];

  for (const pattern of infoDisclosurePatterns) {
    const matches = text.match(pattern.regex);
    if (matches && matches.length) {
      hits.push({
        type: pattern.id,
        description: pattern.description,
        samples: matches.slice(0, 3)
      });
    }
  }

  return hits;
}

async function safeCallTool(client, toolName, args, timeoutMs) {
  const startedAt = Date.now();

  try {
    const response = await withTimeout(client.callTool({ name: toolName, arguments: args }), timeoutMs || 5000, `Tool ${toolName}`);
    return {
      ok: true,
      durationMs: Date.now() - startedAt,
      response,
      text: responseToText(response)
    };
  } catch (error) {
    return {
      ok: false,
      durationMs: Date.now() - startedAt,
      error,
      text: String(error && error.message ? error.message : error)
    };
  }
}

async function openClientConnection(target) {
  const { Client, StdioClientTransport } = await loadClientSdk();

  if (!Client || !StdioClientTransport) {
    throw new Error("Unable to load the MCP client SDK classes.");
  }

  const transport = new StdioClientTransport({
    command: target.command,
    args: Array.isArray(target.args) ? target.args : [],
    env: target.env && typeof target.env === "object" ? { ...process.env, ...target.env } : process.env
  });
  const client = new Client(
    {
      name: "mcp-server-agent-security",
      version: "1.0.0"
    },
    {
      capabilities: {}
    }
  );

  await client.connect(transport);
  return { client, transport };
}

async function closeConnection(client, transport) {
  try {
    if (client && typeof client.close === "function") {
      await client.close();
    }
  } catch (error) {
    // Ignore close failures so transport cleanup still runs.
  }

  try {
    if (transport && typeof transport.close === "function") {
      await transport.close();
    }
  } catch (error) {
    // Ignore transport close failures during teardown.
  }
}

async function listServerTools(target) {
  const { client, transport } = await openClientConnection(target);

  try {
    const listed = await withTimeout(client.listTools(), 5000, "listTools");
    const tools = Array.isArray(listed && listed.tools) ? listed.tools.map(normalizeTool) : [];
    return {
      tools
    };
  } finally {
    await closeConnection(client, transport);
  }
}

function buildValidationFinding(tool, probeCase, result) {
  const inputSchema = selectSchema(tool.inputSchema);
  const requiredFields = Array.isArray(inputSchema.required) ? inputSchema.required.length : 0;

  if (probeCase.id === "null-input" && result.ok && requiredFields > 0) {
    return createFinding({
      source: "server-prober",
      severity: classifyToolRisk(tool) === "critical" ? "high" : "medium",
      confidence: "medium",
      cwe: "input_validation",
      location: tool.name,
      description: `Tool "${tool.name}" accepted null-like inputs despite declaring required fields.`,
      remediation: "Validate request bodies before tool execution and reject missing required properties."
    });
  }

  if (probeCase.id === "oversized-input" && result.ok && result.durationMs < 5000) {
    return createFinding({
      source: "server-prober",
      severity: classifyToolRisk(tool) === "high" || classifyToolRisk(tool) === "critical" ? "medium" : "low",
      confidence: "medium",
      cwe: "rate_limit",
      location: tool.name,
      description: `Tool "${tool.name}" processed a 100KB payload without visible size enforcement.`,
      remediation: "Apply request size limits and defensive parsing on tool input fields."
    });
  }

  return null;
}

function buildExploitFinding(tool, probeCase, result) {
  const text = result.text || "";

  if (probeCase.id === "path-traversal" && /etc\/passwd|root:.*:0:0|system32/i.test(text)) {
    return createFinding({
      source: "server-prober",
      severity: "critical",
      confidence: "high",
      cwe: "path_traversal",
      location: tool.name,
      description: `Tool "${tool.name}" appeared to disclose host filesystem contents when sent a traversal payload.`,
      remediation: "Canonicalize requested paths, reject parent-directory traversal, and pin access to an allowlisted root."
    });
  }

  if (probeCase.id === "shell-metacharacters" && /(uid=|gid=|Linux|Darwin|Windows NT|root:x:0:0)/i.test(text)) {
    return createFinding({
      source: "server-prober",
      severity: "critical",
      confidence: "high",
      cwe: "shell_injection",
      location: tool.name,
      description: `Tool "${tool.name}" responded in a way that suggests shell metacharacters reached command execution.`,
      remediation: "Remove shell invocation from the tool path or strictly separate command arguments from user input."
    });
  }

  if (probeCase.id === "sql-injection" && /(sql syntax|sqlite_error|postgres|mysql|syntax error at or near|unterminated quoted string)/i.test(text)) {
    return createFinding({
      source: "server-prober",
      severity: classifyToolRisk(tool) === "high" ? "high" : "medium",
      confidence: "medium",
      cwe: "sql_injection",
      location: tool.name,
      description: `Tool "${tool.name}" exposed SQL parser details when sent a classic injection payload.`,
      remediation: "Use parameterized queries and replace raw database errors with sanitized failure messages."
    });
  }

  return null;
}

async function runRateLimitProbe(client, tool) {
  const attemptCount = 8;
  const args = buildArgumentsForTool(tool, {
    id: "rate-limit",
    payload: "__rate_limit_probe__"
  });
  const startedAt = Date.now();
  const results = await Promise.all(Array.from({ length: attemptCount }, () => safeCallTool(client, tool.name, args, 2500)));
  const durationMs = Date.now() - startedAt;
  const successCount = results.filter((result) => result.ok).length;
  const rateLimited = results.some((result) => /rate limit|too many requests|thrott/i.test(result.text));

  return {
    attempted: attemptCount,
    successCount,
    rateLimited,
    durationMs
  };
}

async function probeServer(target) {
  const findings = [];
  let toolInventory = [];
  let client;
  let transport;

  try {
    ({ client, transport } = await openClientConnection(target));
    const listed = await withTimeout(client.listTools(), 5000, "listTools");
    toolInventory = Array.isArray(listed && listed.tools) ? listed.tools.map(normalizeTool) : [];

    for (const tool of toolInventory) {
      const probeResults = [];

      for (const probeCase of probeCases) {
        const args = buildArgumentsForTool(tool, probeCase);
        const result = await safeCallTool(client, tool.name, args, probeCase.id === "oversized-input" ? 8000 : 5000);
        const infoDisclosure = detectInfoDisclosure(result.text);
        const validationFinding = buildValidationFinding(tool, probeCase, result);
        const exploitFinding = buildExploitFinding(tool, probeCase, result);

        if (validationFinding) {
          findings.push(validationFinding);
        }

        if (exploitFinding) {
          findings.push(exploitFinding);
        }

        if (infoDisclosure.length) {
          findings.push(createFinding({
            source: "server-prober",
            severity: "high",
            confidence: "high",
            cwe: "info_disclosure",
            location: tool.name,
            description: `Tool "${tool.name}" leaked internal details in its probe response (${infoDisclosure.map((hit) => hit.description).join(", ")}).`,
            remediation: "Replace raw exception output with sanitized errors and scrub secrets, stack traces, and host paths from responses.",
            metadata: {
              probeCase: probeCase.id,
              disclosures: infoDisclosure
            }
          }));
        }

        probeResults.push({
          probe: probeCase.label,
          category: probeCase.category,
          ok: result.ok,
          durationMs: result.durationMs,
          outputSample: result.text.slice(0, 300),
          infoDisclosure
        });
      }

      const rateLimitResult = await runRateLimitProbe(client, tool);
      if (!rateLimitResult.rateLimited && rateLimitResult.successCount === rateLimitResult.attempted) {
        findings.push(createFinding({
          source: "server-prober",
          severity: ["critical", "high"].includes(classifyToolRisk(tool)) ? "medium" : "low",
          confidence: "medium",
          cwe: "rate_limit",
          location: tool.name,
          description: `Tool "${tool.name}" accepted ${rateLimitResult.attempted} rapid invocations without visible throttling.`,
          remediation: "Add request throttling or concurrency controls for high-impact tools to reduce abuse and resource exhaustion."
        }));
      }

      tool.probes = probeResults;
      tool.riskLevel = classifyToolRisk(tool);
      tool.rateLimit = rateLimitResult;
    }
  } catch (error) {
    findings.push(createFinding({
      source: "server-prober",
      severity: "critical",
      confidence: "high",
      cwe: "input_validation",
      description: `Unable to connect to or enumerate the target MCP server: ${error.message}`,
      remediation: "Verify the server launch command, stdio compatibility, and MCP SDK version before rerunning the audit."
    }));
  } finally {
    await closeConnection(client, transport);
  }

  return {
    tool_inventory: toolInventory,
    findings: dedupeFindings(findings)
  };
}

module.exports = {
  probeServer,
  listServerTools,
  classifyToolRisk
};
