const fs = require("fs");
const os = require("os");
const path = require("path");
const { createFinding, dedupeFindings } = require("./findings");
const { stripDisallowedRuntimeEnvKeys } = require("./runtime-policy");
const { withTimeout, importFirst } = require("./utils");

let sdkPromise;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_TOOL_COUNT = 100;
const MAX_RESPONSE_TEXT = 20000;
const SHELL_EXECUTION_MARKER = "__MCPSEC_EXEC__";
const RUNTIME_SANDBOX_PREFIX = "mcp-agent-security-runtime-";
const RUNTIME_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "USERPROFILE",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "TERM",
  "SystemRoot",
  "ComSpec",
  "PATHEXT",
  "WINDIR"
];

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
    payload: `; echo ${SHELL_EXECUTION_MARKER} && id #`
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

function sanitizeEnvironment(envInput) {
  if (!envInput || typeof envInput !== "object" || Array.isArray(envInput)) {
    return undefined;
  }

  const env = {};
  for (const [key, value] of Object.entries(envInput)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }
    if (typeof value === "string") {
      env[key] = value;
    } else if (typeof value === "number" || typeof value === "boolean") {
      env[key] = String(value);
    }
  }

  return stripDisallowedRuntimeEnvKeys(env);
}

function buildRuntimeEnvironment(overrides, options) {
  const safeOverrides = stripDisallowedRuntimeEnvKeys(overrides) || {};
  const internalEnv = options && options.internalEnv && typeof options.internalEnv === "object" && !Array.isArray(options.internalEnv)
    ? options.internalEnv
    : {};
  const env = {};

  for (const key of RUNTIME_ENV_ALLOWLIST) {
    if (typeof internalEnv[key] === "string" && internalEnv[key]) {
      env[key] = internalEnv[key];
      continue;
    }
    if (typeof process.env[key] === "string" && process.env[key]) {
      env[key] = process.env[key];
    }
  }

  for (const [key, value] of Object.entries(internalEnv)) {
    if (typeof value === "string" && value) {
      env[key] = value;
    }
  }

  for (const [key, value] of Object.entries(safeOverrides)) {
    if (typeof value === "string" && value) {
      env[key] = value;
    }
  }

  return Object.keys(env).length ? env : undefined;
}

async function createRuntimeSandbox() {
  const rootDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), RUNTIME_SANDBOX_PREFIX));
  const homeDir = path.join(rootDir, "home");
  const configDir = path.join(rootDir, "config");
  const cacheDir = path.join(rootDir, "cache");
  const dataDir = path.join(rootDir, "data");

  await Promise.all([
    fs.promises.mkdir(homeDir, { recursive: true, mode: 0o700 }),
    fs.promises.mkdir(configDir, { recursive: true, mode: 0o700 }),
    fs.promises.mkdir(cacheDir, { recursive: true, mode: 0o700 }),
    fs.promises.mkdir(dataDir, { recursive: true, mode: 0o700 })
  ]);

  return {
    rootDir,
    env: {
      HOME: homeDir,
      USERPROFILE: homeDir,
      XDG_CONFIG_HOME: configDir,
      XDG_CACHE_HOME: cacheDir,
      XDG_DATA_HOME: dataDir
    }
  };
}

function sanitizeTarget(target) {
  if (!target || typeof target.command !== "string" || !target.command.trim()) {
    throw new Error("Target command must be a non-empty string.");
  }

  return {
    command: target.command,
    args: Array.isArray(target.args) ? target.args.map((value) => String(value)) : [],
    env: sanitizeEnvironment(target.env)
  };
}

function normalizeListedTools(listed) {
  const tools = Array.isArray(listed && listed.tools) ? listed.tools.map(normalizeTool) : [];
  return {
    tools: tools.slice(0, MAX_TOOL_COUNT),
    truncated: tools.length > MAX_TOOL_COUNT
  };
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
    return response.slice(0, MAX_RESPONSE_TEXT);
  }

  if (Array.isArray(response.content)) {
    return response.content.map((item) => {
      if (!item) {
        return "";
      }
      if (typeof item.text === "string") {
        return item.text.slice(0, MAX_RESPONSE_TEXT);
      }
      return JSON.stringify(item);
    }).join("\n").slice(0, MAX_RESPONSE_TEXT);
  }

  return JSON.stringify(response).slice(0, MAX_RESPONSE_TEXT);
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
        samples: matches.slice(0, 3).map((s) => {
          // Mask secret-like values: keep first 4 and last 4 chars, replace middle with ****
          if (s.length > 12) return s.slice(0, 4) + "****" + s.slice(-4);
          return "****";
        })
      });
    }
  }

  return hits;
}

function normalizeProbeText(text) {
  return String(text || "").replace(/\r\n/g, "\n");
}

function containsPayloadEcho(text, payload) {
  const normalizedText = normalizeProbeText(text).toLowerCase();
  const normalizedPayload = normalizeProbeText(payload).toLowerCase();
  return Boolean(normalizedPayload) && normalizedText.includes(normalizedPayload);
}

function hasConfirmedPathTraversalSignal(text, payload) {
  const normalizedText = normalizeProbeText(text);
  const passwdIndicators = [
    /(^|\n)root:[x*]:0:0:/i,
    /(^|\n)daemon:[x*]?:\d+:\d+:/i,
    /(^|\n)nobody:[x*]?:\d+:\d+:/i
  ];

  if (!passwdIndicators.some((pattern) => pattern.test(normalizedText))) {
    return false;
  }

  return !containsPayloadEcho(normalizedText, payload) || /(^|\n)(root|daemon|nobody):/i.test(normalizedText);
}

function hasConfirmedShellExecutionSignal(text, payload) {
  const normalizedText = normalizeProbeText(text);
  if (!normalizedText.includes(SHELL_EXECUTION_MARKER)) {
    return false;
  }

  if (!/\buid=\d+\b/i.test(normalizedText) && !/\bgid=\d+\b/i.test(normalizedText)) {
    return false;
  }

  return !containsPayloadEcho(normalizedText, payload) || /\buid=\d+\b/i.test(normalizedText) || /\bgid=\d+\b/i.test(normalizedText);
}

function hasLikelySqlInjectionSignal(text, payload) {
  const normalizedText = normalizeProbeText(text);
  const parserErrorPattern = /(syntax error at or near|unterminated quoted string|unclosed quotation mark|quoted string not properly terminated|sqlite[_ ]error|you have an error in your sql syntax)/i;

  if (!parserErrorPattern.test(normalizedText)) {
    return false;
  }

  return !containsPayloadEcho(normalizedText, payload) || parserErrorPattern.test(normalizedText);
}

async function safeCallTool(client, toolName, args, timeoutMs) {
  const startedAt = Date.now();

  try {
    const response = await withTimeout(client.callTool({ name: toolName, arguments: args }), timeoutMs || DEFAULT_TIMEOUT_MS, `Tool ${toolName}`);
    const isErrorResponse = response && response.isError === true;
    return {
      ok: !isErrorResponse,
      isError: isErrorResponse,
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

  const safeTarget = sanitizeTarget(target);
  const runtimeSandbox = await createRuntimeSandbox();
  const transport = new StdioClientTransport({
    command: safeTarget.command,
    args: safeTarget.args,
    env: buildRuntimeEnvironment(safeTarget.env, { internalEnv: runtimeSandbox.env }),
    stderr: "pipe"
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

  try {
    await withTimeout(client.connect(transport), DEFAULT_TIMEOUT_MS, "connect");
    return { client, transport, runtimeSandbox };
  } catch (error) {
    await closeConnection(client, transport, runtimeSandbox);
    throw error;
  }
}

async function closeConnection(client, transport, runtimeSandbox) {
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

  try {
    if (runtimeSandbox && runtimeSandbox.rootDir) {
      await fs.promises.rm(runtimeSandbox.rootDir, { recursive: true, force: true });
    }
  } catch (error) {
    // Ignore runtime sandbox cleanup failures during teardown.
  }
}

async function listServerTools(target) {
  const { client, transport, runtimeSandbox } = await openClientConnection(target);

  try {
    const listed = await withTimeout(client.listTools(), DEFAULT_TIMEOUT_MS, "listTools");
    const normalized = normalizeListedTools(listed);
    return {
      tools: normalized.tools,
      truncated: normalized.truncated
    };
  } finally {
    await closeConnection(client, transport, runtimeSandbox);
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

  if (probeCase.id === "path-traversal" && hasConfirmedPathTraversalSignal(text, probeCase.payload)) {
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

  if (probeCase.id === "shell-metacharacters" && hasConfirmedShellExecutionSignal(text, probeCase.payload)) {
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

  if (probeCase.id === "sql-injection" && hasLikelySqlInjectionSignal(text, probeCase.payload)) {
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
  let runtimeSandbox;

  try {
    ({ client, transport, runtimeSandbox } = await openClientConnection(target));
    const listed = await withTimeout(client.listTools(), DEFAULT_TIMEOUT_MS, "listTools");
    const normalized = normalizeListedTools(listed);
    toolInventory = normalized.tools;

    if (normalized.truncated) {
      findings.push(createFinding({
        source: "server-prober",
        severity: "medium",
        confidence: "high",
        cwe: "rate_limit",
        description: `Target MCP server exposed more than ${MAX_TOOL_COUNT} tools; probing was capped to avoid audit-side resource exhaustion.`,
        remediation: "Reduce the exposed tool surface or implement paging and per-request limits before enabling broad automated probing."
      }));
    }

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
          outputSample: "[redacted]",
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
      description: "Unable to connect to or enumerate the target MCP server.",
      remediation: "Verify the server launch command, stdio compatibility, and MCP SDK version before rerunning the audit."
    }));
  } finally {
    await closeConnection(client, transport, runtimeSandbox);
  }

  return {
    tool_inventory: toolInventory,
    findings: dedupeFindings(findings)
  };
}

module.exports = {
  probeServer,
  listServerTools,
  classifyToolRisk,
  testOnly: {
    SHELL_EXECUTION_MARKER,
    buildRuntimeEnvironment,
    createRuntimeSandbox,
    hasConfirmedPathTraversalSignal,
    hasConfirmedShellExecutionSignal,
    hasLikelySqlInjectionSignal
  }
};
