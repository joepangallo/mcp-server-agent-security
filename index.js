const crypto = require("crypto");
const express = require("express");
const store = require("./lib/store");
const { isPlainObject, withTimeout } = require("./lib/utils");
const { analyzeConfig, parseConfig, getServerEntries } = require("./lib/config-analyzer");
const { probeServer } = require("./lib/server-prober");
const { testPromptInjection } = require("./lib/injection-tester");
const { traceDataFlow } = require("./lib/dataflow-tracer");
const { scanPackage } = require("./lib/package-scanner");
const { generateReport } = require("./lib/report-generator");
const { createFinding } = require("./lib/findings");
const { fixConfig } = require("./lib/config-fixer");
const { hardenPrompt } = require("./lib/prompt-hardener");
const { generatePolicy } = require("./lib/policy-generator");
const {
  MCP_COMMAND_ALLOWLIST,
  DISALLOWED_RUNTIME_ENV_KEYS,
  DANGEROUS_ENV_PATTERNS,
  findDisallowedRuntimeEnvKeys,
  isAdminModeEnabled,
  isDangerousEnvKey,
  normalizeEnvKey
} = require("./lib/runtime-policy");
const {
  MAX_COMMAND_LENGTH,
  MAX_ARGS,
  MAX_ARG_LENGTH,
  MAX_ENV_KEYS,
  MAX_ENV_VALUE_LENGTH,
  MAX_JSON_INPUT_CHARS,
  MAX_SYSTEM_PROMPT_CHARS,
  MAX_TOOLS,
  MAX_TOOL_LENGTH,
  MAX_PACKAGE_NAME_LENGTH,
  MAX_TEST_PII_LENGTH,
  MAX_SERVERS_PER_CONFIG,
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  NPX_ALLOWED_FLAGS
} = require("./lib/constants");
const {
  isSafeNpmPackageSpec,
  parseJsonInput,
  sanitizeConfigLaunchTargets,
  sanitizeToolsInput,
  validateConfigTopology,
  validateServerLaunchSpec,
  configContainsCommandLaunchers,
  sanitizeEnvInput
} = require("./lib/validation");

const PORT = Number.parseInt(process.env.AGENT_SECURITY_PORT || "", 10) || 3091;
const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";
const API_KEY = process.env.AGENT_SECURITY_API_KEY || "";

const COMMAND_ALLOWLIST = MCP_COMMAND_ALLOWLIST;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RESERVED_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const RESERVED_RUNTIME_ENV_KEYS = DISALLOWED_RUNTIME_ENV_KEYS;
const INTERNAL_AUDIT_ACCESS_FIELD = "_access";

const RATE_WINDOW_MS = Number.parseInt(process.env.AGENT_SECURITY_RATE_WINDOW_MS || "", 10) || 60_000;
const MAX_PROTECTED_REQUESTS_PER_WINDOW = Number.parseInt(process.env.AGENT_SECURITY_RATE_LIMIT || "", 10) || 30;
const MAX_HEALTH_REQUESTS_PER_WINDOW = Number.parseInt(process.env.AGENT_SECURITY_HEALTH_RATE_LIMIT || "", 10) || 60;
const MAX_CONCURRENT_AUDITS = Number.parseInt(process.env.AGENT_SECURITY_MAX_CONCURRENT_AUDITS || "", 10) || 2;
const MAX_CONCURRENT_AUDITS_PER_CALLER = Number.parseInt(process.env.AGENT_SECURITY_MAX_CONCURRENT_AUDITS_PER_CALLER || "", 10) || 1;
const MAX_AUDIT_MS = Number.parseInt(process.env.AGENT_SECURITY_AUDIT_TIMEOUT_MS || "", 10) || 120_000;

const requestWindows = new Map();
let activeAuditCount = 0;
const activeAuditCountsByCaller = new Map();

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

function getRemoteAddress(req) {
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
}

function isLoopbackAddress(address) {
  return !address || address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function hasForwardingHeaders(req) {
  return Boolean(req.get("forwarded") || req.get("x-forwarded-for") || req.get("x-real-ip"));
}

function getPresentedCredential(req) {
  const bearerHeader = req.get("authorization") || "";
  const bearerToken = bearerHeader.startsWith("Bearer ") ? bearerHeader.slice(7).trim() : "";
  return req.get("x-api-key") || bearerToken || "";
}

function hashValue(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 16);
}

function getCallerFingerprint(req) {
  const presentedCredential = getPresentedCredential(req);
  const remoteAddress = getRemoteAddress(req);

  if (presentedCredential) {
    return `key:${hashValue(presentedCredential)}:ip:${remoteAddress}`;
  }

  return `ip:${remoteAddress}`;
}

function consumeRateLimit(key, limit, windowMs) {
  const now = Date.now();
  let bucket = requestWindows.get(key);

  if (!bucket || bucket.resetAt <= now) {
    bucket = {
      count: 0,
      resetAt: now + windowMs
    };
  }

  if (bucket.count >= limit) {
    requestWindows.set(key, bucket);
    return {
      allowed: false,
      retryAfterMs: Math.max(1, bucket.resetAt - now)
    };
  }

  bucket.count += 1;
  requestWindows.set(key, bucket);

  if (requestWindows.size > 4096) {
    for (const [entryKey, entryValue] of requestWindows.entries()) {
      if (entryValue.resetAt <= now) {
        requestWindows.delete(entryKey);
      }
    }
  }

  return {
    allowed: true,
    retryAfterMs: 0
  };
}

function rateLimitMiddleware(scope, limit) {
  return (req, res, next) => {
    const key = scope === "health"
      ? `health:${getRemoteAddress(req)}`
      : scope === "protected-attempt"
        ? `protected-attempt:${getRemoteAddress(req)}`
      : `${scope}:${getCallerFingerprint(req)}`;
    const result = consumeRateLimit(key, limit, RATE_WINDOW_MS);

    if (!result.allowed) {
      res.set("retry-after", String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
      res.status(429).json({ error: "Rate limit exceeded. Please retry shortly." });
      return;
    }

    next();
  };
}

function acquireAuditSlot(callerFingerprint) {
  if (activeAuditCount >= MAX_CONCURRENT_AUDITS) {
    return {
      ok: false,
      retryAfterSeconds: 5,
      message: "Too many audit jobs are already running. Retry shortly."
    };
  }

  const callerCount = activeAuditCountsByCaller.get(callerFingerprint) || 0;
  if (callerCount >= MAX_CONCURRENT_AUDITS_PER_CALLER) {
    return {
      ok: false,
      retryAfterSeconds: 5,
      message: "This caller already has an audit job in progress. Retry shortly."
    };
  }

  activeAuditCount += 1;
  activeAuditCountsByCaller.set(callerFingerprint, callerCount + 1);

  let released = false;
  return {
    ok: true,
    release() {
      if (released) {
        return;
      }

      released = true;
      activeAuditCount = Math.max(0, activeAuditCount - 1);

      const nextCallerCount = (activeAuditCountsByCaller.get(callerFingerprint) || 1) - 1;
      if (nextCallerCount <= 0) {
        activeAuditCountsByCaller.delete(callerFingerprint);
      } else {
        activeAuditCountsByCaller.set(callerFingerprint, nextCallerCount);
      }
    }
  };
}

function sanitizeExtraFields(result) {
  const BLOCKED_KEYS = new Set([
    "id", "score", "grade", "findings", "findingsSummary", "executiveSummary",
    "generatedAt", INTERNAL_AUDIT_ACCESS_FIELD, ...RESERVED_OBJECT_KEYS,
    "outputSample", "disclosures", "rawOutput", "samples", "text", "response"
  ]);
  const seen = new WeakSet();

  function scrub(val, depth) {
    if (val === null || typeof val !== "object") {
      return val;
    }
    if (depth > 6) {
      return Array.isArray(val) ? [] : "[truncated]";
    }
    if (seen.has(val)) {
      return "[circular]";
    }

    seen.add(val);
    if (Array.isArray(val)) {
      try {
        return val.map((value) => scrub(value, depth + 1));
      } finally {
        seen.delete(val);
      }
    }

    try {
      const out = {};
      for (const [key, value] of Object.entries(val)) {
        if (!BLOCKED_KEYS.has(key)) {
          out[key] = scrub(value, depth + 1);
        }
      }
      return out;
    } finally {
      seen.delete(val);
    }
  }

  return scrub(result || {}, 0);
}

function buildAuditAccessControl(req) {
  return {
    ownerFingerprint: getCallerFingerprint(req)
  };
}

function getAuditAccessControl(audit) {
  return isPlainObject(audit && audit[INTERNAL_AUDIT_ACCESS_FIELD])
    ? audit[INTERNAL_AUDIT_ACCESS_FIELD]
    : null;
}

function sanitizeAuditResponse(audit) {
  if (!isPlainObject(audit)) {
    return audit;
  }

  const sanitizedAudit = { ...audit };
  delete sanitizedAudit[INTERNAL_AUDIT_ACCESS_FIELD];
  return sanitizedAudit;
}

function canReadAudit(req, audit) {
  const accessControl = getAuditAccessControl(audit);
  if (!accessControl || typeof accessControl.ownerFingerprint !== "string" || !accessControl.ownerFingerprint) {
    return !API_KEY && isLoopbackAddress(getRemoteAddress(req));
  }

  return accessControl.ownerFingerprint === getCallerFingerprint(req);
}

function requireTrustedCaller(req, res, next) {
  if (API_KEY) {
    const candidateKey = getPresentedCredential(req);
    const keyLen = Buffer.byteLength(API_KEY);
    const keyBuf = Buffer.alloc(keyLen);
    const candBuf = Buffer.alloc(keyLen);
    keyBuf.write(API_KEY);
    candBuf.write(candidateKey.slice(0, keyLen));
    const validKey = candidateKey.length === API_KEY.length && crypto.timingSafeEqual(keyBuf, candBuf);
    if (!validKey) {
      res.status(401).json({ error: "Unauthorized." });
      return;
    }
  } else if (!isLoopbackAddress(req.socket && req.socket.remoteAddress) || hasForwardingHeaders(req)) {
    res.status(403).json({ error: "Audit API only accepts direct loopback clients unless AGENT_SECURITY_API_KEY is configured." });
    return;
  }

  next();
}

async function executeAuditJob(type, target, runner, options = {}) {
  const accessControl = isPlainObject(options.accessControl) ? options.accessControl : null;
  const initialFindings = {
    findings: [],
    findingsSummary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    executiveSummary: "Audit is in progress.",
    generatedAt: new Date().toISOString()
  };

  if (accessControl) {
    initialFindings[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
  }

  const audit = store.createAudit({
    type,
    target,
    status: "running",
    findings: initialFindings
  });

  try {
    const result = await runner();
    const extraFields = sanitizeExtraFields(result);
    if (accessControl) {
      extraFields[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
    }
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: Array.isArray(result && result.findings) ? result.findings : [],
      extraFields
    });

    return store.updateAudit(audit.id, {
      status: "completed",
      score: report.score,
      grade: report.grade,
      findings: report
    });
  } catch (error) {
    const failureFinding = createFinding({
      source: "http-api",
      severity: "high",
      confidence: "high",
      cwe: "input_validation",
      description: `${type} audit encountered an internal error.`,
      remediation: "Repair the request payload or target environment and rerun the audit."
    });
    const extraFields = {
      error: "Audit failed. Check server logs for details."
    };
    if (accessControl) {
      extraFields[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
    }
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: [failureFinding],
      extraFields
    });

    return store.updateAudit(audit.id, {
      status: "failed",
      score: report.score,
      grade: report.grade,
      findings: report
    });
  }
}

async function executeManagedAudit(req, res, type, target, runner, timeoutMs) {
  const callerFingerprint = getCallerFingerprint(req);
  const accessControl = buildAuditAccessControl(req);
  const slot = acquireAuditSlot(callerFingerprint);

  if (!slot.ok) {
    res.set("retry-after", String(slot.retryAfterSeconds));
    res.status(429).json({ error: slot.message });
    return null;
  }

  const runnerPromise = Promise.resolve().then(runner);
  runnerPromise.finally(() => slot.release());

  return executeAuditJob(
    type,
    target,
    async () => withTimeout(runnerPromise, timeoutMs || MAX_AUDIT_MS, `${type} audit`),
    { accessControl }
  );
}

async function generateCombinedReport(auditIds) {
  const ids = Array.isArray(auditIds) ? auditIds.filter(Boolean) : [];

  if (!ids.length) {
    throw new Error("At least one audit ID is required.");
  }

  const audits = ids.map((id) => store.getAudit(id)).filter(Boolean);
  if (!audits.length) {
    throw new Error("No matching audits were found.");
  }

  const missingAuditIds = ids.filter((id) => !audits.find((audit) => audit.id === id));
  const report = generateReport({
    type: "report",
    target: ids.join(", "),
    auditResults: audits,
    extraFields: {
      sourceAuditIds: ids,
      missingAuditIds
    }
  });

  return store.createAudit({
    id: report.id,
    type: "report",
    target: ids.join(", "),
    status: "completed",
    score: report.score,
    grade: report.grade,
    findings: report,
    completed_at: report.generatedAt
  });
}

function asyncRoute(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal audit error. Check server logs." });
      }
    }
  };
}

function createApp() {
  const app = express();
  app.disable("x-powered-by");

  app.use((req, res, next) => {
    res.set("cache-control", "no-store");
    next();
  });

  app.get("/health", rateLimitMiddleware("health", MAX_HEALTH_REQUESTS_PER_WINDOW), asyncRoute(async (req, res) => {
    store.ensureDatabase();
    res.json({ status: "ok", service: "mcp-server-agent-security", timestamp: new Date().toISOString() });
  }));

  app.use(rateLimitMiddleware("protected-attempt", MAX_PROTECTED_REQUESTS_PER_WINDOW));
  app.use(requireTrustedCaller);
  app.use(rateLimitMiddleware("protected", MAX_PROTECTED_REQUESTS_PER_WINDOW));
  app.use((req, res, next) => {
    if (["POST", "PUT", "PATCH"].includes(req.method) && !req.is("application/json")) {
      res.status(415).json({ error: "Content-Type must be application/json." });
      return;
    }
    next();
  });
  app.use(express.json({ limit: "5mb" }));
  app.use((error, req, res, next) => {
    if (!error) {
      next();
      return;
    }
    if (error.type === "entity.too.large") {
      res.status(413).json({ error: "Request body exceeds the 5mb limit." });
      return;
    }
    if (error.type === "entity.parse.failed" || error instanceof SyntaxError) {
      res.status(400).json({ error: "Malformed JSON body." });
      return;
    }
    next(error);
  });
  app.use((req, res, next) => {
    if (["POST", "PUT", "PATCH"].includes(req.method) && req.body != null && !isPlainObject(req.body)) {
      res.status(400).json({ error: "Request body must be a JSON object." });
      return;
    }
    next();
  });

  app.post("/audit/config", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("config", req.body.config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "config",
      "mcp-config",
      async () => analyzeConfig(validatedConfig.parsed),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/server", asyncRoute(async (req, res) => {
    if (!isAdminModeEnabled()) {
      res.status(403).json({ error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE });
      return;
    }

    const validatedTarget = validateServerLaunchSpec(req.body.command, req.body.args, req.body.env);
    if (validatedTarget.error) {
      res.status(400).json({ error: validatedTarget.error });
      return;
    }

    const target = [validatedTarget.command, ...validatedTarget.args].join(" ").trim();
    const result = await executeManagedAudit(
      req,
      res,
      "server",
      target,
      async () => probeServer(validatedTarget),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/injection", asyncRoute(async (req, res) => {
    if (typeof req.body.system_prompt !== "string" || !req.body.system_prompt.trim()) {
      res.status(400).json({ error: "system_prompt must be a non-empty string." });
      return;
    }
    if (req.body.system_prompt.length > MAX_SYSTEM_PROMPT_CHARS) {
      res.status(400).json({ error: "system_prompt exceeds the maximum size." });
      return;
    }

    const tools = sanitizeToolsInput(req.body.tools);
    if (tools === null) {
      res.status(400).json({ error: `tools must be an array of at most ${MAX_TOOLS} non-empty strings.` });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "injection",
      "prompt-surface",
      async () => testPromptInjection(req.body.system_prompt, tools),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/dataflow", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("mcp_config", req.body.mcp_config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "mcp_config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    if (configContainsCommandLaunchers(validatedConfig.serverEntries) && !isAdminModeEnabled()) {
      res.status(403).json({ error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE });
      return;
    }

    const normalizedConfig = sanitizeConfigLaunchTargets(validatedConfig.parsed);
    if (normalizedConfig.error) {
      res.status(400).json({ error: normalizedConfig.error });
      return;
    }

    if (req.body.test_pii !== undefined && typeof req.body.test_pii !== "string") {
      res.status(400).json({ error: "test_pii must be a string when provided." });
      return;
    }
    if (typeof req.body.test_pii === "string" && req.body.test_pii.length > MAX_TEST_PII_LENGTH) {
      res.status(400).json({ error: "test_pii exceeds the maximum size." });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "dataflow",
      "mcp-pipeline",
      async () => traceDataFlow(normalizedConfig.parsed, req.body.test_pii),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/package", asyncRoute(async (req, res) => {
    if (typeof req.body.package_name !== "string") {
      res.status(400).json({ error: "package_name must be a string." });
      return;
    }

    const packageName = req.body.package_name.trim();
    if (!isSafeNpmPackageSpec(packageName)) {
      res.status(400).json({ error: "package_name must be a valid npm registry package identifier." });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "package",
      packageName,
      async () => scanPackage(packageName),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.get("/report/:id", asyncRoute(async (req, res) => {
    if (!UUID_PATTERN.test(req.params.id)) {
      res.status(400).json({ error: "Audit report id must be a UUID." });
      return;
    }

    const audit = store.getAudit(req.params.id);
    if (!audit || !canReadAudit(req, audit)) {
      res.status(404).json({ error: "Audit report not found." });
      return;
    }

    res.json(sanitizeAuditResponse(audit));
  }));

  app.post("/fix/config", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("config", req.body.config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "fix",
      "mcp-config",
      async () => fixConfig(validatedConfig.parsed),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/fix/prompt", asyncRoute(async (req, res) => {
    if (typeof req.body.system_prompt !== "string" || !req.body.system_prompt.trim()) {
      res.status(400).json({ error: "system_prompt must be a non-empty string." });
      return;
    }

    if (req.body.system_prompt.length > MAX_SYSTEM_PROMPT_CHARS) {
      res.status(400).json({ error: `system_prompt exceeds ${MAX_SYSTEM_PROMPT_CHARS} characters.` });
      return;
    }

    const tools = sanitizeToolsInput(req.body.tools);
    if (tools === null) {
      res.status(400).json({ error: `tools must be an array of at most ${MAX_TOOLS} non-empty strings.` });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "harden",
      "prompt-surface",
      async () => hardenPrompt(req.body.system_prompt, tools),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/fix/policy", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("mcp_config", req.body.mcp_config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "mcp_config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    const normalizedConfig = sanitizeConfigLaunchTargets(validatedConfig.parsed);
    if (normalizedConfig.error) {
      res.status(400).json({ error: normalizedConfig.error });
      return;
    }

    const opts = {};
    if (Array.isArray(req.body.allowed_destinations)) {
      opts.allowed_destinations = req.body.allowed_destinations.slice(0, 50).map((d) => String(d).slice(0, 256));
    }
    if (Array.isArray(req.body.allowed_paths)) {
      opts.allowed_paths = req.body.allowed_paths.slice(0, 50).map((p) => String(p).slice(0, 1024));
    }

    const result = await executeManagedAudit(
      req,
      res,
      "policy",
      "mcp-pipeline",
      async () => generatePolicy(normalizedConfig.parsed, opts),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  return app;
}

function startServer(port, host) {
  const listenPort = port || PORT;
  const listenHost = host || HOST;
  if (!isLoopbackHost(listenHost) && !API_KEY) {
    throw new Error("Refusing to bind the audit API to a non-loopback interface without AGENT_SECURITY_API_KEY.");
  }

  const app = createApp();
  return app.listen(listenPort, listenHost, () => {
    process.stdout.write(`mcp-server-agent-security listening on ${listenHost}:${listenPort}\n`);
  });
}

if (require.main === module) {
  startServer(PORT, HOST);
}

module.exports = {
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  PORT,
  HOST,
  createApp,
  startServer,
  executeAuditJob,
  generateCombinedReport,
  isAdminModeEnabled,
  testOnly: {
    buildAuditAccessControl,
    canReadAudit,
    getCallerFingerprint,
    getRemoteAddress,
    isSafeNpmPackageSpec,
    rateLimitMiddleware,
    sanitizeAuditResponse,
    sanitizeConfigLaunchTargets,
    validateServerLaunchSpec
  }
};
