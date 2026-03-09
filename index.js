const crypto = require("crypto");
const express = require("express");
const store = require("./lib/store");
const { analyzeConfig } = require("./lib/config-analyzer");
const { probeServer } = require("./lib/server-prober");
const { testPromptInjection } = require("./lib/injection-tester");
const { traceDataFlow } = require("./lib/dataflow-tracer");
const { scanPackage } = require("./lib/package-scanner");
const { generateReport } = require("./lib/report-generator");
const { createFinding } = require("./lib/findings");
const {
  MCP_COMMAND_ALLOWLIST,
  findDisallowedRuntimeEnvKeys,
  isAdminModeEnabled,
  isCommandAllowed
} = require("./lib/runtime-policy");

const PORT = Number.parseInt(process.env.AGENT_SECURITY_PORT || "", 10) || 3091;
const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";
const API_KEY = process.env.AGENT_SECURITY_API_KEY || "";
const ACTIVE_SERVER_PROBING_DISABLED_MESSAGE = "Active server probing is disabled. Set AGENT_SECURITY_ADMIN_MODE=1 to enable it.";

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

function isLoopbackAddress(address) {
  return !address || address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function sanitizeExtraFields(result) {
  const BLOCKED_KEYS = new Set([
    "id", "score", "grade", "findings", "findingsSummary", "executiveSummary",
    "generatedAt", "__proto__", "constructor", "prototype",
    // Sensitive probe data — never persist raw output or captured secrets
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
    try {
      if (Array.isArray(val)) {
        return val.map((v) => scrub(v, depth + 1));
      }

      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (!BLOCKED_KEYS.has(k)) {
          out[k] = scrub(v, depth + 1);
        }
      }
      return out;
    } finally {
      seen.delete(val);
    }
  }

  return scrub(result || {}, 0);
}

function formatDisallowedEnvMessage(keys) {
  return `env contains reserved runtime keys that cannot be overridden: ${keys.join(", ")}.`;
}

function sanitizeEnvInput(envInput) {
  if (envInput === undefined) {
    return undefined;
  }

  if (!isPlainObject(envInput)) {
    return null;
  }

  const env = {};
  for (const [key, value] of Object.entries(envInput)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof value !== "string") {
      return null;
    }
    env[key] = value;
  }

  return env;
}

function requireTrustedCaller(req, res, next) {
  if (API_KEY) {
    const bearerHeader = req.get("authorization") || "";
    const bearerToken = bearerHeader.startsWith("Bearer ") ? bearerHeader.slice(7).trim() : "";
    const candidateKey = req.get("x-api-key") || bearerToken || "";
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
  } else if (!isLoopbackAddress(req.socket && req.socket.remoteAddress)) {
    res.status(403).json({ error: "Audit API only accepts loopback clients unless AGENT_SECURITY_API_KEY is configured." });
    return;
  }

  next();
}

async function executeAuditJob(type, target, runner) {
  const audit = store.createAudit({
    type,
    target,
    status: "running",
    findings: {
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
    }
  });

  try {
    const result = await runner();
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: Array.isArray(result && result.findings) ? result.findings : [],
      extraFields: sanitizeExtraFields(result)
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
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: [failureFinding],
      extraFields: {
        error: "Audit failed. Check server logs for details."
      }
    });

    return store.updateAudit(audit.id, {
      status: "failed",
      score: report.score,
      grade: report.grade,
      findings: report
    });
  }
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
      // Never leak internal messages/paths to clients
      res.status(500).json({ error: "Internal audit error. Check server logs." });
    }
  };
}

function handleApplicationError(error, req, res, next) {
  if (res.headersSent) {
    next(error);
    return;
  }

  if (error && error.type === "entity.parse.failed") {
    res.status(400).json({ error: "Malformed JSON body." });
    return;
  }

  if (error && error.type === "entity.too.large") {
    res.status(413).json({ error: "Request body too large." });
    return;
  }

  res.status(500).json({ error: "Internal audit error. Check server logs." });
}

function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "5mb" }));
  app.use((req, res, next) => {
    res.set("cache-control", "no-store");
    next();
  });
  app.get("/health", asyncRoute(async (req, res) => {
    store.ensureDatabase();
    res.json({ status: "ok", service: "mcp-server-agent-security", timestamp: new Date().toISOString() });
  }));

  app.use(requireTrustedCaller);

  app.post("/audit/config", asyncRoute(async (req, res) => {
    if (typeof req.body.config !== "string") {
      res.status(400).json({ error: "config must be a JSON string." });
      return;
    }

    const result = await executeAuditJob("config", "mcp-config", async () => analyzeConfig(req.body.config));
    res.json(result);
  }));

  app.post("/audit/server", asyncRoute(async (req, res) => {
    if (!isAdminModeEnabled()) {
      res.status(403).json({ error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE });
      return;
    }

    if (!req.body.command || typeof req.body.command !== "string") {
      res.status(400).json({ error: "command must be a string." });
      return;
    }
    if (!isCommandAllowed(req.body.command, MCP_COMMAND_ALLOWLIST)) {
      res.status(400).json({ error: "Command not allowed. Permitted: " + [...MCP_COMMAND_ALLOWLIST].join(", ") });
      return;
    }

    if (req.body.args !== undefined && (!Array.isArray(req.body.args) || req.body.args.some((arg) => typeof arg !== "string"))) {
      res.status(400).json({ error: "args must be an array of strings." });
      return;
    }

    const env = sanitizeEnvInput(req.body.env);
    if (env === null) {
      res.status(400).json({ error: "env must be an object of string key/value pairs." });
      return;
    }

    const disallowedEnvKeys = findDisallowedRuntimeEnvKeys(env);
    if (disallowedEnvKeys.length) {
      res.status(400).json({ error: formatDisallowedEnvMessage(disallowedEnvKeys) });
      return;
    }

    const args = Array.isArray(req.body.args) ? req.body.args : [];
    const target = [req.body.command, ...args].join(" ").trim();
    const MAX_AUDIT_MS = 120_000;
    const result = await Promise.race([
      executeAuditJob("server", target, async () => probeServer({ command: req.body.command, args, env })),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Audit timed out after 120s")), MAX_AUDIT_MS))
    ]);
    res.json(result);
  }));

  app.post("/audit/injection", asyncRoute(async (req, res) => {
    if (typeof req.body.system_prompt !== "string") {
      res.status(400).json({ error: "system_prompt must be a string." });
      return;
    }

    const tools = Array.isArray(req.body.tools) ? req.body.tools.map((tool) => String(tool)) : [];
    const result = await executeAuditJob("injection", "prompt-surface", async () => testPromptInjection(req.body.system_prompt, tools));
    res.json(result);
  }));

  app.post("/audit/dataflow", asyncRoute(async (req, res) => {
    if (typeof req.body.mcp_config !== "string") {
      res.status(400).json({ error: "mcp_config must be a JSON string." });
      return;
    }

    const result = await executeAuditJob("dataflow", "mcp-pipeline", async () => traceDataFlow(req.body.mcp_config, req.body.test_pii, {
      adminModeEnabled: isAdminModeEnabled(),
      allowLiveEnumeration: isAdminModeEnabled(),
      commandAllowlist: MCP_COMMAND_ALLOWLIST
    }));
    res.json(result);
  }));

  app.post("/audit/package", asyncRoute(async (req, res) => {
    if (!req.body.package_name || typeof req.body.package_name !== "string") {
      res.status(400).json({ error: "package_name must be a string." });
      return;
    }

    const result = await executeAuditJob("package", req.body.package_name, async () => scanPackage(req.body.package_name));
    res.json(result);
  }));

  app.get("/report/:id", asyncRoute(async (req, res) => {
    const audit = store.getAudit(req.params.id);
    if (!audit) {
      res.status(404).json({ error: "Audit report not found." });
      return;
    }

    res.json(audit);
  }));

  // /health is registered before requireTrustedCaller above

  app.use(handleApplicationError);

  return app;
}

function startServer(port, host) {
  const listenPort = port ?? PORT;
  const listenHost = host ?? HOST;
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
  PORT,
  HOST,
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  createApp,
  startServer,
  executeAuditJob,
  generateCombinedReport,
  isAdminModeEnabled
};
