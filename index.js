const express = require("express");
const store = require("./lib/store");
const { analyzeConfig } = require("./lib/config-analyzer");
const { probeServer } = require("./lib/server-prober");
const { testPromptInjection } = require("./lib/injection-tester");
const { traceDataFlow } = require("./lib/dataflow-tracer");
const { scanPackage } = require("./lib/package-scanner");
const { generateReport } = require("./lib/report-generator");
const { createFinding } = require("./lib/findings");

const PORT = 3091;

function sanitizeExtraFields(result) {
  const extraFields = {};
  const blockedKeys = new Set(["id", "score", "grade", "findings", "findingsSummary", "executiveSummary", "generatedAt"]);

  for (const [key, value] of Object.entries(result || {})) {
    if (!blockedKeys.has(key)) {
      extraFields[key] = value;
    }
  }

  return extraFields;
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
      description: `${type} audit failed: ${error.message}`,
      remediation: "Repair the request payload or target environment and rerun the audit."
    });
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: [failureFinding],
      extraFields: {
        error: error.message
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
      res.status(500).json({
        error: error.message
      });
    }
  };
}

function createApp() {
  const app = express();
  app.use(express.json({ limit: "5mb" }));

  app.post("/audit/config", asyncRoute(async (req, res) => {
    if (typeof req.body.config !== "string") {
      res.status(400).json({ error: "config must be a JSON string." });
      return;
    }

    const result = await executeAuditJob("config", "mcp-config", async () => analyzeConfig(req.body.config));
    res.json(result);
  }));

  app.post("/audit/server", asyncRoute(async (req, res) => {
    if (!req.body.command || typeof req.body.command !== "string") {
      res.status(400).json({ error: "command must be a string." });
      return;
    }

    const args = Array.isArray(req.body.args) ? req.body.args : [];
    const env = req.body.env && typeof req.body.env === "object" ? req.body.env : undefined;
    const target = [req.body.command, ...args].join(" ").trim();
    const result = await executeAuditJob("server", target, async () => probeServer({
      command: req.body.command,
      args,
      env
    }));
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

    const result = await executeAuditJob("dataflow", "mcp-pipeline", async () => traceDataFlow(req.body.mcp_config, req.body.test_pii));
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

  app.get("/health", asyncRoute(async (req, res) => {
    store.ensureDatabase();
    res.json({
      status: "ok",
      service: "mcp-server-agent-security",
      port: PORT,
      timestamp: new Date().toISOString()
    });
  }));

  return app;
}

function startServer(port) {
  const app = createApp();
  return app.listen(port || PORT, () => {
    process.stdout.write(`mcp-server-agent-security listening on ${port || PORT}\n`);
  });
}

if (require.main === module) {
  startServer(PORT);
}

module.exports = {
  PORT,
  createApp,
  startServer,
  executeAuditJob,
  generateCombinedReport
};
