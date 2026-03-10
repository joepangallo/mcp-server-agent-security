const store = require("./store");
const { isPlainObject, withTimeout } = require("./utils");
const { generateReport } = require("./report-generator");
const { createFinding } = require("./findings");

const RESERVED_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const INTERNAL_AUDIT_ACCESS_FIELD = "_access";

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

module.exports = {
  executeAuditJob,
  generateCombinedReport,
  sanitizeExtraFields,
  INTERNAL_AUDIT_ACCESS_FIELD
};
