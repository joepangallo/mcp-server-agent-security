const crypto = require("crypto");

const Severity = Object.freeze({
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info"
});

const severityOrder = {
  [Severity.CRITICAL]: 5,
  [Severity.HIGH]: 4,
  [Severity.MEDIUM]: 3,
  [Severity.LOW]: 2,
  [Severity.INFO]: 1
};

const confidenceOrder = {
  high: 3,
  medium: 2,
  low: 1
};

const CWE_MAP = Object.freeze({
  excessive_privilege: "CWE-250",
  insecure_transport: "CWE-319",
  missing_auth: "CWE-306",
  shell_injection: "CWE-78",
  path_traversal: "CWE-22",
  sql_injection: "CWE-89",
  input_validation: "CWE-20",
  prompt_injection: "CWE-74",
  tool_authorization: "CWE-285",
  info_disclosure: "CWE-200",
  secret_leakage: "CWE-201",
  rate_limit: "CWE-770",
  package_vulnerability: "CWE-1104",
  unsafe_eval: "CWE-95",
  unsafe_file_write: "CWE-73",
  permission_misconfiguration: "CWE-732",
  data_exfiltration: "CWE-359"
});

const cvssBySeverity = {
  [Severity.CRITICAL]: 9.8,
  [Severity.HIGH]: 8.1,
  [Severity.MEDIUM]: 6.4,
  [Severity.LOW]: 3.7,
  [Severity.INFO]: 0.0
};

function stableHash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 12);
}

function normalizeSeverity(severity) {
  const normalized = String(severity || "").toLowerCase();
  return severityOrder[normalized] ? normalized : Severity.INFO;
}

function normalizeConfidence(confidence) {
  const normalized = String(confidence || "").toLowerCase();
  return confidenceOrder[normalized] ? normalized : "medium";
}

function resolveCwe(cwe) {
  if (!cwe) {
    return "CWE-693";
  }

  if (String(cwe).toUpperCase().startsWith("CWE-")) {
    return String(cwe).toUpperCase();
  }

  return CWE_MAP[cwe] || "CWE-693";
}

function estimateCvss(finding) {
  try {
    const severity = normalizeSeverity(finding && finding.severity);
    const confidence = normalizeConfidence(finding && finding.confidence);
    const baseScore = cvssBySeverity[severity];
    const confidenceAdjustment = confidence === "high" ? 0.5 : confidence === "low" ? -0.3 : 0;
    return Number(Math.max(0, Math.min(10, baseScore + confidenceAdjustment)).toFixed(1));
  } catch (error) {
    return cvssBySeverity[Severity.INFO];
  }
}

function buildFindingId(finding) {
  const fingerprint = [
    finding.source || "audit-engine",
    resolveCwe(finding.cwe || finding.cweType),
    normalizeSeverity(finding.severity),
    String(finding.description || "").trim().toLowerCase(),
    String(finding.location || "").trim().toLowerCase(),
    JSON.stringify(finding.metadata || {})
  ].join("|");
  return `${(finding.source || "finding").replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${stableHash(fingerprint)}`;
}

function normalizeFinding(finding) {
  try {
    const normalized = {
      source: finding && finding.source ? String(finding.source) : "audit-engine",
      id: finding && finding.id ? String(finding.id) : undefined,
      severity: normalizeSeverity(finding && finding.severity),
      confidence: normalizeConfidence(finding && finding.confidence),
      description: finding && finding.description ? String(finding.description) : "No description provided.",
      cwe: resolveCwe(finding && (finding.cwe || finding.cweType)),
      remediation: finding && finding.remediation ? String(finding.remediation) : "Review the affected component and apply least-privilege and input validation controls.",
      location: finding && finding.location ? String(finding.location) : undefined,
      metadata: finding && finding.metadata && typeof finding.metadata === "object" ? finding.metadata : {}
    };

    normalized.cvss = typeof (finding && finding.cvss) === "number" ? finding.cvss : estimateCvss(normalized);
    normalized.id = normalized.id || buildFindingId(normalized);
    return normalized;
  } catch (error) {
    return {
      source: "audit-engine",
      id: `finding-${stableHash(Date.now())}`,
      severity: Severity.INFO,
      confidence: "low",
      description: "Failed to normalize a finding.",
      cwe: "CWE-693",
      cvss: 0,
      remediation: "Inspect the audit engine output and repair malformed finding records.",
      metadata: {
        error: error.message
      }
    };
  }
}

function createFinding(finding) {
  return normalizeFinding(finding || {});
}

function compareFindings(left, right) {
  const severityDelta = severityOrder[right.severity] - severityOrder[left.severity];
  if (severityDelta !== 0) {
    return severityDelta;
  }

  const confidenceDelta = confidenceOrder[right.confidence] - confidenceOrder[left.confidence];
  if (confidenceDelta !== 0) {
    return confidenceDelta;
  }

  return left.description.localeCompare(right.description);
}

function dedupeFindings(findings) {
  const deduped = new Map();

  try {
    for (const rawFinding of Array.isArray(findings) ? findings : []) {
      const finding = normalizeFinding(rawFinding);
      const key = [
        finding.source,
        finding.cwe,
        finding.location || "",
        finding.description.trim().toLowerCase()
      ].join("|");
      const existing = deduped.get(key);

      if (!existing) {
        deduped.set(key, finding);
        continue;
      }

      deduped.set(key, compareFindings(finding, existing) < 0 ? finding : existing);
    }
  } catch (error) {
    return (Array.isArray(findings) ? findings : []).map(normalizeFinding).sort(compareFindings);
  }

  return Array.from(deduped.values()).sort(compareFindings);
}

function summarizeFindings(findings) {
  const summary = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of Array.isArray(findings) ? findings : []) {
    const severity = normalizeSeverity(finding.severity);
    summary.total += 1;
    summary[severity] += 1;
  }

  return summary;
}

module.exports = {
  Severity,
  CWE_MAP,
  createFinding,
  normalizeFinding,
  normalizeSeverity,
  normalizeConfidence,
  estimateCvss,
  dedupeFindings,
  summarizeFindings
};
