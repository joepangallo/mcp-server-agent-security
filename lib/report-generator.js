const { dedupeFindings, summarizeFindings } = require("./findings");
const { uuidv4 } = require("./utils");

const severityPenalty = {
  critical: 20,
  high: 12,
  medium: 6,
  low: 2,
  info: 0
};

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function calculateCompositeScore(findings) {
  let score = 100;

  for (const finding of Array.isArray(findings) ? findings : []) {
    score -= severityPenalty[finding.severity] || 0;
  }

  return clampScore(score);
}

function calculateGrade(score) {
  if (score >= 97) {
    return "A+";
  }
  if (score >= 93) {
    return "A";
  }
  if (score >= 90) {
    return "A-";
  }
  if (score >= 87) {
    return "B+";
  }
  if (score >= 83) {
    return "B";
  }
  if (score >= 80) {
    return "B-";
  }
  if (score >= 77) {
    return "C+";
  }
  if (score >= 73) {
    return "C";
  }
  if (score >= 70) {
    return "C-";
  }
  if (score >= 67) {
    return "D+";
  }
  if (score >= 63) {
    return "D";
  }
  if (score >= 60) {
    return "D-";
  }
  return "F";
}

function generateExecutiveSummary(summary, score, grade, options) {
  const subject = options && options.target ? `Target ${options.target}` : "Target";
  const typeText = options && options.type ? `${options.type} audit` : "security audit";

  if (!summary.total) {
    return `${subject} completed a ${typeText} with no findings. Composite score ${score}/100 (${grade}).`;
  }

  const parts = [
    `${subject} completed a ${typeText} with score ${score}/100 (${grade}).`,
    `${summary.total} finding${summary.total === 1 ? "" : "s"} identified`
  ];

  const severityParts = [];
  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    if (summary[severity]) {
      severityParts.push(`${summary[severity]} ${severity}`);
    }
  }

  if (severityParts.length) {
    parts.push(`including ${severityParts.join(", ")}`);
  }

  if (summary.critical || summary.high) {
    parts.push("Immediate remediation is recommended for the highest-severity issues.");
  } else if (summary.medium || summary.low) {
    parts.push("The environment is serviceable but should be hardened before broader deployment.");
  } else {
    parts.push("No exploitable conditions were directly confirmed during this audit.");
  }

  return parts.join(" ");
}

function generateReport(options) {
  try {
    const auditResults = Array.isArray(options && options.auditResults) ? options.auditResults : [];
    const rawFindings = Array.isArray(options && options.findings)
      ? options.findings
      : auditResults.flatMap((result) => result.findings || []);
    const findings = dedupeFindings(rawFindings);
    const score = typeof (options && options.score) === "number" ? options.score : calculateCompositeScore(findings);
    const grade = options && options.grade ? options.grade : calculateGrade(score);
    const findingsSummary = summarizeFindings(findings);
    const generatedAt = options && options.generatedAt ? options.generatedAt : new Date().toISOString();
    const extraFields = options && options.extraFields && typeof options.extraFields === "object" ? options.extraFields : {};

    return {
      id: options && options.id ? options.id : uuidv4(),
      score,
      grade,
      findings,
      findingsSummary,
      executiveSummary: generateExecutiveSummary(findingsSummary, score, grade, options || {}),
      generatedAt,
      ...extraFields
    };
  } catch (error) {
    return {
      id: options && options.id ? options.id : uuidv4(),
      score: 0,
      grade: "F",
      findings: [],
      findingsSummary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      executiveSummary: "Failed to generate audit report.",
      generatedAt: new Date().toISOString()
    };
  }
}

module.exports = {
  calculateCompositeScore,
  calculateGrade,
  generateExecutiveSummary,
  generateReport
};
