const test = require("node:test");
const assert = require("node:assert/strict");
const { generateReport } = require("../lib/report-generator");

test("generateReport ignores extraFields that try to override score and grade", () => {
  const report = generateReport({
    findings: [
      {
        source: "test",
        severity: "critical",
        confidence: "high",
        description: "Critical issue",
        cwe: "CWE-78",
        remediation: "Fix it"
      }
    ],
    extraFields: {
      score: 999,
      grade: "Z"
    }
  });

  // The computed score for one critical finding: 100 - 20 = 80
  assert.equal(report.score, 80, "score should be computed, not from extraFields");
  assert.equal(report.grade, "B-", "grade should be computed, not from extraFields");
  assert.notEqual(report.score, 999);
  assert.notEqual(report.grade, "Z");
});

test("generateReport calculates score and grade from finding severities", () => {
  const report = generateReport({
    findings: [
      {
        source: "test",
        severity: "critical",
        confidence: "high",
        description: "Critical issue",
        cwe: "CWE-78",
        remediation: "Fix it"
      },
      {
        source: "test",
        severity: "medium",
        confidence: "medium",
        description: "Medium issue",
        cwe: "CWE-20",
        remediation: "Fix it"
      }
    ]
  });

  assert.equal(report.score, 74);
  assert.equal(report.grade, "C");
  assert.equal(report.findingsSummary.critical, 1);
  assert.equal(report.findingsSummary.medium, 1);
});
