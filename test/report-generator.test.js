const test = require("node:test");
const assert = require("node:assert/strict");
const { generateReport } = require("../lib/report-generator");

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
