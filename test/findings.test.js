const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createFinding,
  dedupeFindings,
  CWE_MAP,
  normalizeSeverity
} = require("../lib/findings");

test("deduplication removes identical findings", () => {
  const finding = {
    source: "test",
    severity: "high",
    confidence: "high",
    cwe: "shell_injection",
    description: "Duplicate issue",
    location: "server-a",
    remediation: "Fix it"
  };

  const result = dedupeFindings([finding, finding, finding]);
  assert.equal(result.length, 1, "three identical findings should deduplicate to one");
});

test("severity sorting works (critical before high before medium)", () => {
  const findings = [
    createFinding({ source: "test", severity: "low", description: "low issue", cwe: "CWE-20" }),
    createFinding({ source: "test", severity: "critical", description: "critical issue", cwe: "CWE-78" }),
    createFinding({ source: "test", severity: "medium", description: "medium issue", cwe: "CWE-200" }),
    createFinding({ source: "test", severity: "high", description: "high issue", cwe: "CWE-250" })
  ];

  const sorted = dedupeFindings(findings);
  assert.equal(sorted[0].severity, "critical");
  assert.equal(sorted[1].severity, "high");
  assert.equal(sorted[2].severity, "medium");
  assert.equal(sorted[3].severity, "low");
});

test("CWE mapping works for known keys", () => {
  const finding = createFinding({
    source: "test",
    severity: "high",
    cwe: "shell_injection",
    description: "test"
  });
  assert.equal(finding.cwe, "CWE-78");

  const finding2 = createFinding({
    source: "test",
    severity: "medium",
    cwe: "excessive_privilege",
    description: "test2"
  });
  assert.equal(finding2.cwe, "CWE-250");

  const finding3 = createFinding({
    source: "test",
    severity: "medium",
    cwe: "prompt_injection",
    description: "test3"
  });
  assert.equal(finding3.cwe, "CWE-74");
});

test("CWE mapping falls back for unknown keys", () => {
  const finding = createFinding({
    source: "test",
    severity: "low",
    cwe: "something_unknown",
    description: "unknown cwe"
  });
  assert.equal(finding.cwe, "CWE-693", "unknown CWE key should fall back to CWE-693");
});

test("CWE mapping passes through explicit CWE IDs", () => {
  const finding = createFinding({
    source: "test",
    severity: "low",
    cwe: "CWE-999",
    description: "explicit cwe"
  });
  assert.equal(finding.cwe, "CWE-999");
});
