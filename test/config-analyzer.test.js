const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeConfig } = require("../lib/config-analyzer");

test("detects shell interpreter launch (bash -c)", () => {
  const result = analyzeConfig({
    mcpServers: {
      dangerous: {
        command: "bash",
        args: ["-c", "node server.js"]
      }
    }
  });

  const shellFinding = result.findings.find(
    (f) => f.cwe === "CWE-78" && /shell interpreter/i.test(f.description)
  );
  assert.ok(shellFinding, "should flag bash -c as shell injection risk");
  assert.equal(shellFinding.severity, "critical");
});

test("detects exposed secrets in env vars", () => {
  const result = analyzeConfig({
    mcpServers: {
      leaky: {
        command: "node",
        args: ["server.js"],
        env: {
          STRIPE_SECRET_KEY: "sk_live_abc123",
          API_KEY: "key-xyz",
          HARMLESS_VAR: "hello"
        }
      }
    }
  });

  const secretFindings = result.findings.filter(
    (f) => f.cwe === "CWE-201"
  );
  assert.ok(secretFindings.length >= 2, "should flag STRIPE_SECRET_KEY and API_KEY");

  const descriptions = secretFindings.map((f) => f.description).join(" ");
  assert.ok(descriptions.includes("STRIPE_SECRET_KEY"), "should mention STRIPE_SECRET_KEY");
  assert.ok(descriptions.includes("API_KEY"), "should mention API_KEY");

  const harmlessFindings = result.findings.filter(
    (f) => f.description.includes("HARMLESS_VAR")
  );
  assert.equal(harmlessFindings.length, 0, "should not flag HARMLESS_VAR");
});

test("passes clean config with no findings", () => {
  const result = analyzeConfig({
    mcpServers: {
      safe: {
        command: "npx",
        args: ["@modelcontextprotocol/server-memory"]
      }
    }
  });

  const criticalOrHigh = result.findings.filter(
    (f) => f.severity === "critical" || f.severity === "high"
  );
  // A memory server with npx may get a medium finding but should not get critical/high
  // related to shell injection or secret leakage
  const shellOrSecret = result.findings.filter(
    (f) => f.cwe === "CWE-78" || f.cwe === "CWE-201"
  );
  assert.equal(shellOrSecret.length, 0, "clean config should have no shell injection or secret leakage findings");
});

test("detects wildcard/unsafe args patterns", () => {
  const result = analyzeConfig({
    mcpServers: {
      loose: {
        command: "npx",
        args: ["some-server", "--dangerously-skip-permissions"]
      }
    }
  });

  const unsafeFlagFinding = result.findings.find(
    (f) => f.cwe === "CWE-250" && /disable or weaken security/i.test(f.description)
  );
  assert.ok(unsafeFlagFinding, "should flag --dangerously-skip-permissions");
  assert.equal(unsafeFlagFinding.severity, "high");
});
