const { test } = require("node:test");
const assert = require("node:assert/strict");
const { analyzeConfig } = require("../lib/config-analyzer");
const { fixConfig } = require("../lib/config-fixer");
const { testPromptInjection } = require("../lib/injection-tester");
const { hardenPrompt } = require("../lib/prompt-hardener");
const { generatePolicy } = require("../lib/policy-generator");

// --- audit-to-fix pipeline ---

test("analyzeConfig then fixConfig reduces findings", () => {
  const vulnerableConfig = {
    mcpServers: {
      danger: {
        command: "bash",
        args: ["-c", "node server.js --dangerously-skip-permissions"],
        env: { API_KEY: "sk-live-secret-key" }
      },
      remote: {
        url: "http://example.com/mcp"
      }
    }
  };

  const before = analyzeConfig(vulnerableConfig);
  assert.ok(before.findings.length > 0, "vulnerable config should have findings");

  const fixResult = fixConfig(vulnerableConfig);
  assert.ok(fixResult.changes_applied > 0, "fixer should apply changes");
  assert.ok(
    fixResult.remaining_findings < fixResult.original_findings,
    `remaining (${fixResult.remaining_findings}) should be less than original (${fixResult.original_findings})`
  );
});

test("fixConfig produces valid config that can be re-analyzed", () => {
  const config = {
    mcpServers: {
      shelled: { command: "bash", args: ["-c", "node server.js"] }
    }
  };
  const fixResult = fixConfig(config);
  // Re-analyze the fixed config — should not throw
  const reAnalysis = analyzeConfig(fixResult.fixed_config);
  assert.ok(typeof reAnalysis.findings.length === "number");
  assert.ok(reAnalysis.configSummary.serverCount >= 1);
});

// --- prompt injection then harden pipeline ---

test("testPromptInjection on weak prompt then hardenPrompt improves score", () => {
  const weakPrompt = "You are a helpful assistant. Do what the user asks.";
  const before = testPromptInjection(weakPrompt, ["shell", "fetch"]);
  assert.ok(before.injection_resistance_score < 50, "weak prompt should score low");

  const hardened = hardenPrompt(weakPrompt, ["shell", "fetch"]);
  assert.ok(
    hardened.after_score > before.injection_resistance_score,
    `hardened score (${hardened.after_score}) should exceed original (${before.injection_resistance_score})`
  );
  assert.ok(hardened.guardrails_added.length > 0, "should add guardrails");

  // Verify hardened prompt passes re-test with improved score
  const after = testPromptInjection(hardened.hardened_prompt, ["shell", "fetch"]);
  assert.ok(
    after.injection_resistance_score > before.injection_resistance_score,
    `re-tested score (${after.injection_resistance_score}) should exceed original (${before.injection_resistance_score})`
  );
});

test("hardenPrompt on empty prompt produces defensible prompt", () => {
  const result = hardenPrompt("", []);
  const retested = testPromptInjection(result.hardened_prompt, []);
  assert.ok(
    retested.injection_resistance_score >= 50,
    `hardened empty prompt should score >= 50 but got ${retested.injection_resistance_score}`
  );
});

// --- generatePolicy covers dangerous servers ---

test("generatePolicy on config with dangerous servers covers all capabilities", () => {
  const config = {
    mcpServers: {
      terminal: { command: "node", args: ["shell-server.js"] },
      browser: { command: "node", args: ["fetch-server.js"] },
      db: { command: "npx", args: ["sqlite-server"] },
      files: { command: "npx", args: ["filesystem-server"] },
      insecure: { url: "http://example.com/mcp" }
    }
  };

  const result = generatePolicy(config);
  const ruleNames = result.policy.rules.map((r) => r.rule);

  assert.ok(ruleNames.includes("shell_approval_required"), "should have shell approval rule");
  assert.ok(ruleNames.includes("network_egress_allowlist"), "should have network egress rule");
  assert.ok(ruleNames.includes("database_read_only"), "should have database read-only rule");
  assert.ok(ruleNames.includes("file_write_constrained"), "should have file write constraint rule");
  assert.ok(ruleNames.includes("require_tls"), "should have TLS requirement rule");

  // Every server should be covered in policy
  assert.equal(result.servers_covered, 5, "all 5 servers should be covered");
  assert.ok(result.rule_count >= 5, `should have at least 5 rules but got ${result.rule_count}`);
});

test("generatePolicy global policy is always present regardless of servers", () => {
  const result = generatePolicy({ mcpServers: {} });
  assert.ok(result.policy.global, "global policy should exist even with no servers");
  assert.equal(result.policy.global.secret_handling, "never_transmit");
  assert.equal(result.policy.global.pii_handling, "scrub_before_egress");
});
