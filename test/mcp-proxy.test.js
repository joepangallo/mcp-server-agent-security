const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const mcpModule = require("../mcp/index.js");

describe("MCP proxy — tool definitions", () => {
  it("defines exactly 9 tools", () => {
    const expectedTools = [
      "audit_mcp_config",
      "audit_mcp_server",
      "audit_prompt_injection",
      "audit_agent_dataflow",
      "scan_mcp_package",
      "generate_report",
      "fix_mcp_config",
      "harden_system_prompt",
      "generate_policy",
    ];
    assert.deepEqual(
      mcpModule.testOnly.toolDefinitions.map((tool) => tool.name),
      expectedTools
    );
  });
});

describe("MCP proxy — runAuditTool", () => {
  it("returns error for unknown tool names", async () => {
    const result = await mcpModule.runAuditTool("nonexistent_tool", {});
    assert.ok(result.error);
    assert.match(result.error, /Unknown tool/i);
  });

  it("generate_report validates audit_ids is non-empty", async () => {
    const result = await mcpModule.runAuditTool("generate_report", {
      audit_ids: [],
    });
    assert.ok(result.error);
    assert.match(result.error, /non-empty/i);
  });

  it("generate_report validates audit_ids max length of 25", async () => {
    const ids = Array.from({ length: 26 }, (_, i) => `id-${i}`);
    const result = await mcpModule.runAuditTool("generate_report", {
      audit_ids: ids,
    });
    assert.ok(result.error);
    assert.match(result.error, /at most 25/i);
  });

  it("generate_report requires audit_ids to be an array", async () => {
    const result = await mcpModule.runAuditTool("generate_report", {
      audit_ids: "not-an-array",
    });
    assert.ok(result.error);
    assert.match(result.error, /non-empty/i);
  });

  it("handles non-object args gracefully", async () => {
    // Should not throw; runAuditTool coerces bad args to {}
    const result = await mcpModule.runAuditTool("nonexistent_tool", null);
    assert.ok(result.error);
  });

  it("handles array args gracefully", async () => {
    const result = await mcpModule.runAuditTool("nonexistent_tool", [1, 2]);
    assert.ok(result.error);
  });

  it("blocks audit_mcp_server without AGENT_SECURITY_ADMIN_MODE=1", async () => {
    const previousValue = process.env.AGENT_SECURITY_ADMIN_MODE;
    delete process.env.AGENT_SECURITY_ADMIN_MODE;

    try {
      const result = await mcpModule.runAuditTool("audit_mcp_server", {
        command: "node",
        args: ["server.js"],
      });
      assert.match(result.error, /AGENT_SECURITY_ADMIN_MODE=1/);
    } finally {
      if (previousValue === undefined) {
        delete process.env.AGENT_SECURITY_ADMIN_MODE;
      } else {
        process.env.AGENT_SECURITY_ADMIN_MODE = previousValue;
      }
    }
  });

  it("generate_report combines multiple reports into one composite report", () => {
    const combined = mcpModule.testOnly.combineReports([
      {
        id: "a",
        findings: [
          { severity: "high", source: "a", cwe: "shell_injection", description: "Issue A" },
          { severity: "high", source: "a", cwe: "shell_injection", description: "Issue A" },
        ],
      },
      {
        id: "b",
        findings: [
          { severity: "medium", source: "b", cwe: "info_disclosure", description: "Issue B" },
        ],
      },
    ], ["a", "b"]);

    assert.equal(combined.type, "report");
    assert.equal(combined.status, "completed");
    assert.equal(combined.findings.length, 2);
    assert.equal(combined.findingsSummary.high, 1);
    assert.equal(combined.findingsSummary.medium, 1);
    assert.equal(combined.score, 82);
    assert.equal(combined.grade, "B-");
  });
});

describe("MCP proxy — rate limiting", () => {
  it("tracks mcpRequestCount across calls", async () => {
    // Each call to runAuditTool increments the counter.
    // We just verify it doesn't throw for a burst of calls.
    const promises = [];
    for (let i = 0; i < 5; i++) {
      promises.push(mcpModule.runAuditTool("nonexistent_tool", {}));
    }
    const results = await Promise.all(promises);
    // All should return errors (unknown tool or rate limit), not throw
    for (const r of results) {
      assert.ok(r.error);
    }
  });

  it("returns rate limit error when limit exceeded", async () => {
    // Call 31 times rapidly — the 31st should hit the rate limit
    // (assuming the window hasn't reset). We can't fully reset internal
    // state, but we verify the function handles it without crashing.
    const results = [];
    for (let i = 0; i < 35; i++) {
      results.push(await mcpModule.runAuditTool("nonexistent_tool", {}));
    }
    // At least one should mention rate limit (after 30 in the window)
    const rateLimited = results.some(
      (r) => r.error && /rate limit/i.test(r.error)
    );
    assert.equal(rateLimited, true);
    assert.ok(results.every((r) => r.error));
  });
});

describe("MCP proxy — main export", () => {
  it("exports main as a function", () => {
    assert.equal(typeof mcpModule.main, "function");
  });

  it("exports runAuditTool as a function", () => {
    assert.equal(typeof mcpModule.runAuditTool, "function");
  });
});
