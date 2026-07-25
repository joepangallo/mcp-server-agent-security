const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const mcpModule = require("../mcp/index.js");

describe("MCP proxy — tool definitions", () => {
  it("defines exactly 10 tools", () => {
    const expectedTools = [
      "audit_mcp_config",
      "audit_mcp_server",
      "audit_agent_trust",
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
        trust: { score: 91 },
        findings: [
          { severity: "high", source: "a", cwe: "shell_injection", description: "Issue A" },
          { severity: "high", source: "a", cwe: "shell_injection", description: "Issue A" },
        ],
      },
      {
        id: "b",
        trust: { score: 74 },
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
    assert.equal(combined.trustSummary.minimumScore, 74);
    assert.equal(combined.trustSummary.averageScore, 83);
  });

  it("returns hosted auth guidance on 401 when no API key is configured", async () => {
    const savedBaseUrl = process.env.AGENT_SECURITY_BASE_URL;
    const savedApiKey = process.env.AGENT_SECURITY_API_KEY;
    const originalFetch = global.fetch;

    process.env.AGENT_SECURITY_BASE_URL = "https://audit.leddconsulting.com";
    delete process.env.AGENT_SECURITY_API_KEY;
    global.fetch = async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ error: "Unauthorized." })
    });

    delete require.cache[require.resolve("../index.js")];
    delete require.cache[require.resolve("../mcp/index.js")];
    const freshModule = require("../mcp/index.js");

    try {
      const result = await freshModule.runAuditTool("audit_mcp_config", {
        config: "{\"mcpServers\":{}}"
      });
      assert.match(result.error, /AGENT_SECURITY_API_KEY/);
      assert.match(result.error, /audit\.leddconsulting\.com/);
    } finally {
      global.fetch = originalFetch;

      if (savedBaseUrl === undefined) {
        delete process.env.AGENT_SECURITY_BASE_URL;
      } else {
        process.env.AGENT_SECURITY_BASE_URL = savedBaseUrl;
      }

      if (savedApiKey === undefined) {
        delete process.env.AGENT_SECURITY_API_KEY;
      } else {
        process.env.AGENT_SECURITY_API_KEY = savedApiKey;
      }

      delete require.cache[require.resolve("../index.js")];
      delete require.cache[require.resolve("../mcp/index.js")];
    }
  });
});

describe("MCP proxy — unreachable backend", () => {
  const AUDIT_ENV_KEYS = [
    "AGENT_SECURITY_BASE_URL",
    "AGENT_SECURITY_API_KEY",
    "AGENT_SECURITY_HOST",
    "AGENT_SECURITY_PORT"
  ];

  function withAuditEnv(overrides, run) {
    const saved = {};
    for (const key of AUDIT_ENV_KEYS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
    for (const [key, value] of Object.entries(overrides)) {
      process.env[key] = value;
    }

    const originalFetch = global.fetch;
    delete require.cache[require.resolve("../index.js")];
    delete require.cache[require.resolve("../mcp/index.js")];

    try {
      return run(() => require("../mcp/index.js"));
    } finally {
      global.fetch = originalFetch;
      for (const key of AUDIT_ENV_KEYS) {
        if (saved[key] === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = saved[key];
        }
      }
      delete require.cache[require.resolve("../index.js")];
      delete require.cache[require.resolve("../mcp/index.js")];
    }
  }

  it("maps a bare 'fetch failed' TypeError to actionable setup guidance", async () => {
    await withAuditEnv({}, async (load) => {
      global.fetch = async () => {
        const error = new TypeError("fetch failed");
        error.cause = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:3091"), {
          code: "ECONNREFUSED"
        });
        throw error;
      };

      const freshModule = load();
      const result = await freshModule.runAuditTool("audit_mcp_config", {
        config: "{\"mcpServers\":{}}"
      });

      assert.ok(result.error);
      assert.notEqual(result.error, "fetch failed");
      assert.match(result.error, /http:\/\/127\.0\.0\.1:3091/);
      assert.match(result.error, /ECONNREFUSED/);
      assert.match(result.error, /AGENT_SECURITY_API_KEY/);
      assert.match(result.error, /AGENT_SECURITY_BASE_URL/);
    });
  });

  it("rewrites 403 responses into user-actionable key guidance", async () => {
    await withAuditEnv(
      {
        AGENT_SECURITY_BASE_URL: "https://audit.example.com",
        AGENT_SECURITY_API_KEY: "test-key"
      },
      async (load) => {
        global.fetch = async () => ({
          ok: false,
          status: 403,
          text: async () => JSON.stringify({
            error: "Audit API only accepts direct loopback clients unless AGENT_SECURITY_API_KEY is configured"
          })
        });

        const freshModule = load();
        const result = await freshModule.runAuditTool("audit_mcp_config", {
          config: "{\"mcpServers\":{}}"
        });

        assert.ok(result.error);
        assert.match(result.error, /403/);
        assert.match(result.error, /AGENT_SECURITY_API_KEY was not accepted/);
        assert.match(result.error, /audit\.example\.com/);
        assert.doesNotMatch(result.error, /loopback/i);
      }
    );
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
