const test = require("node:test");
const assert = require("node:assert/strict");
const { runAuditTool } = require("../mcp/index");

test("audit_mcp_server requires AGENT_SECURITY_ADMIN_MODE=1 exactly", async () => {
  const originalAdminMode = process.env.AGENT_SECURITY_ADMIN_MODE;

  try {
    process.env.AGENT_SECURITY_ADMIN_MODE = "0";
    const disabledResult = await runAuditTool("audit_mcp_server", { command: "node" });
    assert.match(disabledResult.error, /AGENT_SECURITY_ADMIN_MODE=1/);

    process.env.AGENT_SECURITY_ADMIN_MODE = "true";
    const truthyResult = await runAuditTool("audit_mcp_server", { command: "node" });
    assert.match(truthyResult.error, /AGENT_SECURITY_ADMIN_MODE=1/);

    process.env.AGENT_SECURITY_ADMIN_MODE = "1";
    const allowlistResult = await runAuditTool("audit_mcp_server", { command: "bash" });
    assert.match(allowlistResult.error, /Command not allowed/);

    const envOverrideResult = await runAuditTool("audit_mcp_server", {
      command: "node",
      env: {
        PATH: "/tmp/evil-bin"
      }
    });
    assert.match(envOverrideResult.error, /reserved runtime keys/i);
  } finally {
    if (originalAdminMode === undefined) {
      delete process.env.AGENT_SECURITY_ADMIN_MODE;
    } else {
      process.env.AGENT_SECURITY_ADMIN_MODE = originalAdminMode;
    }
  }
});

test("audit_mcp_server rejects malformed env input", async () => {
  const originalAdminMode = process.env.AGENT_SECURITY_ADMIN_MODE;

  try {
    process.env.AGENT_SECURITY_ADMIN_MODE = "1";
    const result = await runAuditTool("audit_mcp_server", {
      command: "node",
      env: ["not-an-object"]
    });
    assert.match(result.error, /env/i);
  } finally {
    if (originalAdminMode === undefined) {
      delete process.env.AGENT_SECURITY_ADMIN_MODE;
    } else {
      process.env.AGENT_SECURITY_ADMIN_MODE = originalAdminMode;
    }
  }
});

test("MCP rate limit: 30 calls succeed, 31st is rejected", async () => {
  const { _testOnly } = require("../mcp/index");
  _testOnly.resetRateLimits();

  // First 30 calls should all succeed (not return rate limit error)
  for (let i = 0; i < 30; i++) {
    const result = await runAuditTool("audit_mcp_config", {
      config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
    });
    assert.ok(!result.error || !result.error.includes("Rate limit"), `call ${i + 1} should not be rate-limited`);
  }

  // 31st call should be rate-limited
  const result31 = await runAuditTool("audit_mcp_config", {
    config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
  });
  assert.ok(result31.error, "31st call should return an error");
  assert.match(result31.error, /rate limit/i);

  // Clean up
  _testOnly.resetRateLimits();
});

test("MCP rate limit: reset allows next call to succeed", async () => {
  const { _testOnly } = require("../mcp/index");
  _testOnly.resetRateLimits();

  // Exhaust the limit
  for (let i = 0; i < 30; i++) {
    await runAuditTool("audit_mcp_config", {
      config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
    });
  }

  // Verify exhausted
  const blocked = await runAuditTool("audit_mcp_config", {
    config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
  });
  assert.match(blocked.error, /rate limit/i);

  // Reset and verify next call succeeds
  _testOnly.resetRateLimits();
  const afterReset = await runAuditTool("audit_mcp_config", {
    config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
  });
  assert.ok(!afterReset.error || !afterReset.error.includes("Rate limit"), "call after reset should succeed");

  _testOnly.resetRateLimits();
});

test("MCP concurrent audit limit: rejects when mcpActiveAudits >= max", async () => {
  const { _testOnly } = require("../mcp/index");
  _testOnly.resetRateLimits();

  // Set active audits to the max (2)
  _testOnly.setMcpActiveAudits(2);

  const result = await runAuditTool("audit_mcp_config", {
    config: JSON.stringify({ mcpServers: { s: { command: "node", args: ["x.js"] } } })
  });
  assert.ok(result.error, "should return an error when concurrent limit reached");
  assert.match(result.error, /concurrent/i);

  // Clean up
  _testOnly.resetRateLimits();
});

test("audit_agent_dataflow blocks local command launchers without admin mode", async () => {
  const originalAdminMode = process.env.AGENT_SECURITY_ADMIN_MODE;

  try {
    process.env.AGENT_SECURITY_ADMIN_MODE = "0";
    const result = await runAuditTool("audit_agent_dataflow", {
      mcp_config: JSON.stringify({
        mcpServers: {
          local: {
            command: "node",
            args: ["server.js"]
          }
        }
      })
    });
    assert.match(result.error, /AGENT_SECURITY_ADMIN_MODE=1/);
  } finally {
    if (originalAdminMode === undefined) {
      delete process.env.AGENT_SECURITY_ADMIN_MODE;
    } else {
      process.env.AGENT_SECURITY_ADMIN_MODE = originalAdminMode;
    }
  }
});
