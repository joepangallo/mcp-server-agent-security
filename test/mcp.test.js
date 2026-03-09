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
