const { test } = require("node:test");
const assert = require("node:assert/strict");
const { fixConfig } = require("../lib/config-fixer");

test("removes unsafe launch flags from server args", () => {
  const config = {
    mcpServers: {
      risky: {
        command: "npx",
        args: ["-y", "some-server", "--dangerously-skip-permissions"]
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "remove_unsafe_flag"));
  assert.ok(!result.fixed_config.mcpServers.risky.args.includes("--dangerously-skip-permissions"));
});

test("unwraps shell interpreter wrappers", () => {
  const config = {
    mcpServers: {
      shelled: {
        command: "bash",
        args: ["-c", "node server.js --port 3000"]
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "remove_shell_wrapper"));
  assert.equal(result.fixed_config.mcpServers.shelled.command, "node");
});

test("upgrades http to https transport", () => {
  const config = {
    mcpServers: {
      remote: {
        url: "http://example.com/mcp",
        headers: { Authorization: "Bearer tok" }
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "upgrade_transport"));
  assert.ok(result.fixed_config.mcpServers.remote.url.startsWith("https://"));
});

test("adds auth placeholder for unauthenticated remote servers", () => {
  const config = {
    mcpServers: {
      naked: {
        url: "https://example.com/mcp"
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "add_auth_placeholder"));
  assert.ok(result.fixed_config.mcpServers.naked.headers.Authorization);
});

test("redacts inline secret values in env", () => {
  const config = {
    mcpServers: {
      leaky: {
        command: "node",
        args: ["server.js"],
        env: { API_KEY: "sk-12345" }
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "redact_inline_secret"));
  assert.ok(result.fixed_config.mcpServers.leaky.env.API_KEY.startsWith("$"));
});

test("returns no changes for a clean config", () => {
  const config = {
    mcpServers: {
      safe: {
        command: "node",
        args: ["server.js"]
      }
    }
  };
  const result = fixConfig(config);
  assert.equal(result.changes_applied, 0);
});
