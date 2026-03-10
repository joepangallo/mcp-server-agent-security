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

test("fixConfig handles servers array format", () => {
  const config = {
    servers: [
      {
        name: "shelled",
        command: "bash",
        args: ["-c", "node server.js --port 3000"]
      }
    ]
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "remove_shell_wrapper"));
  assert.ok(result.original_findings > 0);
});

test("upgrades ws:// to wss:// transport", () => {
  const config = {
    mcpServers: {
      wsserver: {
        url: "ws://example.com/mcp",
        headers: { Authorization: "Bearer tok" }
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "upgrade_transport"));
  assert.ok(result.fixed_config.mcpServers.wsserver.url.startsWith("wss://"));
});

test("fixes multiple issues simultaneously", () => {
  const config = {
    mcpServers: {
      multi: {
        command: "bash",
        args: ["-c", "node server.js --dangerously-skip-permissions"],
        env: { API_KEY: "sk-secret-123" },
        url: "http://example.com/mcp"
      }
    }
  };
  const result = fixConfig(config);
  const actions = result.changes.map((c) => c.action);
  // Should have multiple different fix actions
  assert.ok(result.changes_applied >= 2, `expected >= 2 changes but got ${result.changes_applied}`);
  // Remaining findings should be fewer than original
  assert.ok(result.remaining_findings <= result.original_findings);
});

test("filesystem server with / path is replaced with ./workspace", () => {
  const config = {
    mcpServers: {
      files: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/"]
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "constrain_filesystem"));
  const args = result.fixed_config.mcpServers.files.args;
  assert.ok(!args.includes("/"), "root path should be replaced");
  assert.ok(args.includes("./workspace"), "should contain ./workspace");
});

test("filesystem server with /home path is replaced with ./workspace", () => {
  const config = {
    mcpServers: {
      files: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/home"]
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "constrain_filesystem"));
  const args = result.fixed_config.mcpServers.files.args;
  assert.ok(!args.includes("/home"), "/home should be replaced");
  assert.ok(args.includes("./workspace"), "should contain ./workspace");
});

test("filesystem server with ~/ path is replaced with ./workspace", () => {
  const config = {
    mcpServers: {
      files: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "~"]
      }
    }
  };
  const result = fixConfig(config);
  assert.ok(result.changes.some((c) => c.action === "constrain_filesystem"));
  const args = result.fixed_config.mcpServers.files.args;
  assert.ok(!args.includes("~"), "~ should be replaced");
  assert.ok(args.includes("./workspace"), "should contain ./workspace");
});

test("fixConfig throws on null input", () => {
  assert.throws(() => fixConfig(null), /Missing MCP config/);
});

test("fixConfig throws on undefined input", () => {
  assert.throws(() => fixConfig(undefined), /Missing MCP config/);
});
