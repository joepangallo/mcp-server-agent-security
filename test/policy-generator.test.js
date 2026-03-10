const { test } = require("node:test");
const assert = require("node:assert/strict");
const { generatePolicy } = require("../lib/policy-generator");

test("generates shell approval rule for shell-capable servers", () => {
  const config = JSON.stringify({
    mcpServers: {
      terminal: {
        command: "node",
        args: ["shell-server.js"]
      }
    }
  });
  const result = generatePolicy(config);
  assert.ok(result.policy.rules.some((r) => r.rule === "shell_approval_required"));
  assert.ok(result.policy.servers.terminal.require_approval.some((a) => a.capability === "shell-exec"));
});

test("generates network egress allowlist for fetch-capable servers", () => {
  const config = JSON.stringify({
    mcpServers: {
      browser: {
        command: "node",
        args: ["fetch-server.js"]
      }
    }
  });
  const result = generatePolicy(config);
  assert.ok(result.policy.rules.some((r) => r.rule === "network_egress_allowlist"));
  assert.ok(result.policy.servers.browser.allowed_destinations.length > 0);
});

test("generates TLS requirement for http transport", () => {
  const config = JSON.stringify({
    mcpServers: {
      insecure: {
        url: "http://example.com/mcp"
      }
    }
  });
  const result = generatePolicy(config);
  assert.ok(result.policy.rules.some((r) => r.rule === "require_tls"));
});

test("respects custom allowed_destinations", () => {
  const config = JSON.stringify({
    mcpServers: {
      fetcher: {
        command: "node",
        args: ["web-server.js"]
      }
    }
  });
  const result = generatePolicy(config, { allowed_destinations: ["*.example.com"] });
  assert.deepEqual(result.policy.servers.fetcher.allowed_destinations, ["*.example.com"]);
});

test("includes global policy defaults", () => {
  const config = JSON.stringify({
    mcpServers: {
      basic: {
        command: "node",
        args: ["server.js"]
      }
    }
  });
  const result = generatePolicy(config);
  assert.equal(result.policy.global.pii_handling, "scrub_before_egress");
  assert.equal(result.policy.global.secret_handling, "never_transmit");
  assert.equal(result.policy.version, "1.0");
});

test("applies tighter rate limits for dangerous capabilities", () => {
  const config = JSON.stringify({
    mcpServers: {
      dangerous: {
        command: "node",
        args: ["exec-server.js"]
      }
    }
  });
  const result = generatePolicy(config);
  assert.equal(result.policy.servers.dangerous.rate_limit.requests_per_minute, 10);
});

test("generates policy with empty config (no servers)", () => {
  const result = generatePolicy({ mcpServers: {} });
  assert.equal(result.rule_count, 0);
  assert.equal(result.servers_covered, 0);
  assert.ok(result.policy.global);
  assert.equal(result.policy.version, "1.0");
});

test("generates policy with servers[] array format", () => {
  const config = {
    servers: [
      { name: "db", command: "npx", args: ["postgres-server"] }
    ]
  };
  const result = generatePolicy(config);
  assert.ok(result.servers_covered >= 1);
  assert.ok(result.policy.servers.db);
});

test("database-capable server gets read_only rule", () => {
  const config = {
    mcpServers: {
      mydb: {
        command: "npx",
        args: ["sqlite-server"]
      }
    }
  };
  const result = generatePolicy(config);
  assert.ok(
    result.policy.rules.some((r) => r.rule === "database_read_only"),
    "should generate database_read_only rule for sqlite server"
  );
  assert.ok(
    result.policy.servers.mydb.require_approval.some((a) => a.capability === "database-write"),
    "should require approval for database-write capability"
  );
});

test("file-write server gets path constraint rule", () => {
  const config = {
    mcpServers: {
      files: {
        command: "npx",
        args: ["filesystem-server"]
      }
    }
  };
  const result = generatePolicy(config);
  assert.ok(
    result.policy.rules.some((r) => r.rule === "file_write_constrained"),
    "should generate file_write_constrained rule for filesystem server"
  );
  assert.ok(
    result.policy.servers.files.allowed_paths.length > 0,
    "should have allowed_paths for file-write server"
  );
});
