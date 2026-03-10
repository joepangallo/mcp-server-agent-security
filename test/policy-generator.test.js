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
