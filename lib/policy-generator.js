const { parseConfig, getServerEntries, extractPackageNames, extractTransport } = require("./config-analyzer");
const { createFinding, dedupeFindings } = require("./findings");
const { classifyCapability } = require("./dataflow-tracer");

function generatePolicy(mcpConfig, options) {
  const opts = options || {};
  const config = parseConfig(mcpConfig);
  const servers = getServerEntries(config);
  const findings = [];

  const policy = {
    version: "1.0",
    generated_at: new Date().toISOString(),
    description: "Auto-generated security policy from MCP config audit",
    rules: [],
    servers: {}
  };

  for (const [name, server] of servers) {
    if (!server) continue;

    const packageNames = extractPackageNames(server);
    const transport = extractTransport(server);
    const serverPolicy = {
      transport,
      require_approval: [],
      blocked_capabilities: [],
      allowed_destinations: [],
      rate_limit: { requests_per_minute: 30 }
    };

    // Infer tools from package names and server config
    const corpus = [String(server.command || ""), ...(Array.isArray(server.args) ? server.args : []), ...packageNames].join(" ");
    const capabilities = classifyCapability(name, corpus, packageNames);

    // Shell execution: block or require approval
    if (capabilities.includes("shell-exec")) {
      serverPolicy.require_approval.push({
        capability: "shell-exec",
        reason: "Shell execution detected — requires human approval before each invocation",
        enforcement: "block_until_approved"
      });
      policy.rules.push({
        server: name,
        rule: "shell_approval_required",
        action: "require_approval",
        description: `Server "${name}" has shell execution capability — all shell calls must be approved`
      });
    }

    // Network egress: restrict to allowed destinations
    if (capabilities.includes("network-egress")) {
      serverPolicy.require_approval.push({
        capability: "network-egress",
        reason: "Network egress detected — outbound requests restricted to allowlist",
        enforcement: "allowlist_only"
      });
      serverPolicy.allowed_destinations = opts.allowed_destinations || [
        "*.anthropic.com",
        "*.openai.com",
        "api.github.com"
      ];
      policy.rules.push({
        server: name,
        rule: "network_egress_allowlist",
        action: "restrict_destinations",
        description: `Server "${name}" can make outbound requests — restricted to approved domains`
      });
    }

    // File write: constrain paths
    if (capabilities.includes("file-write")) {
      serverPolicy.require_approval.push({
        capability: "file-write",
        reason: "File write detected — writes restricted to approved directories",
        enforcement: "path_allowlist"
      });
      serverPolicy.allowed_paths = opts.allowed_paths || [
        "./output/",
        "./tmp/",
        "/tmp/"
      ];
      policy.rules.push({
        server: name,
        rule: "file_write_constrained",
        action: "restrict_paths",
        description: `Server "${name}" can write files — restricted to safe directories`
      });
    }

    // Database: require read-only unless approved
    if (capabilities.includes("database")) {
      serverPolicy.require_approval.push({
        capability: "database-write",
        reason: "Database access detected — write operations require approval",
        enforcement: "read_only_default"
      });
      policy.rules.push({
        server: name,
        rule: "database_read_only",
        action: "enforce_read_only",
        description: `Server "${name}" has database access — default to read-only`
      });
    }

    // Transport security
    if (transport === "http" || transport === "ws") {
      policy.rules.push({
        server: name,
        rule: "require_tls",
        action: "block",
        description: `Server "${name}" uses cleartext ${transport} — upgrade to ${transport === "http" ? "https" : "wss"}`
      });
    }

    // Rate limiting - tighter for dangerous capabilities
    if (capabilities.includes("shell-exec") || capabilities.includes("network-egress")) {
      serverPolicy.rate_limit.requests_per_minute = 10;
    }

    policy.servers[name] = serverPolicy;
  }

  // Add global rules
  policy.global = {
    pii_handling: "scrub_before_egress",
    secret_handling: "never_transmit",
    logging: "all_tool_calls",
    max_concurrent_requests: 5,
    default_action: "allow_with_logging"
  };

  return {
    policy,
    rule_count: policy.rules.length,
    servers_covered: Object.keys(policy.servers).length,
    format: "json",
    usage: "Load this policy into an MCP proxy or enforcement middleware to apply these rules at runtime."
  };
}

module.exports = { generatePolicy };
