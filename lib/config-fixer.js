const { parseConfig, getServerEntries, extractTransport, extractPackageNames } = require("./config-analyzer");
const { analyzeConfig } = require("./config-analyzer");
const { createFinding, dedupeFindings } = require("./findings");

const UNSAFE_FLAGS = /^(--unsafe|--insecure|--allow-all|--dangerously-skip-permissions|--no-auth)$/i;
const SENSITIVE_ENV = /(key|token|secret|password|credential|private|session)/i;

function fixConfig(configInput, options) {
  const config = parseConfig(configInput);
  const audit = analyzeConfig(config);
  const changes = [];
  const fixed = JSON.parse(JSON.stringify(config));
  const opts = options || {};

  const serverEntries = getServerEntries(fixed);

  for (const [name, server] of serverEntries) {
    if (!server) continue;

    // 1. Remove unsafe launch flags
    if (Array.isArray(server.args)) {
      const before = server.args.length;
      server.args = server.args.filter((arg) => {
        if (UNSAFE_FLAGS.test(arg)) {
          changes.push({
            server: name,
            action: "remove_unsafe_flag",
            detail: `Removed flag: ${arg}`,
            severity: "high"
          });
          return false;
        }
        return true;
      });
    }

    // 2. Strip shell interpreter wrappers (bash -c "...")
    const command = String(server.command || "");
    if (/^(sh|bash|zsh|cmd|powershell|pwsh)$/i.test(command) && Array.isArray(server.args)) {
      const cFlagIndex = server.args.findIndex((a) => /^(-c|\/c|-command)$/i.test(a));
      if (cFlagIndex !== -1 && server.args.length > cFlagIndex + 1) {
        const innerCommand = server.args[cFlagIndex + 1];
        const parts = innerCommand.trim().split(/\s+/);
        if (parts.length >= 1) {
          changes.push({
            server: name,
            action: "remove_shell_wrapper",
            detail: `Replaced "${command} ${server.args[cFlagIndex]} ..." with direct command: ${parts[0]}`,
            severity: "critical"
          });
          server.command = parts[0];
          server.args = parts.slice(1);
        }
      }
    }

    // 3. Upgrade http:// to https:// and ws:// to wss://
    if (server.url) {
      if (/^http:\/\//i.test(server.url)) {
        const newUrl = server.url.replace(/^http:\/\//i, "https://");
        changes.push({
          server: name,
          action: "upgrade_transport",
          detail: `Upgraded ${server.url} → ${newUrl}`,
          severity: "high"
        });
        server.url = newUrl;
      }
      if (/^ws:\/\//i.test(server.url)) {
        const newUrl = server.url.replace(/^ws:\/\//i, "wss://");
        changes.push({
          server: name,
          action: "upgrade_transport",
          detail: `Upgraded ${server.url} → ${newUrl}`,
          severity: "high"
        });
        server.url = newUrl;
      }
    }

    // 4. Redact sensitive env vars that look like raw secrets
    if (server.env && typeof server.env === "object") {
      for (const [key, value] of Object.entries(server.env)) {
        if (SENSITIVE_ENV.test(key) && typeof value === "string" && value.length > 0) {
          // Replace inline secrets with env var references
          const envRef = `\${${key.toUpperCase()}}`;
          if (!value.startsWith("${") && !value.startsWith("$")) {
            changes.push({
              server: name,
              action: "redact_inline_secret",
              detail: `Replaced inline value for "${key}" with environment variable reference ${envRef}`,
              severity: "medium"
            });
            server.env[key] = envRef;
          }
        }
      }
    }

    // 5. Add auth placeholder for remote servers missing auth
    const transport = extractTransport(server);
    const isRemote = ["http", "https", "sse", "ws", "wss"].includes(transport);
    if (isRemote && !server.auth && !server.authToken && !server.apiKey && !server.token) {
      if (!(server.headers && (server.headers.Authorization || server.headers.authorization))) {
        changes.push({
          server: name,
          action: "add_auth_placeholder",
          detail: "Added headers.Authorization placeholder — replace with a real bearer token",
          severity: "high"
        });
        server.headers = server.headers || {};
        server.headers.Authorization = "Bearer ${AUTH_TOKEN}";
      }
    }

    // 6. Constrain filesystem scope for filesystem-capable servers
    const packageNames = extractPackageNames(server);
    const corpus = [String(server.command || ""), ...(server.args || []), ...packageNames].join(" ");
    if (/filesystem|file[-_ ]?system|server-filesystem|fs\b/i.test(corpus)) {
      if (Array.isArray(server.args)) {
        const hasPath = server.args.some((a) => a.startsWith("/") || a.startsWith("./") || /^[A-Za-z]:\\/.test(a));
        const hasDangerousRoot = server.args.some((a) => {
          const n = a.replace(/[\\/]+$/, "");
          return a === "/" || a === "~" || n === "/Users" || n === "/home" || n === "/root" || /^[A-Za-z]:$/.test(n);
        });
        if (hasDangerousRoot) {
          server.args = server.args.map((a) => {
            const n = a.replace(/[\\/]+$/, "");
            if (a === "/" || a === "~" || n === "/Users" || n === "/home" || n === "/root" || /^[A-Za-z]:$/.test(n)) {
              return "./workspace";
            }
            return a;
          });
          changes.push({
            server: name,
            action: "constrain_filesystem",
            detail: "Replaced dangerous root path with ./workspace — update to your specific project directory",
            severity: "high"
          });
        } else if (!hasPath) {
          changes.push({
            server: name,
            action: "constrain_filesystem",
            detail: "Filesystem server has no path constraint — add an explicit allowed directory",
            severity: "high"
          });
        }
      }
    }
  }

  // Re-audit the fixed config to show remaining issues
  const postAudit = analyzeConfig(fixed);

  return {
    original_findings: audit.findings.length,
    changes_applied: changes.length,
    changes,
    remaining_findings: postAudit.findings.length,
    remaining_issues: postAudit.findings,
    fixed_config: fixed
  };
}

module.exports = { fixConfig };
