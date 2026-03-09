const path = require("path");
const { createFinding, dedupeFindings } = require("./findings");

const sensitiveEnvPattern = /(key|token|secret|password|credential|private|session)/i;
const shellExecutionPattern = /\b(sh|bash|zsh|cmd|powershell|pwsh|python|node)\b/i;
const templatedInputPattern = /(\$\{[^}]+\}|{{[^}]+}}|<%=?[^%]+%>|%[A-Z0-9_]+%|{user[_ -]?input}|{prompt}|<user_input>)/i;

const riskCatalog = [
  {
    pattern: /(server-)?shell|terminal|exec|command/i,
    capability: "shell",
    severity: "critical",
    cwe: "shell_injection",
    remediation: "Remove arbitrary command execution, or gate it behind a fixed allowlist and human approval."
  },
  {
    pattern: /filesystem|file[-_ ]?system|server-filesystem|fs\b/i,
    capability: "filesystem",
    severity: "high",
    cwe: "excessive_privilege",
    remediation: "Constrain file access to a dedicated working directory and enforce explicit path allowlists."
  },
  {
    pattern: /postgres|mysql|sqlite|mongodb|database|sql\b/i,
    capability: "database",
    severity: "high",
    cwe: "tool_authorization",
    remediation: "Use read-only credentials, parameterized queries, and table allowlists."
  },
  {
    pattern: /fetch|http|browser|web|request|crawl|puppeteer/i,
    capability: "network",
    severity: "medium",
    cwe: "data_exfiltration",
    remediation: "Restrict outbound domains and treat remote content as untrusted."
  },
  {
    pattern: /docker|kubernetes|terraform|aws|gcp|azure|cloud/i,
    capability: "infrastructure",
    severity: "high",
    cwe: "excessive_privilege",
    remediation: "Apply least-privilege API credentials and isolate deployment tooling from general agent workflows."
  }
];

function parseConfig(configInput) {
  if (!configInput) {
    throw new Error("Missing MCP config.");
  }

  if (typeof configInput === "string") {
    return JSON.parse(configInput);
  }

  if (typeof configInput === "object") {
    return configInput;
  }

  throw new Error("Config must be a JSON string or object.");
}

function getServerEntries(config) {
  if (config && config.mcpServers && typeof config.mcpServers === "object") {
    return Object.entries(config.mcpServers).map(([name, server]) => [name, server || {}]);
  }

  if (config && Array.isArray(config.servers)) {
    return config.servers.map((server, index) => [server && server.name ? server.name : `server-${index + 1}`, server || {}]);
  }

  return [];
}

function normalizeArgs(args) {
  return Array.isArray(args) ? args.map((value) => String(value)) : [];
}

function extractPackageNames(server) {
  const args = normalizeArgs(server && server.args);
  const command = String((server && server.command) || "");
  const packages = new Set();

  try {
    if (/^npx(?:\.cmd)?$/i.test(command) || /^npm(?:\.cmd)?$/i.test(command)) {
      for (const arg of args) {
        if (!arg.startsWith("-")) {
          packages.add(arg);
        }
      }
    }

    if (/^uvx$/i.test(command) || /^pipx$/i.test(command)) {
      for (const arg of args) {
        if (!arg.startsWith("-")) {
          packages.add(arg);
        }
      }
    }

    if (/^node$/i.test(command) || /node_modules/.test(command)) {
      for (const arg of args) {
        const match = arg.match(/node_modules\/([^/]+(?:\/[^/]+)?)/);
        if (match) {
          packages.add(match[1]);
        }
      }
    }

    for (const arg of args) {
      if (/^@[^/]+\/[^/]+$/.test(arg) || /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9._-]+)?$/i.test(arg)) {
        if (!arg.startsWith(".") && !arg.startsWith("/") && !arg.includes(path.sep)) {
          packages.add(arg);
        }
      }
    }
  } catch (error) {
    return [];
  }

  return Array.from(packages);
}

function extractTransport(server) {
  if (server && server.url) {
    if (/^https:\/\//i.test(server.url)) {
      return "https";
    }
    if (/^http:\/\//i.test(server.url)) {
      return "http";
    }
    if (/^wss?:\/\//i.test(server.url)) {
      return server.url.toLowerCase().startsWith("wss://") ? "wss" : "ws";
    }
  }

  if (server && server.transport) {
    return String(server.transport).toLowerCase();
  }

  return "stdio";
}

function hasAuthConfiguration(server) {
  if (!server || typeof server !== "object") {
    return false;
  }

  return Boolean(
    server.auth ||
    server.authToken ||
    server.apiKey ||
    server.token ||
    (server.headers && (server.headers.Authorization || server.headers.authorization))
  );
}

function describeCapability(packageNames, command, args) {
  const corpus = [String(command || ""), ...normalizeArgs(args), ...packageNames].join(" ");
  return riskCatalog.find((entry) => entry.pattern.test(corpus)) || null;
}

function analyzeFilesystemScope(serverName, server, packageNames, findings) {
  const capability = describeCapability(packageNames, server.command, server.args);
  if (!capability || capability.capability !== "filesystem") {
    return;
  }

  const args = normalizeArgs(server.args);
  const pathLikeArgs = args.filter((arg) => arg.startsWith("/") || arg.startsWith("./") || arg.startsWith("../") || /^[A-Za-z]:\\/.test(arg));
  const dangerousRoot = pathLikeArgs.some((arg) => ["/", "~", "/Users", "/home", "C:\\", "D:\\"].includes(arg) || /\/$/.test(arg));

  if (!pathLikeArgs.length) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "high",
      cwe: "excessive_privilege",
      location: serverName,
      description: `Filesystem-capable MCP server "${serverName}" does not declare a constrained path allowlist.`,
      remediation: "Pass one or more explicit safe directories instead of relying on process-wide filesystem access."
    }));
    return;
  }

  if (dangerousRoot) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "medium",
      cwe: "excessive_privilege",
      location: serverName,
      description: `Filesystem MCP server "${serverName}" appears to expose a root or home-level directory.`,
      remediation: "Reduce the exposed path scope to a dedicated project directory with no secrets or credentials."
    }));
  }
}

function analyzeDatabaseScope(serverName, server, packageNames, findings) {
  const capability = describeCapability(packageNames, server.command, server.args);
  if (!capability || capability.capability !== "database") {
    return;
  }

  const corpus = [String(server.command || ""), ...normalizeArgs(server.args), JSON.stringify(server.env || {})].join(" ");
  if (!/(readonly|read-only|ro\b)/i.test(corpus)) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "medium",
      cwe: "tool_authorization",
      location: serverName,
      description: `Database-capable MCP server "${serverName}" does not advertise read-only constraints.`,
      remediation: "Use dedicated read-only credentials and enforce parameterized queries with table allowlists."
    }));
  }
}

function analyzeShellExecution(serverName, server, findings) {
  const command = String(server.command || "");
  const args = normalizeArgs(server.args);
  const joined = [command, ...args].join(" ");

  if (/(^| )(sh|bash|zsh|cmd|powershell|pwsh)( |$)/i.test(command) && args.some((arg) => /^(-c|\/c|-command)$/i.test(arg))) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "critical",
      confidence: "high",
      cwe: "shell_injection",
      location: serverName,
      description: `MCP server "${serverName}" is launched through a shell interpreter with inline commands.`,
      remediation: "Invoke the server binary directly instead of shelling out through bash, sh, cmd, or PowerShell."
    }));
  }

  if (templatedInputPattern.test(joined)) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "medium",
      cwe: "shell_injection",
      location: serverName,
      description: `MCP server "${serverName}" launch arguments appear to interpolate external input into the command line.`,
      remediation: "Remove user-controlled placeholders from command arguments and validate all dynamic values before process launch."
    }));
  }
}

function analyzeTransport(serverName, server, findings) {
  const transport = extractTransport(server);
  const remoteTransport = ["http", "https", "sse", "ws", "wss"].includes(transport);

  if (transport === "http" || transport === "ws") {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "high",
      cwe: "insecure_transport",
      location: serverName,
      description: `MCP server "${serverName}" uses cleartext remote transport (${transport}).`,
      remediation: "Require TLS for remote MCP connections and pin the server endpoint to a trusted hostname."
    }));
  }

  if (remoteTransport && !hasAuthConfiguration(server)) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "high",
      confidence: "medium",
      cwe: "missing_auth",
      location: serverName,
      description: `Remote MCP server "${serverName}" does not declare authentication material in its configuration.`,
      remediation: "Require bearer tokens, mutual TLS, or another authenticated transport for remote MCP access."
    }));
  }
}

function analyzeEnvironment(serverName, server, findings) {
  const env = server && server.env && typeof server.env === "object" ? server.env : {};

  for (const [key, value] of Object.entries(env)) {
    if (!sensitiveEnvPattern.test(key)) {
      continue;
    }

    findings.push(createFinding({
      source: "config-analyzer",
      severity: "medium",
      confidence: "high",
      cwe: "secret_leakage",
      location: `${serverName}:${key}`,
      description: `Sensitive environment variable "${key}" is passed directly into MCP server "${serverName}".`,
      remediation: "Scope secrets to the minimum required server, rotate them regularly, and avoid forwarding unrelated credentials into MCP subprocesses."
    }));

    if (templatedInputPattern.test(String(value))) {
      findings.push(createFinding({
        source: "config-analyzer",
        severity: "high",
        confidence: "medium",
        cwe: "secret_leakage",
        location: `${serverName}:${key}`,
        description: `Environment variable "${key}" for MCP server "${serverName}" appears to be assembled from templated input.`,
        remediation: "Resolve secrets from a fixed secret store instead of interpolating runtime or user-controlled values."
      }));
    }
  }
}

function analyzeRiskyPackages(serverName, server, packageNames, findings) {
  const capability = describeCapability(packageNames, server.command, server.args);

  if (!capability) {
    return;
  }

  findings.push(createFinding({
    source: "config-analyzer",
    severity: capability.severity,
    confidence: "medium",
    cwe: capability.cwe,
    location: serverName,
    description: `MCP server "${serverName}" appears to use a ${capability.capability}-capable package (${packageNames.join(", ") || server.command || "unknown package"}).`,
    remediation: capability.remediation
  }));
}

function analyzeConfig(configInput) {
  const findings = [];
  const config = parseConfig(configInput);
  const servers = getServerEntries(config);
  const serverSummaries = [];

  if (!servers.length) {
    findings.push(createFinding({
      source: "config-analyzer",
      severity: "low",
      confidence: "high",
      cwe: "input_validation",
      description: "No MCP server definitions were found in the supplied config.",
      remediation: "Provide a config with an mcpServers object or servers array to perform a meaningful audit."
    }));
  }

  for (const [serverName, server] of servers) {
    try {
      const packageNames = extractPackageNames(server);
      analyzeRiskyPackages(serverName, server, packageNames, findings);
      analyzeShellExecution(serverName, server, findings);
      analyzeTransport(serverName, server, findings);
      analyzeEnvironment(serverName, server, findings);
      analyzeFilesystemScope(serverName, server, packageNames, findings);
      analyzeDatabaseScope(serverName, server, packageNames, findings);

      const args = normalizeArgs(server.args);
      if (args.some((arg) => /(--unsafe|--insecure|--allow-all|--dangerously-skip-permissions|--no-auth)/i.test(arg))) {
        findings.push(createFinding({
          source: "config-analyzer",
          severity: "high",
          confidence: "high",
          cwe: "excessive_privilege",
          location: serverName,
          description: `MCP server "${serverName}" is launched with flags that disable or weaken security controls.`,
          remediation: "Remove unsafe launch flags and replace them with explicit allowlists or authenticated controls."
        }));
      }

      if (shellExecutionPattern.test(String(server.command || "")) && !args.length) {
        findings.push(createFinding({
          source: "config-analyzer",
          severity: "medium",
          confidence: "medium",
          cwe: "input_validation",
          location: serverName,
          description: `MCP server "${serverName}" is launched through a general-purpose interpreter without explicit argument constraints.`,
          remediation: "Prefer fixed binaries or scripts with a narrow argument surface over general interpreters."
        }));
      }

      serverSummaries.push({
        name: serverName,
        transport: extractTransport(server),
        packages: packageNames,
        command: server.command || null
      });
    } catch (error) {
      findings.push(createFinding({
        source: "config-analyzer",
        severity: "medium",
        confidence: "high",
        cwe: "input_validation",
        location: serverName,
        description: `Failed to fully analyze MCP server "${serverName}": ${error.message}`,
        remediation: "Repair the server configuration format and rerun the audit."
      }));
    }
  }

  return {
    configSummary: {
      serverCount: servers.length,
      servers: serverSummaries
    },
    findings: dedupeFindings(findings)
  };
}

module.exports = {
  analyzeConfig,
  parseConfig,
  getServerEntries,
  extractPackageNames,
  extractTransport
};
