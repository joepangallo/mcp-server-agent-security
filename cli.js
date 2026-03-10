#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { PORT } = require("./index");

const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";
const API_KEY = process.env.AGENT_SECURITY_API_KEY || "";

function printUsage() {
  process.stderr.write(
    [
      "Usage:",
      "  agent-security scan-config <file>         Audit an MCP config file",
      "  agent-security scan-server <command> [args...]  Probe a running MCP server",
      "  agent-security scan-package <name>         Audit an npm package",
      "  agent-security scan-injection <file>       Test a system prompt for injection vulnerabilities",
      "  agent-security scan-dataflow <file>        Trace data flows through an MCP config",
      "  agent-security fix-config <file>           Auto-fix security issues in an MCP config",
      "  agent-security harden-prompt <file>        Harden a system prompt against injection",
      "  agent-security generate-policy <file>      Generate a security policy from an MCP config",
      "  agent-security report <id>                 Retrieve an audit report by ID",
      "",
      "Flags:",
      "  --help, -h       Show this help message",
      "  --version, -v    Show version number",
      "  --json           Output raw JSON instead of formatted tables"
    ].join("\n") + "\n"
  );
}

async function callApi(method, pathname, payload) {
  const headers = {
    "content-type": "application/json"
  };
  if (API_KEY) {
    headers["x-api-key"] = API_KEY;
  }

  const response = await fetch(`http://${HOST}:${PORT}${pathname}`, {
    method,
    headers,
    body: payload ? JSON.stringify(payload) : undefined
  });

  let body;
  try {
    body = await response.json();
  } catch (parseError) {
    throw new Error(`Request failed with status ${response.status} (non-JSON response).`);
  }
  if (!response.ok) {
    throw new Error(body && body.error ? body.error : `Request failed with status ${response.status}`);
  }

  return body;
}

function formatReport(report) {
  console.table([
    {
      id: report.id,
      type: report.type || "",
      target: report.target || "",
      status: report.status,
      score: report.score,
      grade: report.grade
    }
  ]);

  if (report.findingsSummary) {
    console.table([report.findingsSummary]);
  }

  if (Array.isArray(report.findings) && report.findings.length) {
    console.table(report.findings.map((finding) => ({
      severity: finding.severity,
      source: finding.source,
      cwe: finding.cwe,
      confidence: finding.confidence,
      location: finding.location || "",
      description: finding.description
    })));
  } else {
    process.stdout.write("No findings.\n");
  }
}

function formatFixConfig(result) {
  process.stdout.write(`Original findings: ${result.original_findings}\n`);
  process.stdout.write(`Changes applied: ${result.changes_applied}\n`);
  process.stdout.write(`Remaining findings: ${result.remaining_findings}\n\n`);

  if (Array.isArray(result.changes) && result.changes.length) {
    console.table(result.changes.map((change) => ({
      server: change.server,
      action: change.action,
      severity: change.severity,
      detail: change.detail
    })));
  } else {
    process.stdout.write("No changes needed.\n");
  }

  if (result.fixed_config) {
    process.stdout.write("\nFixed config:\n");
    process.stdout.write(JSON.stringify(result.fixed_config, null, 2) + "\n");
  }
}

function formatHardenPrompt(result) {
  process.stdout.write(`Action: ${result.action}\n`);
  process.stdout.write(`Before score: ${result.before_score}\n`);
  process.stdout.write(`After score: ${result.after_score}\n`);

  if (result.improvement !== undefined) {
    process.stdout.write(`Improvement: +${result.improvement}\n`);
  }

  if (Array.isArray(result.guardrails_added) && result.guardrails_added.length) {
    process.stdout.write("\nGuardrails added:\n");
    console.table(result.guardrails_added.map((g) => ({
      control: g.control,
      label: g.label
    })));
  }

  if (result.hardened_prompt) {
    process.stdout.write("\nHardened prompt:\n");
    process.stdout.write(result.hardened_prompt + "\n");
  }
}

function formatGeneratePolicy(result) {
  process.stdout.write(`Rules generated: ${result.rule_count}\n`);
  process.stdout.write(`Servers covered: ${result.servers_covered}\n`);

  if (result.policy) {
    if (Array.isArray(result.policy.rules) && result.policy.rules.length) {
      console.table(result.policy.rules.map((rule) => ({
        server: rule.server,
        rule: rule.rule,
        action: rule.action,
        description: rule.description
      })));
    }

    process.stdout.write("\nFull policy:\n");
    process.stdout.write(JSON.stringify(result.policy, null, 2) + "\n");
  }

  if (result.usage) {
    process.stdout.write("\n" + result.usage + "\n");
  }
}

async function main() {
  const [, , command, ...args] = process.argv;
  const jsonMode = process.argv.includes("--json");

  try {
    if (command === "--help" || command === "-h") {
      printUsage();
      return;
    }

    if (command === "--version" || command === "-v") {
      const pkg = require("./package.json");
      process.stdout.write(pkg.version + "\n");
      return;
    }

    if (command === "scan-config") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("scan-config requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const config = await fs.promises.readFile(absolutePath, "utf8");
      const report = await callApi("POST", "/audit/config", { config });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    if (command === "scan-server") {
      const targetCommand = args[0];
      if (!targetCommand) {
        throw new Error("scan-server requires a command.");
      }

      const report = await callApi("POST", "/audit/server", {
        command: targetCommand,
        args: args.slice(1)
      });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    if (command === "scan-package") {
      const packageName = args[0];
      if (!packageName) {
        throw new Error("scan-package requires a package name.");
      }

      const report = await callApi("POST", "/audit/package", {
        package_name: packageName
      });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    if (command === "scan-injection") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("scan-injection requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const systemPrompt = await fs.promises.readFile(absolutePath, "utf8");
      const report = await callApi("POST", "/audit/injection", { system_prompt: systemPrompt });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    if (command === "scan-dataflow") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("scan-dataflow requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const mcpConfig = await fs.promises.readFile(absolutePath, "utf8");
      const report = await callApi("POST", "/audit/dataflow", { mcp_config: mcpConfig });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    if (command === "fix-config") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("fix-config requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const config = await fs.promises.readFile(absolutePath, "utf8");
      const result = await callApi("POST", "/fix/config", { config });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        formatFixConfig(result.findings || result);
      }
      return;
    }

    if (command === "harden-prompt") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("harden-prompt requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const systemPrompt = await fs.promises.readFile(absolutePath, "utf8");
      const result = await callApi("POST", "/fix/prompt", { system_prompt: systemPrompt });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        formatHardenPrompt(result.findings || result);
      }
      return;
    }

    if (command === "generate-policy") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("generate-policy requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const mcpConfig = await fs.promises.readFile(absolutePath, "utf8");
      const result = await callApi("POST", "/fix/policy", { mcp_config: mcpConfig });
      if (jsonMode) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        formatGeneratePolicy(result.findings || result);
      }
      return;
    }

    if (command === "report") {
      const reportId = args[0];
      if (!reportId) {
        throw new Error("report requires an audit id.");
      }

      const report = await callApi("GET", `/report/${encodeURIComponent(reportId)}`);
      if (jsonMode) {
        process.stdout.write(JSON.stringify(report, null, 2) + "\n");
      } else {
        formatReport(report);
      }
      return;
    }

    printUsage();
    process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}
