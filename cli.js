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
      "  agent-security scan-config <file>",
      "  agent-security scan-server <command> [args...]",
      "  agent-security scan-package <name>",
      "  agent-security report <id>"
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

  const body = await response.json();
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

async function main() {
  const [, , command, ...args] = process.argv;

  try {
    if (command === "scan-config") {
      const filePath = args[0];
      if (!filePath) {
        throw new Error("scan-config requires a file path.");
      }

      const absolutePath = path.resolve(process.cwd(), filePath);
      const config = await fs.promises.readFile(absolutePath, "utf8");
      const report = await callApi("POST", "/audit/config", { config });
      formatReport(report);
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
      formatReport(report);
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
      formatReport(report);
      return;
    }

    if (command === "report") {
      const reportId = args[0];
      if (!reportId) {
        throw new Error("report requires an audit id.");
      }

      const report = await callApi("GET", `/report/${encodeURIComponent(reportId)}`);
      formatReport(report);
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
