const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");

const { testOnly } = require("../cli");
const CLI_PATH = path.join(__dirname, "..", "cli.js");
const SAMPLE_CONFIG = path.join(__dirname, "..", "examples", "vulnerable-config.json");

function cliEnv(overrides = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("AGENT_SECURITY_")) {
      delete env[key];
    }
  }
  return { ...env, ...overrides };
}

function runCliAsync(args = [], envOverrides = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: path.join(__dirname, ".."),
      env: cliEnv(envOverrides),
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (exitCode) => resolve({ stdout, stderr, exitCode }));
  });
}

async function reserveClosedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

function runCli(args = []) {
  try {
    const stdout = execFileSync(process.execPath, [CLI_PATH, ...args], {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    return {
      stdout: err.stdout || "",
      stderr: err.stderr || "",
      exitCode: err.status,
    };
  }
}

describe("CLI — help", () => {
  it("--help prints usage and exits 0", () => {
    // printUsage writes to stderr, but exit code is 0.
    // execFileSync doesn't throw on exit 0, so stderr isn't captured
    // via the error path. Instead we verify it exits cleanly and
    // produces no error output on stdout.
    const result = runCli(["--help"]);
    assert.equal(result.exitCode, 0);
    // The CLI prints usage to stderr. On success, stdout should be empty.
    assert.equal(result.stdout.trim(), "");
  });

  it("-h prints usage and exits 0", () => {
    const result = runCli(["-h"]);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.trim(), "");
  });
});

describe("CLI — version", () => {
  it("--version prints the version number", () => {
    const result = runCli(["--version"]);
    assert.equal(result.exitCode, 0);
    assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+$/);
  });

  it("-v prints the version number", () => {
    const result = runCli(["-v"]);
    assert.equal(result.exitCode, 0);
    assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+$/);
  });
});

describe("CLI — unknown commands", () => {
  it("unknown command prints usage and exits 1", () => {
    const result = runCli(["bogus-command"]);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /Usage/);
  });

  it("no arguments prints usage and exits 1", () => {
    const result = runCli([]);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /Usage/);
  });
});

describe("CLI — --mcp flag", () => {
  it("--mcp flag keeps the MCP server process alive", async () => {
    const child = spawn(process.execPath, [CLI_PATH, "--mcp"], {
      cwd: path.join(__dirname, ".."),
      stdio: ["pipe", "pipe", "pipe"],
    });

    let exitCode = null;
    child.on("exit", (code) => {
      exitCode = code;
    });

    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(exitCode, null);
    child.kill("SIGTERM");
    await new Promise((resolve) => child.once("exit", resolve));
  });
});

describe("CLI — parsing", () => {
  it("supports --json before the command", () => {
    const parsed = testOnly.parseCliArgs(["--json", "report", "abc"]);
    assert.equal(parsed.command, "report");
    assert.deepEqual(parsed.args, ["abc"]);
    assert.equal(parsed.jsonMode, true);
  });

  it("removes --json from scan-server forwarded args", () => {
    const parsed = testOnly.parseCliArgs(["scan-server", "node", "--json", "server.js"]);
    assert.equal(parsed.command, "scan-server");
    assert.deepEqual(parsed.args, ["node", "server.js"]);
    assert.equal(parsed.jsonMode, true);
  });

  it("supports scan-trust arguments with optional policy file", () => {
    const parsed = testOnly.parseCliArgs(["scan-trust", "config.json", "policy.json", "--json"]);
    assert.equal(parsed.command, "scan-trust");
    assert.deepEqual(parsed.args, ["config.json", "policy.json"]);
    assert.equal(parsed.jsonMode, true);
  });
});

describe("CLI — auth guidance", () => {
  it("buildUnauthorizedMessage points hosted users at AGENT_SECURITY_API_KEY", () => {
    const savedBaseUrl = process.env.AGENT_SECURITY_BASE_URL;
    const savedApiKey = process.env.AGENT_SECURITY_API_KEY;

    delete process.env.AGENT_SECURITY_API_KEY;
    process.env.AGENT_SECURITY_BASE_URL = "https://audit.leddconsulting.com";

    delete require.cache[require.resolve("../index.js")];
    delete require.cache[require.resolve("../cli.js")];
    const cliModule = require("../cli.js");

    assert.match(
      cliModule.testOnly.buildUnauthorizedMessage("Unauthorized."),
      /AGENT_SECURITY_API_KEY/
    );
    assert.match(
      cliModule.testOnly.buildUnauthorizedMessage("Unauthorized."),
      /audit\.leddconsulting\.com/
    );

    if (savedBaseUrl === undefined) {
      delete process.env.AGENT_SECURITY_BASE_URL;
    } else {
      process.env.AGENT_SECURITY_BASE_URL = savedBaseUrl;
    }

    if (savedApiKey === undefined) {
      delete process.env.AGENT_SECURITY_API_KEY;
    } else {
      process.env.AGENT_SECURITY_API_KEY = savedApiKey;
    }

    delete require.cache[require.resolve("../index.js")];
    delete require.cache[require.resolve("../cli.js")];
  });
});

describe("CLI — unreachable backend", () => {
  it("explains a refused loopback connection instead of printing 'fetch failed'", async () => {
    const port = await reserveClosedPort();
    const result = await runCliAsync(["scan-config", SAMPLE_CONFIG], {
      AGENT_SECURITY_BASE_URL: `http://127.0.0.1:${port}`,
    });

    assert.equal(result.exitCode, 1);
    assert.notEqual(result.stderr.trim(), "fetch failed");
    assert.match(result.stderr, /Could not reach the audit API/);
    assert.match(result.stderr, new RegExp(`http://127\\.0\\.0\\.1:${port}`));
    assert.match(result.stderr, /AGENT_SECURITY_API_KEY/);
    assert.match(result.stderr, /AGENT_SECURITY_BASE_URL/);
  });

  it("turns a backend 403 into key guidance without leaking loopback semantics", async () => {
    const server = http.createServer((req, res) => {
      req.resume();
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({
        error: "Audit API only accepts direct loopback clients unless AGENT_SECURITY_API_KEY is configured"
      }));
    });

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();

    try {
      const result = await runCliAsync(["scan-config", SAMPLE_CONFIG], {
        AGENT_SECURITY_BASE_URL: `http://127.0.0.1:${port}`,
        AGENT_SECURITY_API_KEY: "test-key",
      });

      assert.equal(result.exitCode, 1);
      assert.match(result.stderr, /403/);
      assert.match(result.stderr, /AGENT_SECURITY_API_KEY was not accepted/);
      assert.doesNotMatch(result.stderr, /loopback/i);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

describe("CLI — error formatting", () => {
  it("describeCliError maps transport failures and passes other errors through", () => {
    const refused = new TypeError("fetch failed");
    refused.cause = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:3091"), {
      code: "ECONNREFUSED",
    });

    assert.match(testOnly.describeCliError(refused), /Could not reach the audit API/);
    assert.equal(
      testOnly.describeCliError(new Error("scan-config requires a file path.")),
      "scan-config requires a file path."
    );
  });

  it("buildForbiddenCliMessage never echoes the backend's loopback wording", () => {
    const message = testOnly.buildForbiddenCliMessage();
    assert.match(message, /403/);
    assert.match(message, /AGENT_SECURITY_API_KEY/);
    assert.doesNotMatch(message, /loopback/i);
  });
});

describe("CLI — trust formatter", () => {
  it("formats trust audits with inventories and policy drift", () => {
    const originalTable = console.table;
    const tables = [];
    const writes = [];
    console.table = (value) => tables.push(value);
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk) => {
      writes.push(String(chunk));
      return true;
    });

    try {
      testOnly.formatTrustAudit({
        id: "trust-1",
        target: "demo",
        status: "completed",
        trust: {
          score: 74,
          grade: "C",
          networkPolicy: "allowlist",
          provenanceCoverage: "observed",
          toolPermissionInventory: [
            { tool: "Bash", enabled: true, permission: "workspace-only", risk: "high" },
          ],
          secretExposureChecks: [
            { name: "env-scan", status: "passed", exposure: "none" },
          ],
          policyDiff: [
            { control: "network", claimed: "disabled", observed: "allowlist", status: "drift" },
          ],
        },
        findings: [
          { severity: "medium", source: "trust", description: "Open network policy" },
        ],
      });
    } finally {
      console.table = originalTable;
      process.stdout.write = originalWrite;
    }

    assert.equal(tables.length >= 4, true);
    assert.match(writes.join(""), /Claimed-vs-observed policy drift/);
  });
});
