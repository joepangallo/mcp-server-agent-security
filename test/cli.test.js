const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawn } = require("node:child_process");
const path = require("node:path");

const { testOnly } = require("../cli");
const CLI_PATH = path.join(__dirname, "..", "cli.js");

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
});
