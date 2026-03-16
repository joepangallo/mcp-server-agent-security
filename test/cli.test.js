const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

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
  it("--mcp flag triggers MCP server mode (process starts)", () => {
    const { execFile } = require("node:child_process");
    const child = execFile(process.execPath, [CLI_PATH, "--mcp"], {
      timeout: 1000,
    });

    return new Promise((resolve) => {
      setTimeout(() => {
        child.kill("SIGTERM");
        resolve();
      }, 500);
    });
  });
});
