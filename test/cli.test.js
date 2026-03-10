const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const { execFile, spawn } = require("node:child_process");
const path = require("path");

const CLI_PATH = path.resolve(__dirname, "..", "cli.js");

function runCli(args, options = {}) {
  return new Promise((resolve) => {
    const timeout = options.timeout || 5000;
    execFile("node", [CLI_PATH, ...args], { timeout, ...options }, (error, stdout, stderr) => {
      resolve({
        exitCode: error ? error.code : 0,
        stdout,
        stderr,
        error
      });
    });
  });
}

describe("cli --help", () => {
  test("exits 0 and prints usage with command names", async () => {
    const result = await runCli(["--help"]);
    assert.equal(result.exitCode, 0);

    const output = result.stderr; // printUsage writes to stderr
    assert.ok(output.includes("scan-config"), "should mention scan-config");
    assert.ok(output.includes("fix-config"), "should mention fix-config");
    assert.ok(output.includes("harden-prompt"), "should mention harden-prompt");
    assert.ok(output.includes("generate-policy"), "should mention generate-policy");
    assert.ok(output.includes("scan-server"), "should mention scan-server");
    assert.ok(output.includes("scan-package"), "should mention scan-package");
    assert.ok(output.includes("scan-injection"), "should mention scan-injection");
    assert.ok(output.includes("scan-dataflow"), "should mention scan-dataflow");
    assert.ok(output.includes("report"), "should mention report");
    assert.ok(output.includes("--mcp"), "should mention --mcp flag");
  });

  test("-h is an alias for --help", async () => {
    const result = await runCli(["-h"]);
    assert.equal(result.exitCode, 0);
    assert.ok(result.stderr.includes("scan-config"));
  });
});

describe("cli --version", () => {
  test("exits 0 and prints a semver version string", async () => {
    const result = await runCli(["--version"]);
    assert.equal(result.exitCode, 0);

    const version = result.stdout.trim();
    assert.match(version, /^\d+\.\d+\.\d+/, "should be a semver version");
  });

  test("-v is an alias for --version", async () => {
    const result = await runCli(["-v"]);
    assert.equal(result.exitCode, 0);
    assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+/);
  });
});

describe("cli --mcp", () => {
  test("starts without crashing (does not exit with code 1 within 1s)", async () => {
    const child = spawn("node", [CLI_PATH, "--mcp"], {
      stdio: ["pipe", "pipe", "pipe"]
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    const result = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        // Process survived 1 second without exiting — success
        child.kill("SIGTERM");
        resolve({ survived: true });
      }, 1000);

      child.on("exit", (code) => {
        clearTimeout(timer);
        resolve({ survived: false, code, stderr });
      });
    });

    if (!result.survived) {
      assert.notEqual(result.code, 1, `--mcp exited early with code ${result.code}: ${result.stderr}`);
    }
    // If it survived the timeout, the test passes (process was killed by us)
  });
});

describe("cli no args / invalid command", () => {
  test("no args exits with code 1 and prints usage to stderr", async () => {
    const result = await runCli([]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("Usage"), "stderr should contain usage info");
  });

  test("invalid command exits with code 1 and prints usage to stderr", async () => {
    const result = await runCli(["invalid-command"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("Usage"), "stderr should contain usage info");
  });
});

describe("cli missing file argument", () => {
  test("scan-config with no file exits 1 with error message", async () => {
    const result = await runCli(["scan-config"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("fix-config with no file exits 1 with error message", async () => {
    const result = await runCli(["fix-config"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("harden-prompt with no file exits 1 with error message", async () => {
    const result = await runCli(["harden-prompt"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("generate-policy with no file exits 1 with error message", async () => {
    const result = await runCli(["generate-policy"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("scan-server with no command exits 1 with error message", async () => {
    const result = await runCli(["scan-server"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("scan-package with no name exits 1 with error message", async () => {
    const result = await runCli(["scan-package"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("scan-injection with no file exits 1 with error message", async () => {
    const result = await runCli(["scan-injection"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("scan-dataflow with no file exits 1 with error message", async () => {
    const result = await runCli(["scan-dataflow"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });

  test("report with no id exits 1 with error message", async () => {
    const result = await runCli(["report"]);
    assert.equal(result.exitCode, 1);
    assert.ok(result.stderr.includes("requires"), "stderr should mention missing argument");
  });
});
