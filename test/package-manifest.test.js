const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");

const execFileAsync = promisify(execFile);

test("npm pack dry-run includes the public proxy entrypoints", async () => {
  const cacheDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "mcp-audit-pack-cache-"));

  try {
    const { stdout } = await execFileAsync("npm", ["pack", "--json", "--dry-run"], {
      cwd: path.join(__dirname, ".."),
      env: {
        ...process.env,
        npm_config_cache: cacheDir,
        NPM_CONFIG_CACHE: cacheDir
      },
      maxBuffer: 10 * 1024 * 1024
    });
    const packOutput = JSON.parse(stdout);
    const packRecord = Array.isArray(packOutput)
      ? packOutput[0]
      : packOutput && typeof packOutput === "object"
        ? packOutput["ledd-mcp-audit-server"]
        : undefined;
    assert.ok(packRecord, "npm pack returned package metadata");
    const filePaths = new Set((packRecord.files || []).map((entry) => entry.path));

    assert.equal(packRecord.name, "ledd-mcp-audit-server");
    assert.ok(filePaths.has("index.js"));
    assert.ok(filePaths.has("cli.js"));
    assert.ok(filePaths.has("CHANGELOG.md"));
    assert.ok(filePaths.has("MIGRATION.md"));
    assert.ok(filePaths.has("server.json"));
  } finally {
    await fs.promises.rm(cacheDir, { recursive: true, force: true });
  }
});
