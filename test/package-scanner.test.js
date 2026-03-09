const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { normalizePackageSpecifier, parseTarEntries, testOnly } = require("../lib/package-scanner");

test("normalizePackageSpecifier accepts registry package names and exact versions", () => {
  assert.equal(normalizePackageSpecifier("left-pad"), "left-pad");
  assert.equal(normalizePackageSpecifier("@scope/pkg@1.2.3"), "@scope/pkg@1.2.3");
  assert.equal(normalizePackageSpecifier("pkg@latest"), "pkg@latest");
});

test("normalizePackageSpecifier rejects urls, paths, and range specifiers", () => {
  assert.throws(() => normalizePackageSpecifier("https://evil.example/pkg.tgz"));
  assert.throws(() => normalizePackageSpecifier("../local-package"));
  assert.throws(() => normalizePackageSpecifier("@scope/pkg@^1.2.3"));
});

test("parseTarEntries parses regular files and directories", () => {
  const entries = parseTarEntries([
    "drwxr-xr-x 0/0               0 2026-03-09 00:00:00 package/",
    "-rw-r--r-- 0/0             123 2026-03-09 00:00:00 package/index.js"
  ].join("\n"));

  assert.deepEqual(entries, [
    { type: "d", rawPath: "package/" },
    { type: "-", rawPath: "package/index.js" }
  ]);
});

test("resolveNpmRegistry only accepts https and loopback http overrides", () => {
  assert.equal(testOnly.resolveNpmRegistry("http://example.com/private-registry"), "https://registry.npmjs.org/");
  assert.equal(testOnly.resolveNpmRegistry("https://registry.example.com"), "https://registry.example.com/");
  assert.equal(testOnly.resolveNpmRegistry("http://127.0.0.1:4873"), "http://127.0.0.1:4873/");
});

test("buildNpmScanEnvironment strips ambient npm credentials and config", async () => {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "pkg-scan-env-"));
  const originalPath = process.env.PATH;
  const originalNodeAuthToken = process.env.NODE_AUTH_TOKEN;
  const originalNpmConfigRegistry = process.env.NPM_CONFIG_REGISTRY;
  const originalHome = process.env.HOME;

  process.env.PATH = originalPath || "/usr/bin";
  process.env.NODE_AUTH_TOKEN = "top-secret-token";
  process.env.NPM_CONFIG_REGISTRY = "https://internal.example.invalid/";

  try {
    const env = await testOnly.buildNpmScanEnvironment(tmpDir);

    assert.equal(env.NODE_AUTH_TOKEN, undefined);
    assert.equal(env.NPM_CONFIG_REGISTRY, "https://registry.npmjs.org/");
    assert.match(env.NPM_CONFIG_USERCONFIG, /user\.npmrc$/);
    assert.notEqual(env.HOME, originalHome);
    await fs.promises.stat(env.NPM_CONFIG_USERCONFIG);
  } finally {
    if (originalPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = originalPath;
    }

    if (originalNodeAuthToken === undefined) {
      delete process.env.NODE_AUTH_TOKEN;
    } else {
      process.env.NODE_AUTH_TOKEN = originalNodeAuthToken;
    }

    if (originalNpmConfigRegistry === undefined) {
      delete process.env.NPM_CONFIG_REGISTRY;
    } else {
      process.env.NPM_CONFIG_REGISTRY = originalNpmConfigRegistry;
    }

    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  }
});
