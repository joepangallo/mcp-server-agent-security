const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  isCommandAllowed,
  getCommandBase,
  stripDisallowedRuntimeEnvKeys,
  isAdminModeEnabled
} = require("../lib/runtime-policy");

// --- isCommandAllowed ---

test("isCommandAllowed allows node", () => {
  assert.equal(isCommandAllowed("node server.js"), true);
});

test("isCommandAllowed allows python3", () => {
  assert.equal(isCommandAllowed("python3 main.py"), true);
});

test("isCommandAllowed allows npx", () => {
  assert.equal(isCommandAllowed("npx some-package"), true);
});

test("isCommandAllowed rejects bash", () => {
  assert.equal(isCommandAllowed("bash -c 'echo hi'"), false);
});

test("isCommandAllowed rejects rm", () => {
  assert.equal(isCommandAllowed("rm -rf /"), false);
});

test("isCommandAllowed rejects curl", () => {
  assert.equal(isCommandAllowed("curl https://evil.com"), false);
});

test("isCommandAllowed rejects empty string", () => {
  assert.equal(isCommandAllowed(""), false);
});

test("isCommandAllowed rejects non-string input", () => {
  assert.equal(isCommandAllowed(null), false);
  assert.equal(isCommandAllowed(undefined), false);
  assert.equal(isCommandAllowed(42), false);
});

test("isCommandAllowed respects custom allowlist", () => {
  const custom = new Set(["curl", "wget"]);
  assert.equal(isCommandAllowed("curl https://example.com", custom), true);
  assert.equal(isCommandAllowed("node server.js", custom), false);
});

// --- getCommandBase ---

test("getCommandBase extracts binary from absolute path", () => {
  assert.equal(getCommandBase("/usr/bin/node"), "/usr/bin/node");
});

test("getCommandBase extracts plain command", () => {
  assert.equal(getCommandBase("node"), "node");
});

test("getCommandBase extracts relative path command", () => {
  assert.equal(getCommandBase("./node server.js"), "./node");
});

test("getCommandBase strips arguments", () => {
  assert.equal(getCommandBase("python3 -m http.server"), "python3");
});

test("getCommandBase returns empty for non-string", () => {
  assert.equal(getCommandBase(null), "");
  assert.equal(getCommandBase(undefined), "");
  assert.equal(getCommandBase(123), "");
});

test("getCommandBase returns empty for whitespace-only", () => {
  assert.equal(getCommandBase("   "), "");
});

// --- stripDisallowedRuntimeEnvKeys ---

test("stripDisallowedRuntimeEnvKeys removes PATH", () => {
  const result = stripDisallowedRuntimeEnvKeys({ PATH: "/usr/bin", MY_VAR: "ok" });
  assert.equal(result.MY_VAR, "ok");
  assert.equal(result.PATH, undefined);
});

test("stripDisallowedRuntimeEnvKeys removes NODE_OPTIONS", () => {
  const result = stripDisallowedRuntimeEnvKeys({ NODE_OPTIONS: "--max-old-space-size=4096", SAFE: "yes" });
  assert.equal(result.NODE_OPTIONS, undefined);
  assert.equal(result.SAFE, "yes");
});

test("stripDisallowedRuntimeEnvKeys removes LD_PRELOAD", () => {
  const result = stripDisallowedRuntimeEnvKeys({ LD_PRELOAD: "/lib/evil.so", APP_NAME: "test" });
  assert.equal(result.LD_PRELOAD, undefined);
  assert.equal(result.APP_NAME, "test");
});

test("stripDisallowedRuntimeEnvKeys removes PYTHONPATH", () => {
  const result = stripDisallowedRuntimeEnvKeys({ PYTHONPATH: "/sneaky", OK: "1" });
  assert.equal(result.PYTHONPATH, undefined);
  assert.equal(result.OK, "1");
});

test("stripDisallowedRuntimeEnvKeys returns undefined when all keys are disallowed", () => {
  const result = stripDisallowedRuntimeEnvKeys({ PATH: "/bin", NODE_OPTIONS: "--x" });
  assert.equal(result, undefined);
});

test("stripDisallowedRuntimeEnvKeys returns undefined for null/array/non-object", () => {
  assert.equal(stripDisallowedRuntimeEnvKeys(null), undefined);
  assert.equal(stripDisallowedRuntimeEnvKeys([1, 2]), undefined);
  assert.equal(stripDisallowedRuntimeEnvKeys("string"), undefined);
});

test("stripDisallowedRuntimeEnvKeys preserves safe keys", () => {
  const result = stripDisallowedRuntimeEnvKeys({ API_KEY: "abc", DATABASE_URL: "postgres://..." });
  assert.equal(result.API_KEY, "abc");
  assert.equal(result.DATABASE_URL, "postgres://...");
});

// --- isAdminModeEnabled ---

test("isAdminModeEnabled returns true when env is '1'", () => {
  const original = process.env.AGENT_SECURITY_ADMIN_MODE;
  process.env.AGENT_SECURITY_ADMIN_MODE = "1";
  assert.equal(isAdminModeEnabled(), true);
  if (original === undefined) {
    delete process.env.AGENT_SECURITY_ADMIN_MODE;
  } else {
    process.env.AGENT_SECURITY_ADMIN_MODE = original;
  }
});

test("isAdminModeEnabled returns false when env is 'true'", () => {
  const original = process.env.AGENT_SECURITY_ADMIN_MODE;
  process.env.AGENT_SECURITY_ADMIN_MODE = "true";
  assert.equal(isAdminModeEnabled(), false);
  if (original === undefined) {
    delete process.env.AGENT_SECURITY_ADMIN_MODE;
  } else {
    process.env.AGENT_SECURITY_ADMIN_MODE = original;
  }
});

test("isAdminModeEnabled returns false when env is empty string", () => {
  const original = process.env.AGENT_SECURITY_ADMIN_MODE;
  process.env.AGENT_SECURITY_ADMIN_MODE = "";
  assert.equal(isAdminModeEnabled(), false);
  if (original === undefined) {
    delete process.env.AGENT_SECURITY_ADMIN_MODE;
  } else {
    process.env.AGENT_SECURITY_ADMIN_MODE = original;
  }
});

test("isAdminModeEnabled returns false when env is undefined", () => {
  const original = process.env.AGENT_SECURITY_ADMIN_MODE;
  delete process.env.AGENT_SECURITY_ADMIN_MODE;
  assert.equal(isAdminModeEnabled(), false);
  if (original !== undefined) {
    process.env.AGENT_SECURITY_ADMIN_MODE = original;
  }
});
