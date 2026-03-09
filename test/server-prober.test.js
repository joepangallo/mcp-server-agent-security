const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const { testOnly } = require("../lib/server-prober");

test("path traversal detection ignores echoed payloads", () => {
  assert.equal(
    testOnly.hasConfirmedPathTraversalSignal("invalid path ../../etc/passwd", "../../etc/passwd"),
    false
  );
});

test("path traversal detection requires real passwd-like content", () => {
  assert.equal(
    testOnly.hasConfirmedPathTraversalSignal(
      "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
      "../../etc/passwd"
    ),
    true
  );
});

test("shell execution detection requires both a canary and command output", () => {
  const payload = `; echo ${testOnly.SHELL_EXECUTION_MARKER} && id #`;

  assert.equal(
    testOnly.hasConfirmedShellExecutionSignal(`rejected input: ${payload}`, payload),
    false
  );
  assert.equal(
    testOnly.hasConfirmedShellExecutionSignal(`${testOnly.SHELL_EXECUTION_MARKER}\nuid=501(user) gid=20(staff)`, payload),
    true
  );
});

test("runtime environment strips reserved launch-control overrides", () => {
  const env = testOnly.buildRuntimeEnvironment({
    SAFE_TOKEN: "allowed",
    PATH: "/tmp/evil-bin",
    NODE_OPTIONS: "--require /tmp/evil.js"
  });

  assert.equal(env.SAFE_TOKEN, "allowed");
  assert.notEqual(env.PATH, "/tmp/evil-bin");
  assert.equal(env.NODE_OPTIONS, undefined);
});

test("runtime environment uses an isolated home directory for probed servers", async () => {
  const sandbox = await testOnly.createRuntimeSandbox();

  try {
    const env = testOnly.buildRuntimeEnvironment({
      SAFE_TOKEN: "allowed",
      HOME: "/tmp/ignored-home"
    }, {
      internalEnv: sandbox.env
    });

    assert.equal(env.SAFE_TOKEN, "allowed");
    assert.equal(env.HOME, sandbox.env.HOME);
    assert.equal(env.USERPROFILE, sandbox.env.USERPROFILE);
    assert.equal(env.XDG_CONFIG_HOME, sandbox.env.XDG_CONFIG_HOME);
    await fs.promises.stat(sandbox.env.HOME);
    await fs.promises.stat(sandbox.env.XDG_CONFIG_HOME);
  } finally {
    await fs.promises.rm(sandbox.rootDir, { recursive: true, force: true });
  }
});

test("sql injection detection looks for parser errors instead of backend names", () => {
  const payload = "' OR '1'='1' --";

  assert.equal(
    testOnly.hasLikelySqlInjectionSignal("Postgres backend unavailable", payload),
    false
  );
  assert.equal(
    testOnly.hasLikelySqlInjectionSignal("syntax error at or near \"'\"", payload),
    true
  );
});
