const test = require("node:test");
const assert = require("node:assert/strict");
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
