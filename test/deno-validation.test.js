const test = require("node:test");
const assert = require("node:assert/strict");
const { testOnly: { validateServerLaunchSpec } } = require("../index");

test("deno run --allow-all is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-all", "script.js"]);
  assert.ok(result.error, "should be rejected");
  assert.match(result.error, /not allowed/i);
});

test("deno run --allow-sys is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-sys", "script.js"]);
  assert.ok(result.error);
  assert.match(result.error, /not allowed/i);
});

test("deno run --allow-ffi is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-ffi", "script.js"]);
  assert.ok(result.error);
  assert.match(result.error, /not allowed/i);
});

test("deno run --allow-run (unscoped) is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-run", "script.js"]);
  assert.ok(result.error);
  assert.match(result.error, /scope/i);
});

test("deno run --allow-run=/usr/bin/node (scoped) is allowed", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-run=/usr/bin/node", "script.js"]);
  assert.ok(!result.error, `unexpected error: ${result.error}`);
  assert.equal(result.command, "deno");
});

test("deno run --allow-net (unscoped) is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-net", "script.js"]);
  assert.ok(result.error);
  assert.match(result.error, /scope/i);
});

test("deno run --allow-net=example.com (scoped) is allowed", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--allow-net=example.com", "script.js"]);
  assert.ok(!result.error, `unexpected error: ${result.error}`);
  assert.equal(result.command, "deno");
});

test("deno run --eval is rejected", () => {
  const result = validateServerLaunchSpec("deno", ["run", "--eval", "code"]);
  assert.ok(result.error);
  assert.match(result.error, /eval/i);
});

test("deno run script.js (clean) is allowed", () => {
  const result = validateServerLaunchSpec("deno", ["run", "script.js"]);
  assert.ok(!result.error, `unexpected error: ${result.error}`);
  assert.equal(result.command, "deno");
  assert.deepEqual(result.args, ["run", "script.js"]);
});
