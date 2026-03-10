const test = require("node:test");
const assert = require("node:assert/strict");
const { isPlainObject, withTimeout, uuidv4, importFirst } = require("../lib/utils");

// ── isPlainObject ──

test("isPlainObject returns true for plain objects", () => {
  assert.equal(isPlainObject({}), true);
  assert.equal(isPlainObject({ a: 1 }), true);
  assert.equal(isPlainObject(Object.create(null)), true);
});

test("isPlainObject returns false for null, undefined, arrays, primitives, and functions", () => {
  assert.equal(isPlainObject(null), false);
  assert.equal(isPlainObject(undefined), false);
  assert.equal(isPlainObject([]), false);
  assert.equal(isPlainObject("string"), false);
  assert.equal(isPlainObject(42), false);
  assert.equal(isPlainObject(function () {}), false);
});

test("isPlainObject treats Date objects as plain objects (implementation quirk)", () => {
  // The current implementation considers any non-null, non-array object as plain.
  // This verifies the actual behavior so callers know Date passes the check.
  assert.equal(isPlainObject(new Date()), true);
});

// ── withTimeout ──

test("withTimeout resolves when fn completes before timeout", async () => {
  const result = await withTimeout(
    Promise.resolve("done"),
    500,
    "fast-op"
  );
  assert.equal(result, "done");
});

test("withTimeout rejects with timeout error when fn takes too long", async () => {
  const slow = new Promise((resolve) => setTimeout(() => resolve("late"), 200));
  await assert.rejects(
    () => withTimeout(slow, 50, "slow-op"),
    (err) => {
      assert.ok(err instanceof Error);
      assert.ok(err.message.includes("slow-op"));
      assert.ok(err.message.includes("timed out"));
      return true;
    }
  );
});

// ── uuidv4 ──

test("uuidv4 returns a string matching UUID v4 pattern", () => {
  const id = uuidv4();
  assert.equal(typeof id, "string");
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
});

test("uuidv4 returns different values on successive calls", () => {
  const a = uuidv4();
  const b = uuidv4();
  assert.notEqual(a, b);
});

// ── importFirst ──

test("importFirst returns the first successful import", async () => {
  // "node:path" should always be importable
  const result = await importFirst(["node:path"]);
  assert.ok(result);
  assert.equal(typeof result.join, "function");
});

test("importFirst throws when all specifiers fail", async () => {
  await assert.rejects(
    () => importFirst(["nonexistent-module-abc123", "also-nonexistent-xyz789"]),
    (err) => {
      assert.ok(err instanceof Error);
      return true;
    }
  );
});
