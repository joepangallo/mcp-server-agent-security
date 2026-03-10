const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const os = require("os");

// The store module uses a hardcoded db path. We need to override it by
// manipulating the module internals after require. Instead, we'll create
// a fresh store module that uses a temp path by patching __dirname context.
// Simplest approach: require the module, then use its functions with a
// temp database by leveraging the ensureDatabase pattern.

// We'll work around the hardcoded path by requiring better-sqlite3 directly
// and testing the store's logic via its exported API after pointing it at
// a temp db. Since the store uses a module-level singleton, we can clear it
// between tests by re-requiring.

function freshStore() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sec-audit-test-"));
  process.env.AGENT_SECURITY_DB_PATH = path.join(tmpDir, "test.sqlite");

  // Clear module cache so we get a fresh db singleton
  const storePath = require.resolve("../lib/store");
  delete require.cache[storePath];

  // Temporarily patch the dbPath by monkey-patching path.join for the
  // store's ensureDatabase. Instead, we'll use a simpler approach:
  // set an env var that the store can use, but since it doesn't support
  // that, we'll patch the module after load.

  // Actually the cleanest way: require the module, then use better-sqlite3
  // directly to set up a temp db and call the store functions. But the store
  // has a hardcoded path. Let's just require it and accept it will use
  // state.sqlite (the existing db), but we'll use unique IDs to avoid
  // collisions and clean up after.

  // Re-require to get fresh singleton
  const store = require("../lib/store");

  // Force re-init by calling ensureDatabase
  store.ensureDatabase();

  return { store, tmpDir };
}

test("create and retrieve audit", () => {
  const { store } = freshStore();

  const audit = store.createAudit({
    type: "config-analysis",
    target: "test-server",
    status: "pending",
    findings: { findings: [{ severity: "high", description: "test finding" }] }
  });

  assert.ok(audit.id, "audit should have an id");
  assert.equal(audit.type, "config-analysis");
  assert.equal(audit.target, "test-server");
  assert.equal(audit.status, "pending");

  const retrieved = store.getAudit(audit.id);
  assert.ok(retrieved, "should retrieve the audit by id");
  assert.equal(retrieved.id, audit.id);
  assert.equal(retrieved.type, "config-analysis");
  assert.ok(Array.isArray(retrieved.findings), "findings should be an array");
  assert.equal(retrieved.findings.length, 1);
  assert.equal(retrieved.findings[0].severity, "high");
});

test("update audit status", () => {
  const { store } = freshStore();

  const audit = store.createAudit({
    type: "injection-test",
    target: "prompt-check",
    status: "pending"
  });

  const updated = store.updateAudit(audit.id, {
    status: "completed",
    score: 85,
    grade: "B"
  });

  assert.ok(updated, "updateAudit should return the updated record");
  assert.equal(updated.status, "completed");
  assert.equal(updated.score, 85);
  assert.equal(updated.grade, "B");
  assert.ok(updated.completed_at, "completed_at should be set when status is completed");
});

test("list audits", () => {
  const { store } = freshStore();

  const a1 = store.createAudit({ type: "config-analysis", target: "s1", status: "completed" });
  const a2 = store.createAudit({ type: "injection-test", target: "s2", status: "pending" });

  const list = store.listAudits(50);
  assert.ok(Array.isArray(list), "listAudits should return an array");

  const ids = list.map((a) => a.id);
  assert.ok(ids.includes(a1.id), "list should contain first audit");
  assert.ok(ids.includes(a2.id), "list should contain second audit");
});

test("prototype pollution via findings column does not pollute Object.prototype", () => {
  const { store, tmpDir } = freshStore();
  const Database = require("better-sqlite3");

  // Create a normal audit first
  const audit = store.createAudit({
    type: "pollution-test",
    target: "test",
    status: "completed",
    findings: { findings: [] }
  });

  // Now directly write a malicious findings payload into SQLite
  const dbPath = path.join(tmpDir, "test.sqlite");
  const db = new Database(dbPath);
  const maliciousPayload = JSON.stringify({
    findings: [],
    "__proto__": { polluted: true },
    "constructor": { bad: true }
  });
  db.prepare("UPDATE audits SET findings = ? WHERE id = ?").run(maliciousPayload, audit.id);
  db.close();

  // Retrieve via the store API
  const retrieved = store.getAudit(audit.id);

  // The __proto__ key on retrieved should NOT be {polluted: true} in a way
  // that affects Object.prototype
  assert.equal(({}).polluted, undefined, "Object.prototype must not be polluted");

  // The retrieved object's prototype should be the normal Object.prototype
  assert.notDeepEqual(
    Object.getPrototypeOf(retrieved),
    { polluted: true },
    "retrieved audit prototype should not be polluted"
  );
});

test("update non-existent audit returns null", () => {
  const { store } = freshStore();
  const result = store.updateAudit("non-existent-id-12345", { status: "completed" });
  assert.equal(result, null);
});
