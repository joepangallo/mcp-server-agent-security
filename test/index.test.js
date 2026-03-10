const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

async function withFreshIndex(testFn) {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "agent-sec-index-"));
  const managedKeys = ["AGENT_SECURITY_DB_PATH"];
  const previousEnv = Object.fromEntries(managedKeys.map((key) => [key, process.env[key]]));

  process.env.AGENT_SECURITY_DB_PATH = path.join(tmpDir, "state.sqlite");

  const storePath = require.resolve("../lib/store");
  const orchestrationPath = require.resolve("../lib/audit-orchestration");
  const indexPath = require.resolve("../index");
  delete require.cache[storePath];
  delete require.cache[orchestrationPath];
  delete require.cache[indexPath];

  try {
    await testFn(require("../index"));
  } finally {
    delete require.cache[storePath];
    delete require.cache[orchestrationPath];
    delete require.cache[indexPath];
    await fs.promises.rm(tmpDir, { recursive: true, force: true });

    for (const [key, value] of Object.entries(previousEnv)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test("executeAuditJob redacts deep sensitive fields and tolerates circular metadata", async () => {
  await withFreshIndex(async ({ executeAuditJob }) => {
    const result = {
      findings: []
    };

    result.deep = {
      a: {
        b: {
          c: {
            d: {
              e: {
                f: {
                  rawOutput: "deep-secret-value",
                  samples: ["deep-secret-value"]
                }
              }
            }
          }
        }
      }
    };
    result.circular = result;

    const audit = await executeAuditJob("config", "mcp-config", async () => result);
    const serialized = JSON.stringify(audit);

    assert.equal(audit.status, "completed");
    assert.equal(audit.serializationError, undefined);
    assert.doesNotMatch(serialized, /deep-secret-value/);
    assert.doesNotMatch(serialized, /rawOutput/);
    assert.doesNotMatch(serialized, /samples/);
    assert.match(serialized, /\[truncated\]/);
    assert.match(serialized, /\[circular\]/);
  });
});
