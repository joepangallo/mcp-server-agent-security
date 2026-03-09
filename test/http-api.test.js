const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { once } = require("events");

async function startFreshServer(envOverrides = {}) {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "agent-sec-http-"));
  const managedKeys = ["AGENT_SECURITY_API_KEY", "AGENT_SECURITY_ADMIN_MODE", "AGENT_SECURITY_DB_PATH"];
  const previousEnv = Object.fromEntries(managedKeys.map((key) => [key, process.env[key]]));

  for (const key of managedKeys) {
    delete process.env[key];
  }

  process.env.AGENT_SECURITY_DB_PATH = path.join(tmpDir, "state.sqlite");
  for (const [key, value] of Object.entries(envOverrides)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  const storePath = require.resolve("../lib/store");
  const indexPath = require.resolve("../index");
  delete require.cache[storePath];
  delete require.cache[indexPath];

  const { createApp } = require("../index");
  const server = createApp().listen(0, "127.0.0.1");
  await once(server, "listening");

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      await fs.promises.rm(tmpDir, { recursive: true, force: true });
      delete require.cache[storePath];
      delete require.cache[indexPath];

      for (const [key, value] of Object.entries(previousEnv)) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    }
  };
}

test("health is public but active server probing requires admin mode", async () => {
  const ctx = await startFreshServer({ AGENT_SECURITY_ADMIN_MODE: "0" });

  try {
    const healthResponse = await fetch(`${ctx.baseUrl}/health`);
    assert.equal(healthResponse.status, 200);

    const probeResponse = await fetch(`${ctx.baseUrl}/audit/server`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        command: "node",
        args: ["--version"]
      })
    });

    assert.equal(probeResponse.status, 403);
    const body = await probeResponse.json();
    assert.match(body.error, /AGENT_SECURITY_ADMIN_MODE=1/);
  } finally {
    await ctx.close();
  }
});
