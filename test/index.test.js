const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

describe("index.js exports", () => {
  it("exports PORT as a number defaulting to 3091", () => {
    // Clear any env override so we test the default
    const saved = process.env.AGENT_SECURITY_PORT;
    delete process.env.AGENT_SECURITY_PORT;

    // Re-require to pick up defaults
    delete require.cache[require.resolve("../index.js")];
    const { PORT } = require("../index.js");

    assert.equal(typeof PORT, "number");
    assert.equal(PORT, 3091);

    // Restore
    if (saved !== undefined) process.env.AGENT_SECURITY_PORT = saved;
  });

  it("exports HOST as a string defaulting to 127.0.0.1", () => {
    const saved = process.env.AGENT_SECURITY_HOST;
    delete process.env.AGENT_SECURITY_HOST;

    delete require.cache[require.resolve("../index.js")];
    const { HOST } = require("../index.js");

    assert.equal(typeof HOST, "string");
    assert.equal(HOST, "127.0.0.1");

    if (saved !== undefined) process.env.AGENT_SECURITY_HOST = saved;
  });

  it("PORT respects AGENT_SECURITY_PORT env var", () => {
    process.env.AGENT_SECURITY_PORT = "4000";
    delete require.cache[require.resolve("../index.js")];
    const { PORT } = require("../index.js");
    assert.equal(PORT, 4000);
    delete process.env.AGENT_SECURITY_PORT;
  });

  it("HOST respects AGENT_SECURITY_HOST env var", () => {
    process.env.AGENT_SECURITY_HOST = "localhost";
    delete require.cache[require.resolve("../index.js")];
    const { HOST } = require("../index.js");
    assert.equal(HOST, "localhost");
    delete process.env.AGENT_SECURITY_HOST;
  });

  it("BASE_URL defaults to a local http origin", () => {
    delete process.env.AGENT_SECURITY_BASE_URL;
    delete process.env.AGENT_SECURITY_HOST;
    delete process.env.AGENT_SECURITY_PORT;

    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, "http://127.0.0.1:3091");
  });

  it("BASE_URL respects AGENT_SECURITY_BASE_URL and trims trailing slashes", () => {
    process.env.AGENT_SECURITY_BASE_URL = "https://audit.example.com///";
    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, "https://audit.example.com");
    delete process.env.AGENT_SECURITY_BASE_URL;
  });

  it("rejects non-loopback host/port fallback without AGENT_SECURITY_BASE_URL", () => {
    delete process.env.AGENT_SECURITY_BASE_URL;
    process.env.AGENT_SECURITY_HOST = "audit.example.com";
    delete require.cache[require.resolve("../index.js")];

    assert.throws(() => require("../index.js"), /https:\/\/ origin/);

    delete process.env.AGENT_SECURITY_HOST;
  });

  it("rejects non-loopback http AGENT_SECURITY_BASE_URL", () => {
    process.env.AGENT_SECURITY_BASE_URL = "http://audit.example.com";
    delete require.cache[require.resolve("../index.js")];

    assert.throws(() => require("../index.js"), /https:\/\//);

    delete process.env.AGENT_SECURITY_BASE_URL;
  });
});
