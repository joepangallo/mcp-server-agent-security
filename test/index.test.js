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
    delete process.env.AGENT_SECURITY_API_KEY;

    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, "http://127.0.0.1:3091");
  });

  it("BASE_URL defaults to the hosted origin when only AGENT_SECURITY_API_KEY is set", () => {
    delete process.env.AGENT_SECURITY_BASE_URL;
    delete process.env.AGENT_SECURITY_HOST;
    delete process.env.AGENT_SECURITY_PORT;
    process.env.AGENT_SECURITY_API_KEY = "test-key";

    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL, DEFAULT_HOSTED_BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, DEFAULT_HOSTED_BASE_URL);

    delete process.env.AGENT_SECURITY_API_KEY;
  });

  it("BASE_URL respects AGENT_SECURITY_BASE_URL and trims trailing slashes", () => {
    process.env.AGENT_SECURITY_BASE_URL = "https://audit.example.com///";
    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, "https://audit.example.com");
    delete process.env.AGENT_SECURITY_BASE_URL;
  });

  it("explicit loopback host/port override wins over hosted auto-targeting", () => {
    delete process.env.AGENT_SECURITY_BASE_URL;
    process.env.AGENT_SECURITY_API_KEY = "test-key";
    process.env.AGENT_SECURITY_HOST = "127.0.0.1";
    process.env.AGENT_SECURITY_PORT = "4012";

    delete require.cache[require.resolve("../index.js")];
    const { BASE_URL } = require("../index.js");
    assert.equal(BASE_URL, "http://127.0.0.1:4012");

    delete process.env.AGENT_SECURITY_API_KEY;
    delete process.env.AGENT_SECURITY_HOST;
    delete process.env.AGENT_SECURITY_PORT;
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

function loadIndex() {
  delete require.cache[require.resolve("../index.js")];
  return require("../index.js");
}

function refusedConnectionError() {
  const error = new TypeError("fetch failed");
  error.cause = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:3091"), {
    code: "ECONNREFUSED"
  });
  return error;
}

describe("index.js — connection failure classification", () => {
  it("treats a bare undici TypeError as a connection failure", () => {
    const { isConnectionError } = loadIndex();
    assert.equal(isConnectionError(new TypeError("fetch failed")), true);
  });

  it("treats a nested ECONNREFUSED cause as a connection failure", () => {
    const { isConnectionError } = loadIndex();
    assert.equal(isConnectionError(refusedConnectionError()), true);
  });

  it("treats an AggregateError of transport failures as a connection failure", () => {
    const { isConnectionError } = loadIndex();
    const aggregate = new AggregateError(
      [Object.assign(new Error("connect ECONNREFUSED ::1:3091"), { code: "ECONNREFUSED" })],
      "all attempts failed"
    );
    assert.equal(isConnectionError(new TypeError("fetch failed", { cause: aggregate })), true);
  });

  it("does not treat aborts or ordinary errors as connection failures", () => {
    const { isConnectionError } = loadIndex();
    const abort = new Error("This operation was aborted");
    abort.name = "AbortError";

    assert.equal(isConnectionError(abort), false);
    assert.equal(isConnectionError(new Error("Request failed with status 500")), false);
    assert.equal(isConnectionError(null), false);
  });
});

describe("index.js — connection failure message", () => {
  it("names the loopback URL it tried and every env var that redirects it", () => {
    const { buildConnectionErrorMessage, DEFAULT_HOSTED_BASE_URL } = loadIndex();
    const message = buildConnectionErrorMessage(refusedConnectionError(), "http://127.0.0.1:3091");

    assert.match(message, /http:\/\/127\.0\.0\.1:3091/);
    assert.match(message, /ECONNREFUSED/);
    assert.match(message, /AGENT_SECURITY_API_KEY/);
    assert.match(message, /AGENT_SECURITY_BASE_URL/);
    assert.match(message, /AGENT_SECURITY_HOST/);
    assert.ok(message.includes(DEFAULT_HOSTED_BASE_URL));
    // The raw "fetch failed" text must never be the whole story.
    assert.notEqual(message.trim(), "fetch failed");
  });

  it("gives remote-host guidance instead of local-startup guidance for hosted origins", () => {
    const { buildConnectionErrorMessage } = loadIndex();
    const message = buildConnectionErrorMessage(
      new TypeError("fetch failed", {
        cause: Object.assign(new Error("getaddrinfo ENOTFOUND audit.example.com"), { code: "ENOTFOUND" })
      }),
      "https://audit.example.com"
    );

    assert.match(message, /https:\/\/audit\.example\.com/);
    assert.match(message, /ENOTFOUND/);
    assert.match(message, /AGENT_SECURITY_BASE_URL/);
    assert.doesNotMatch(message, /Nothing is listening/);
  });

  it("still names the endpoint when the failure carries no error code", () => {
    const { buildConnectionErrorMessage } = loadIndex();
    const message = buildConnectionErrorMessage(new TypeError("fetch failed"), "http://127.0.0.1:3091");
    assert.match(message, /http:\/\/127\.0\.0\.1:3091/);
  });
});

describe("index.js — forbidden message", () => {
  it("tells a key-holding user their key was rejected", () => {
    const { buildForbiddenMessage } = loadIndex();
    const message = buildForbiddenMessage("https://audit.leddconsulting.com", true);

    assert.match(message, /403/);
    assert.match(message, /AGENT_SECURITY_API_KEY was not accepted/);
    assert.match(message, /audit\.leddconsulting\.com/);
    assert.doesNotMatch(message, /loopback/i);
  });

  it("tells a key-less user to set an API key", () => {
    const { buildForbiddenMessage } = loadIndex();
    const message = buildForbiddenMessage("https://audit.leddconsulting.com", false);

    assert.match(message, /403/);
    assert.match(message, /no API key was sent/);
    assert.match(message, /Set AGENT_SECURITY_API_KEY/);
    assert.doesNotMatch(message, /loopback/i);
  });
});
