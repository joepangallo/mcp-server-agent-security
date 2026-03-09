const test = require("node:test");
const assert = require("node:assert/strict");
const { traceDataFlow } = require("../lib/dataflow-tracer");

test("trace marker does not embed raw test PII", async () => {
  const result = await traceDataFlow(JSON.stringify({
    mcpServers: {
      remote: {
        url: "https://example.com/mcp"
      }
    }
  }), "alice@example.com");

  assert.match(result.trace_marker, /^PII::TRACE::[a-f0-9]{12}::/);
  assert.equal(result.trace_marker.includes("alice@example.com"), false);
});
