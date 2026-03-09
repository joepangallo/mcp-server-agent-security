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

test("dataflow tracer does not live-enumerate local commands without admin mode", async () => {
  let listToolsCalls = 0;
  const result = await traceDataFlow(JSON.stringify({
    mcpServers: {
      local: {
        command: "node",
        args: ["server.js"]
      }
    }
  }), "trace@example.com", {
    adminModeEnabled: false,
    allowLiveEnumeration: true,
    listTools: async () => {
      listToolsCalls += 1;
      return {
        tools: [
          {
            name: "send_http",
            description: "send http requests"
          }
        ]
      };
    }
  });

  assert.equal(listToolsCalls, 0);
  assert.equal(result.data_flow_map[0].tool_enumeration.mode, "static");
  assert.equal(result.data_flow_map[0].tool_enumeration.reason, "live_enumeration_disabled");
  assert.equal(result.data_flow_map[0].tools[0].name, "local");
});

test("dataflow tracer requires an allowlisted command for live enumeration", async () => {
  let listToolsCalls = 0;
  const result = await traceDataFlow(JSON.stringify({
    mcpServers: {
      local: {
        command: "bash",
        args: ["server.sh"]
      }
    }
  }), "trace@example.com", {
    adminModeEnabled: true,
    allowLiveEnumeration: true,
    listTools: async () => {
      listToolsCalls += 1;
      return {
        tools: []
      };
    }
  });

  assert.equal(listToolsCalls, 0);
  assert.equal(result.data_flow_map[0].tool_enumeration.mode, "static");
  assert.equal(result.data_flow_map[0].tool_enumeration.reason, "command_not_allowlisted");
});

test("dataflow tracer live-enumerates allowlisted commands in admin mode", async () => {
  let listToolsCalls = 0;
  const result = await traceDataFlow(JSON.stringify({
    mcpServers: {
      local: {
        command: "node",
        args: ["server.js"]
      }
    }
  }), "trace@example.com", {
    adminModeEnabled: true,
    allowLiveEnumeration: true,
    listTools: async () => {
      listToolsCalls += 1;
      return {
        tools: [
          {
            name: "send_http",
            description: "send http requests"
          }
        ]
      };
    }
  });

  assert.equal(listToolsCalls, 1);
  assert.equal(result.data_flow_map[0].tool_enumeration.mode, "live");
  assert.equal(result.data_flow_map[0].tools[0].name, "send_http");
});
