const crypto = require("crypto");
const { createFinding, dedupeFindings } = require("./findings");
const { parseConfig, getServerEntries, extractPackageNames, extractTransport } = require("./config-analyzer");
const { listServerTools } = require("./server-prober");
const {
  MCP_COMMAND_ALLOWLIST,
  isAdminModeEnabled,
  isCommandAllowed
} = require("./runtime-policy");

let uuidv4 = () => crypto.randomUUID();
try {
  uuidv4 = require("uuid").v4;
} catch (error) {
  uuidv4 = () => crypto.randomUUID();
}

function classifyCapability(name, description, packageNames) {
  const corpus = [name || "", description || "", ...(packageNames || [])].join(" ").toLowerCase();
  const capabilities = [];

  if (/(fetch|request|http|https|webhook|post|send|email|slack|discord|upload|browser|web)/.test(corpus)) {
    capabilities.push("network-egress");
  }
  if (/(write|append|save|delete|create|filesystem|file|download)/.test(corpus)) {
    capabilities.push("file-write");
  }
  if (/(read|list|search|get|fetch|open|query|select|retrieve|filesystem|file|browser)/.test(corpus)) {
    capabilities.push("data-ingress");
  }
  if (/(sql|database|postgres|mysql|sqlite|mongo|insert|update|delete)/.test(corpus)) {
    capabilities.push("database");
  }
  if (/(shell|exec|command|terminal|bash|powershell|spawn)/.test(corpus)) {
    capabilities.push("shell-exec");
  }

  return Array.from(new Set(capabilities));
}

function buildExposureFinding(serverName, toolName, capability, transport) {
  const severity = capability === "shell-exec" ? "high" : capability === "network-egress" ? "high" : "medium";
  const description = capability === "network-egress"
    ? `Tool "${toolName}" on server "${serverName}" can transmit data off-host.`
    : capability === "file-write"
      ? `Tool "${toolName}" on server "${serverName}" can persist user data to the filesystem.`
      : capability === "database"
        ? `Tool "${toolName}" on server "${serverName}" can store or query data in a database context.`
        : `Tool "${toolName}" on server "${serverName}" can execute shell or process-level actions.`;

  return createFinding({
    source: "dataflow-tracer",
    severity,
    confidence: "medium",
    cwe: capability === "network-egress" ? "data_exfiltration" : capability === "shell-exec" ? "shell_injection" : "secret_leakage",
    location: `${serverName}:${toolName}`,
    description,
    remediation: capability === "network-egress"
      ? "Restrict outbound destinations and require approval before transmitting tagged or sensitive data."
      : capability === "file-write"
        ? "Constrain write paths and scrub tagged data before persisting it."
        : capability === "database"
          ? "Use read-only database roles where possible and classify tables that can contain PII."
          : "Require explicit approval and sandbox shell-capable tooling.",
    metadata: {
      transport
    }
  });
}

function createTraceMarker(testPii) {
  const markerSeed = typeof testPii === "string" && testPii ? testPii : "PII";
  const digest = crypto.createHash("sha256").update(markerSeed).digest("hex").slice(0, 12);
  return `PII::TRACE::${digest}::${uuidv4()}`;
}

function normalizeTraceOptions(options) {
  const normalized = options && typeof options === "object" ? options : {};
  const adminModeEnabled = normalized.adminModeEnabled === undefined ? isAdminModeEnabled() : Boolean(normalized.adminModeEnabled);
  const allowLiveEnumeration = normalized.allowLiveEnumeration === undefined ? adminModeEnabled : Boolean(normalized.allowLiveEnumeration);

  return {
    adminModeEnabled,
    allowLiveEnumeration,
    commandAllowlist: normalized.commandAllowlist instanceof Set ? normalized.commandAllowlist : MCP_COMMAND_ALLOWLIST,
    listTools: typeof normalized.listTools === "function" ? normalized.listTools : listServerTools
  };
}

function shouldLiveEnumerateServer(server, options) {
  return Boolean(
    server &&
    typeof server.command === "string" &&
    options.allowLiveEnumeration &&
    options.adminModeEnabled &&
    isCommandAllowed(server.command, options.commandAllowlist)
  );
}

async function traceDataFlow(mcpConfig, testPii, options) {
  const findings = [];
  const piiExposurePoints = [];
  const exfiltrationRisks = [];
  const dataFlowMap = [];
  const traceMarker = createTraceMarker(testPii);
  const traceOptions = normalizeTraceOptions(options);
  const parsedConfig = parseConfig(mcpConfig);
  const servers = getServerEntries(parsedConfig);

  for (const [serverName, server] of servers) {
    const packageNames = extractPackageNames(server);
    const transport = extractTransport(server);
    let tools = [];
    let toolEnumeration = {
      mode: "static",
      attempted: false,
      reason: server && server.command ? "live_enumeration_disabled" : "no_local_command"
    };

    try {
      if (shouldLiveEnumerateServer(server, traceOptions)) {
        const listed = await traceOptions.listTools({
          command: server.command,
          args: Array.isArray(server.args) ? server.args : [],
          env: server.env
        });
        tools = listed.tools;
        toolEnumeration = {
          mode: "live",
          attempted: true,
          reason: null
        };
      } else if (server && server.command && !isCommandAllowed(server.command, traceOptions.commandAllowlist)) {
        toolEnumeration = {
          mode: "static",
          attempted: false,
          reason: "command_not_allowlisted"
        };
      }
    } catch (error) {
      toolEnumeration = {
        mode: "static",
        attempted: true,
        reason: "live_enumeration_failed"
      };
      findings.push(createFinding({
        source: "dataflow-tracer",
        severity: "medium",
        confidence: "medium",
        cwe: "info_disclosure",
        location: serverName,
        description: `Could not live-enumerate tools for "${serverName}" during data flow analysis.`,
        remediation: "Verify the MCP server launch command and rerun the data-flow audit to obtain tool-level visibility."
      }));
    }

    const observedTools = tools.length ? tools : [
      {
        name: serverName,
        description: `Inferred from packages: ${packageNames.join(", ") || String(server.command || "unknown")}`
      }
    ];

    const mappedTools = observedTools.map((tool) => {
      const capabilities = classifyCapability(tool.name, tool.description, packageNames);
      for (const capability of capabilities) {
        const exposure = {
          server: serverName,
          tool: tool.name,
          capability,
          trace_marker: traceMarker
        };

        piiExposurePoints.push(exposure);

        if (["network-egress", "file-write", "database", "shell-exec"].includes(capability)) {
          exfiltrationRisks.push(exposure);
          findings.push(buildExposureFinding(serverName, tool.name, capability, transport));
        }
      }

      return {
        name: tool.name,
        description: tool.description || "",
        capabilities
      };
    });

    if ((transport === "http" || transport === "ws") && exfiltrationRisks.some((risk) => risk.server === serverName)) {
      findings.push(createFinding({
        source: "dataflow-tracer",
        severity: "high",
        confidence: "medium",
        cwe: "insecure_transport",
        location: serverName,
        description: `Server "${serverName}" exposes data-moving capabilities over cleartext transport (${transport}).`,
        remediation: "Require TLS for remote MCP transport before allowing PII-bearing tool paths."
      }));
    }

    dataFlowMap.push({
      server: serverName,
      transport,
      packages: packageNames,
      tool_enumeration: toolEnumeration,
      trace_marker: traceMarker,
      tools: mappedTools
    });
  }

  return {
    trace_marker: traceMarker,
    analysis_mode: "capability_based_dataflow_trace",
    data_flow_map: dataFlowMap,
    exfiltration_risks: exfiltrationRisks,
    pii_exposure_points: piiExposurePoints,
    findings: dedupeFindings(findings)
  };
}

module.exports = {
  traceDataFlow,
  testOnly: {
    shouldLiveEnumerateServer
  }
};
