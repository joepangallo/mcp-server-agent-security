# mcp-server-agent-security — AI Agent & MCP Security Auditor

## Product Vision
The first MCP server that audits other MCP servers and AI agent systems for security vulnerabilities. Targets the gap between traditional web security tools (which scan HTTP endpoints) and the new attack surface created by autonomous AI agents with tool access.

## Target Market
- Companies deploying AI agents internally (the consulting leads we're targeting)
- MCP server developers who need to verify their tools are safe before publishing
- Enterprises evaluating third-party MCP servers before adding to their agent stack

## What It Audits

### 1. MCP Server Security (connect to a running MCP server via stdio/SSE)
- **Tool Permission Audit**: What can each tool do? File read/write, network access, shell execution, database queries
- **Input Validation**: Send malformed/adversarial inputs to each tool — do they sanitize properly?
- **Auth & Access Control**: Does the server require authentication? Are there privilege escalation paths?
- **Information Disclosure**: Do error messages leak internal paths, credentials, or system info?
- **Resource Limits**: Can a tool be called in a loop to exhaust memory/CPU/disk? Rate limiting?

### 2. Prompt Injection Resistance (test an agent's system prompt + tool pipeline)
- **Direct Injection**: Craft inputs that attempt to override system prompts
- **Indirect Injection**: Inject via tool results (e.g., a web page containing injection payloads)
- **Tool-Mediated Injection**: Use one tool's output to manipulate another tool's behavior
- **Exfiltration Probes**: Can the agent be tricked into sending data to external URLs?

### 3. Tool Call Authorization
- **Scope Creep Detection**: Can the agent access tools/resources outside its declared scope?
- **Chain-of-Tool Exploits**: Can combining tools in sequence achieve unauthorized actions?
- **Consent Bypass**: Can tools that should require human approval be triggered without it?

### 4. Data Flow Analysis
- **PII Exposure**: Track where user data flows through the tool pipeline
- **Secret Leakage**: Check if API keys, tokens, or credentials appear in tool inputs/outputs
- **Exfiltration Paths**: Map all outbound data channels (HTTP, file write, database, etc.)

### 5. MCP Config Analysis (static analysis of MCP config JSON)
- **Overprivileged Tools**: Tools with broader access than their description suggests
- **Missing Transport Security**: stdio vs SSE, auth tokens, TLS
- **Known Vulnerable Packages**: Check MCP server dependencies against CVE databases
- **Dangerous Tool Patterns**: Shell execution, arbitrary file access, raw SQL

## MCP Tools to Expose

### `audit_mcp_config`
- Input: `{ config: string }` — raw MCP config JSON (from claude_desktop_config.json or similar)
- Static analysis only, no connections made
- Returns: risk score, findings per server, overprivileged tools, missing security controls

### `audit_mcp_server`
- Input: `{ command: string, args?: string[], env?: object }` — how to launch the MCP server
- Connects via stdio, enumerates tools, runs active security probes against each tool
- Returns: tool inventory with risk ratings, input validation results, information disclosure findings

### `audit_prompt_injection`
- Input: `{ system_prompt: string, tools: string[], model?: string }`
- Tests prompt injection resistance with a battery of known attack patterns
- Returns: injection success rate, vulnerable patterns, recommended mitigations

### `audit_agent_dataflow`
- Input: `{ mcp_config: string, test_pii?: string }` — traces PII through the agent's tool pipeline
- Sends tagged test data and monitors where it appears
- Returns: data flow map, exfiltration risks, PII exposure points

### `scan_mcp_package`
- Input: `{ package_name: string }` — npm package name of an MCP server
- Downloads, inspects source, checks dependencies against CVE database
- Returns: dependency vulnerabilities, dangerous code patterns, permission analysis

### `generate_report`
- Input: `{ audit_ids: string[] }` — combine multiple audit results
- Returns: executive summary, risk score (0-100), grade (A-F), prioritized remediation

## Report Format
Follow existing agent-audit pattern:
- Score: 0-100
- Grade: A+ through F (13-tier)
- Findings array with: source, id, severity, confidence, description, CWE, CVSS, remediation
- findingsSummary with counts by severity

## Tech Stack
- Node.js + Express (HTTP API) + MCP SDK (stdio server)
- SQLite for audit persistence (same pattern as agent-audit)
- @modelcontextprotocol/sdk for connecting to target MCP servers as a client
- No external dependencies for scanning (built-in probes)

## Architecture
```
┌─────────────────────────────┐
│  mcp-server-agent-security  │
│  (MCP Server — 6 tools)     │
└────────────┬────────────────┘
             │ stdio/SSE
┌────────────▼────────────────┐
│  HTTP API (Express)         │
│  POST /audit/config         │
│  POST /audit/server         │
│  POST /audit/injection      │
│  POST /audit/dataflow       │
│  POST /audit/package        │
│  GET  /report/:id           │
│  GET  /health               │
└────────────┬────────────────┘
             │
┌────────────▼────────────────┐
│  Audit Engine               │
│  ├── config-analyzer.js     │
│  ├── server-prober.js       │
│  ├── injection-tester.js    │
│  ├── dataflow-tracer.js     │
│  ├── package-scanner.js     │
│  └── report-generator.js    │
└────────────┬────────────────┘
             │
┌────────────▼────────────────┐
│  SQLite (state.sqlite)      │
│  jobs, findings, reports    │
└─────────────────────────────┘
```

## Port: 3091
