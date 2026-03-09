# CODEX Review: `mcp-server-agent-security`

## Scope

Reviewed source and tests in:

- `index.js`
- `cli.js`
- `lib/config-analyzer.js`
- `lib/dataflow-tracer.js`
- `lib/findings.js`
- `lib/injection-tester.js`
- `lib/package-scanner.js`
- `lib/report-generator.js`
- `lib/server-prober.js`
- `lib/store.js`
- `mcp/index.js`
- `mcp/server.json`
- `test/*.test.js`

Validation performed:

- `npm test` on 2026-03-09: 21/21 tests passed.
- `npm pack --dry-run --json`: confirmed the published package includes `cli.js`, `lib/*`, `mcp/*`, `README.md`, `LICENSE`, and `package.json`, and does **not** publish `test/*` or the local SQLite artifacts.

## Executive Summary

This repo has some solid defensive building blocks:

- The HTTP API is loopback-only by default and refuses non-loopback binding without an API key (`index.js:71-85`, `index.js:299-309`).
- The package scanner uses `execFile` rather than a shell, normalizes npm package specifiers, and validates tarball paths before extraction (`lib/package-scanner.js:57-107`, `lib/package-scanner.js:109-132`, `lib/package-scanner.js:182-222`).
- SQLite usage is parameterized (`lib/store.js:99-105`, `lib/store.js:139-153`).
- MCP stdio transport is the safest transport choice for a local admin tool, and runtime MCP errors are returned with `isError: true` rather than leaking stacks (`mcp/index.js:235-260`).

The biggest problems are not classic shell-injection bugs inside the codebase; they are **design-level safety issues and correctness gaps in the audit engine itself**:

1. `audit_mcp_server` is effectively an admin-only local process launcher plus active fuzzer, but it is exposed as a normal MCP tool and HTTP endpoint.
2. The prober stores raw output samples and secret-looking disclosure samples in audit results, which are then persisted to SQLite and returned via API/MCP.
3. The prober incorrectly treats MCP `isError` tool responses as successful calls, which materially breaks the findings logic.
4. `scanPackage` inherits ambient npm auth/registry configuration, which can leak credentials or send requests to internal/custom registries.
5. The prompt-injection and dataflow modules are useful heuristics, but they are easy to game and should not be treated as high-confidence security gates.

## Strengths / What Looks Good

- **No obvious command-injection bug in package scanning.** `scanPackage()` uses `execFile`, not `exec`, and `normalizePackageSpecifier()` rejects paths, URLs, Git specs, whitespace, and version ranges (`lib/package-scanner.js:57-107`).
- **Tarball path traversal defenses are good.** The scanner validates tar metadata before extraction and rejects absolute paths, backslashes, `../`, symlinks, and non-file/non-directory archive entries (`lib/package-scanner.js:161-222`).
- **The HTTP API has a sane default trust boundary.** Loopback-only access without an API key is the right default for a tool that can spawn local processes (`index.js:71-85`, `index.js:299-309`).
- **The MCP server returns structured tool schemas and surfaces errors as MCP errors.** That part is directionally correct (`mcp/index.js:8-112`, `mcp/index.js:231-260`).
- **Findings normalization/deduping is clean and deterministic enough for reporting.** `lib/findings.js` is one of the stronger modules in the repo.

## Findings

### 1. Critical: `audit_mcp_server` is an admin-only local code-execution surface with side-effectful active probing

**Evidence**

- The HTTP API accepts arbitrary `command` + `args` and forwards them to `probeServer()` (`index.js:218-243`).
- The MCP tool `audit_mcp_server` does the same (`mcp/index.js:178-185`).
- `probeServer()` then actively invokes **every** discovered tool with six probe payloads and an 8-request rate-limit burst (`lib/server-prober.js:8-44`, `lib/server-prober.js:525-579`).
- Arguments are auto-filled from the tool schema rather than constrained to read-only/dry-run shapes (`lib/server-prober.js:217-277`).

**Why this matters**

This is not a hidden injection bug; it is a **dangerous capability exposed as a normal tool**. A connected MCP client or HTTP caller can make the package spawn arbitrary local executables, then make the resulting server execute synthetic payloads against every tool it exposes. For destructive tools, that can mean real writes, deletions, network sends, database mutations, or shell execution.

This is especially risky because the package is a public npm package that can be attached to a general-purpose AI agent. In that deployment model, `audit_mcp_server` becomes a privilege-escalation surface unless it is treated as an explicitly admin-only capability.

**Recommendation**

- Disable `audit_mcp_server` by default in the MCP server unless an explicit admin-mode flag is set.
- Add a command allowlist or explicit wrapper model instead of arbitrary `command` execution.
- Split probing into `passive inventory` and `active probes`, with active probes behind a separate opt-in flag.
- Skip or require per-tool confirmation for tools classified as `high`/`critical` risk.

### 2. High: The prober persists raw tool output and disclosure samples, which can store leaked secrets in reports/SQLite

**Evidence**

- `detectInfoDisclosure()` captures matched strings such as bearer tokens, AWS keys, OpenAI-style keys, filesystem paths, and stack traces, and keeps up to three raw samples (`lib/server-prober.js:304-319`).
- Those samples are copied directly into finding metadata as `disclosures` (`lib/server-prober.js:543-555`).
- Probe output is also stored as `outputSample` on each tool probe (`lib/server-prober.js:559-565`).
- `executeAuditJob()` preserves these extra fields and stores them in the final report (`index.js:107-122`).
- `store.js` serializes the full findings payload to SQLite (`lib/store.js:43-63`, `lib/store.js:139-153`).

**Why this matters**

If the target server leaks a real secret during probing, this tool currently **amplifies the leak** by storing that value in audit artifacts and returning it to callers. That defeats the purpose of a security audit tool: it turns transient target leakage into persistent local secret retention.

**Recommendation**

- Redact all secret-like matches before storing them.
- Store only categories, counts, hashes, or a masked preview such as `AKIA****WXYZ`.
- Remove or heavily redact `outputSample` by default.
- Treat the SQLite store as sensitive state and document retention/deletion behavior.

### 3. High: `server-prober` treats MCP `isError` responses as successful tool calls

**Evidence**

- `safeCallTool()` marks a call as `ok: true` whenever `client.callTool()` resolves; it never checks `response.isError` (`lib/server-prober.js:322-339`).
- The repo’s own MCP server returns validation/runtime failures as resolved responses with `isError: true` (`mcp/index.js:248-259`).
- Downstream logic uses `result.ok` for validation findings and rate-limit conclusions (`lib/server-prober.js:409-437`, `lib/server-prober.js:482-499`).

**Why this matters**

This is a real correctness bug, not just a heuristic issue. A tool that correctly rejects malformed input with `isError: true` is currently treated as if it successfully processed the input. That can create:

- false positives like “accepted null-like inputs” or “processed a 100KB payload,” and
- false rate-limit conclusions because error responses are counted as successes.

**Recommendation**

- In `safeCallTool()`, treat `response.isError === true` as `ok: false`.
- Preserve both the transport result and an application-level success bit.
- Add tests that simulate MCP error responses and verify the null-input, oversized-input, and rate-limit logic.

### 4. High: `scanPackage()` inherits ambient npm registry/auth configuration, which can cause SSRF-ish behavior or credential leakage

**Evidence**

- `runCommand()` defaults to `env: process.env` unless overridden (`lib/package-scanner.js:109-116`).
- `scanPackage()` runs `npm view`, `npm install --package-lock-only`, `npm audit`, and `npm pack` on user-controlled package names (`lib/package-scanner.js:373-427`).

**Why this matters**

The code correctly blocks URL/path/Git package specs, so there is **not** an obvious command-injection bug here. The bigger issue is that npm still runs with ambient environment and config. That means the package scan can inherit:

- `NPM_CONFIG_REGISTRY` / `npm_config_registry`
- auth tokens such as `NODE_AUTH_TOKEN`
- `HOME` / user-level `.npmrc`
- proxy settings pointing to internal infrastructure

In practice, scanning an arbitrary package name can therefore send requests to a private/internal registry, use credentials the operator did not intend to expose to this workflow, or hit infrastructure behind corporate proxies.

**Recommendation**

- Run npm with a scrubbed environment.
- Pin the registry explicitly unless the operator opts into a different allowlisted registry.
- Point `HOME`/`npm_config_userconfig` to a temporary empty directory for scanning.
- Document that package scanning is networked and should run in an egress-restricted sandbox.

### 5. Medium: Exploit-detection heuristics in `server-prober` can produce critical false positives

**Evidence**

- Path traversal is flagged if the response text contains `etc/passwd`, `root:...:0:0`, or `system32` (`lib/server-prober.js:443-452`).
- The path traversal payload itself is `../../etc/passwd` (`lib/server-prober.js:28-32`).
- Shell and SQL probes similarly rely on fragile regexes over response text (`lib/server-prober.js:455-476`).

**Why this matters**

A safe tool that simply echoes the rejected input back in an error message can be reported as critically vulnerable. For example, an error like `invalid path ../../etc/passwd` matches `etc/passwd` and triggers a critical traversal finding without any actual file read.

The shell and SQL detectors have the same problem: they are detecting **strings associated with exploitation**, not confirmed exploitation.

**Recommendation**

- Do not treat echoed probe payloads as exploit evidence.
- Require stronger indicators such as non-echoed file content, successful command output with a plausible execution marker, or structured success responses.
- Lower confidence/severity unless the tool behavior clearly shows exploitation rather than rejection.

### 6. Medium: `traceDataFlow()` is capability inference, not real tagged-data tracing

**Evidence**

- `testPii` is only used to derive a hashed marker in `createTraceMarker()` (`lib/dataflow-tracer.js:66-70`).
- The tracer never injects the PII or marker into any tool call or observes it leaving the system (`lib/dataflow-tracer.js:72-167`).

**Why this matters**

The module is honest enough to label itself `capability_based_dataflow_trace`, but it is still easy for consumers to over-read the results. This is not end-to-end tracing; it is risk inference from tool names, descriptions, package names, and transport.

That produces meaningful blind spots:

- Remote `url`-only servers are only weakly modeled when live tool enumeration is unavailable.
- A dangerous tool with a bland name/description may be missed.
- A benign tool with a suggestive name may be overstated.

**Recommendation**

- Either rename/reposition this as “capability inference” everywhere, or add a true canary mode that injects tagged values and observes propagation.
- Add URL-transport enumeration support where possible.
- Consider using input schemas as another signal when tool names/descriptions are weak.

### 7. Medium: `config-analyzer` has substantial heuristic false-positive / false-negative risk

**Evidence**

- `extractPackageNames()` is permissive enough to treat many arbitrary args as package names (`lib/config-analyzer.js:78-120`).
- Filesystem “dangerous root” detection treats any path ending in `/` as suspicious (`lib/config-analyzer.js:168-170`, `lib/config-analyzer.js:185-194`), which can flag safe project-scoped directories.
- Database safety is inferred from the presence of `readonly`, `read-only`, or `ro` in command/env text (`lib/config-analyzer.js:204-215`).
- Any env var whose name looks sensitive is reported, regardless of whether forwarding that env var is expected/necessary (`lib/config-analyzer.js:277-305`).

**Why this matters**

This module is useful as a linter, but its output should not be treated as authoritative. It will likely:

- overstate risk for normal filesystem/database servers,
- miss non-obvious risky capabilities hidden behind neutral names, and
- conflate “secret is present” with “secret is improperly exposed.”

**Recommendation**

- Tighten package extraction to known launcher patterns instead of arbitrary arg guessing.
- Replace the trailing-slash root heuristic with canonical path-scope analysis.
- Differentiate “secret forwarded” from “secret likely over-scoped.”
- Use lower default confidence on capability inferences unless corroborated by multiple signals.

### 8. Medium: The 36 prompt-injection payloads are a solid baseline, but they are not comprehensive and the scoring is easy to game

**Evidence**

- The repo contains 36 payloads across six categories (`lib/injection-tester.js:51-268`).
- Detection is based on regex presence/absence of nine prompt controls (`lib/injection-tester.js:3-49`, `lib/injection-tester.js:270-279`).
- A payload is considered blocked largely if the expected control phrases are present (`lib/injection-tester.js:292-308`, `lib/injection-tester.js:327-394`).

**Assessment**

The current corpus is a good seed set for:

- direct overrides,
- retrieved-content hijacking,
- role-play/mode-switch escapes,
- delimiter/markup attacks,
- simple encoded payloads, and
- a small multilingual set.

However, it is missing important attack classes that matter in 2026-era agent stacks:

- second-order / cross-tool injection (tool A writes malicious content, tool B later reads it)
- tool metadata/schema poisoning (malicious tool names, descriptions, or schema field descriptions)
- memory poisoning / long-lived note or retrieval-store poisoning
- approval laundering (`the user/developer already approved this` across turns or tool results)
- Unicode obfuscation beyond simple encoding: zero-width chars, homoglyphs, mixed-script text, typoglycemia
- layered/nested encodings and format transforms (encoded JSON inside markdown inside HTML, etc.)
- non-Latin language coverage beyond the current small Latin-script sample set
- reasoning/policy extraction via translation/summarization rather than direct “reveal your prompt” requests

**Why this matters**

The module is mostly scoring prompt wording, not resistance behavior. A system prompt can score well by stuffing the right phrases while still being easy to jailbreak in practice.

**Recommendation**

- Keep the 36 payloads public as a baseline corpus, but add a separate private holdout corpus for CI/security gates.
- Expand coverage to the missing attack classes above.
- Consider separating “prompt policy quality” from “behavioral resistance score.”
- Document clearly that the score is heuristic, not a certification.

### 9. Medium: Default SQLite storage location is poor for a public npm package

**Evidence**

- The default DB path is the package root: `path.join(__dirname, "..", "state.sqlite")` (`lib/store.js:13-15`).

**Why this matters**

For a published npm package, writing state next to installed code is brittle and potentially unsafe:

- global or system installs may be read-only,
- multiple users/processes may share the same package directory,
- audit data lives alongside executable package contents,
- local filesystem permissions/umask determine who can read those reports.

Combined with Finding #2, this becomes more serious because stored reports may contain sensitive probe output.

**Recommendation**

- Default to an OS-appropriate per-user state directory.
- Create the directory with restrictive permissions.
- Document retention and provide a supported “purge state” command.

### 10. Medium: Test coverage misses the highest-risk surfaces

**Evidence**

- There are tests for `config-analyzer`, `dataflow-tracer`, `findings`, `injection-tester`, `package-scanner`, `report-generator`, and `store`, but none for `lib/server-prober.js`, `index.js`, `cli.js`, or `mcp/index.js`.

**Why this matters**

The most security-sensitive modules are exactly the ones without direct coverage:

- active probing behavior,
- HTTP auth/binding behavior,
- MCP tool handler correctness,
- secret redaction / storage behavior,
- `isError` handling,
- destructive-side-effect controls.

**Recommendation**

- Add focused tests for `server-prober` with mocked MCP clients.
- Add request-level tests for `index.js` auth and endpoint validation.
- Add MCP handler tests for `mcp/index.js`, especially `isError` flows.
- Add regression tests that ensure secrets are redacted before persistence.

## False Positive / False Negative Hotspots by Module

### `lib/config-analyzer.js`

- **False positives:** filesystem servers without path args, DB servers whose read-only guarantees live outside command text, expected env secret forwarding.
- **False negatives:** risky capabilities hidden behind neutral names, auth handled through non-standard headers or external transport controls.

### `lib/dataflow-tracer.js`

- **False positives:** capability regexes fire on suggestive tool names/descriptions.
- **False negatives:** dangerous tools with bland naming, remote/url-based servers not live-enumerated, actual exfil paths not tested.

### `lib/injection-tester.js`

- **False positives:** strong prompts that use different phrasing than the regex catalog.
- **False negatives:** prompts that mention the expected phrases but still contain loopholes or contradictory instructions.

### `lib/package-scanner.js`

- **False positives:** regex scans can match comments, docs, or examples in source files.
- **False negatives:** misses non-JS dangerous behavior, dynamic imports, indirect eval/shell libs, or files over 1 MB.

### `lib/server-prober.js`

- **False positives:** exploit detectors match echoed payloads or sanitized error strings.
- **False negatives:** schema generation chooses only the first `oneOf`/`anyOf` branch, `isError` is mishandled, and tool behavior may differ from tool text/schema assumptions.

## MCP Server Correctness Notes

### What is correct

- Runtime `listTools`/`callTool` handlers are registered and return standard text content (`mcp/index.js:231-264`).
- Errors are surfaced as MCP tool errors with `isError: true` (`mcp/index.js:248-259`).
- Using stdio transport is the right default for a local high-trust tool.

### What needs work

- Tool schemas are valid but too permissive for dangerous operations; there are no max lengths, allowlists, or “active probe” opt-ins (`mcp/index.js:8-112`).
- `audit_mcp_server` should not be treated like a normal end-user tool in a shared agent environment.
- The static `mcp/server.json` is descriptive but omits input schemas, so it should not be relied on as the authoritative contract (`mcp/server.json:1-35`).
- The runtime MCP server is better than the prober client here; the client-side logic is what misinterprets `isError`.

## What Should and Should Not Be Public in the npm Package

### Fine to keep public

- `lib/findings.js` normalization/CWE mapping/reporting logic.
- `lib/config-analyzer.js` and `lib/package-scanner.js` heuristics.
- The baseline 36 prompt-injection payloads in `lib/injection-tester.js`.
- The report scoring logic in `lib/report-generator.js`, **as long as it is documented as heuristic**.

### Should not be public or should be redacted/admin-only

- **Raw probe outputs and disclosure samples** from `lib/server-prober.js` findings/results.
- **SQLite audit contents** and any generated reports containing sensitive target data.
- **`audit_mcp_server` access for general-purpose or user-facing agents**; this should be an explicitly admin-only capability.
- Any future private/holdout payload corpus you use for policy gates; publishing only the visible 36-payload set encourages “teach to the test.”

### My view on the examples in the prompt

- **Full payload list:** okay to publish.
- **Internal scoring formula:** okay to publish if you are transparent that it is heuristic; not okay to market as a security boundary.
- **Raw captured probe artifacts:** not okay to expose/persist without redaction.

## Bottom Line

I would describe this repo as **a promising admin-side audit toolkit with solid low-level defenses in the package scanner, but with major safety and correctness issues in the active prober and in how audit artifacts are stored**.

If I were prioritizing fixes, I would do them in this order:

1. Redact/remove raw probe output and secret samples before persistence.
2. Fix `isError` handling in `server-prober`.
3. Put `audit_mcp_server` behind explicit admin-only and active-probe gates.
4. Sandbox/scrub npm environment for `scanPackage()`.
5. Tighten the prober heuristics to reduce false criticals.
6. Reposition `traceDataFlow()` and `testPromptInjection()` as heuristic assessments, not strong proof.
