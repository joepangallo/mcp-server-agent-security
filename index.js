const crypto = require("crypto");
const express = require("express");
const store = require("./lib/store");
const { analyzeConfig, parseConfig, getServerEntries } = require("./lib/config-analyzer");
const { probeServer } = require("./lib/server-prober");
const { testPromptInjection } = require("./lib/injection-tester");
const { traceDataFlow } = require("./lib/dataflow-tracer");
const { scanPackage } = require("./lib/package-scanner");
const { generateReport } = require("./lib/report-generator");
const { createFinding } = require("./lib/findings");

const PORT = Number.parseInt(process.env.AGENT_SECURITY_PORT || "", 10) || 3091;
const HOST = process.env.AGENT_SECURITY_HOST || "127.0.0.1";
const API_KEY = process.env.AGENT_SECURITY_API_KEY || "";
const ACTIVE_SERVER_PROBING_DISABLED_MESSAGE = "Active server probing is disabled unless AGENT_SECURITY_ADMIN_MODE=1.";

const COMMAND_ALLOWLIST = new Set(["node", "python3", "python", "npx", "uvx", "deno", "bun"]);
const NPX_ALLOWED_FLAGS = new Set(["-y", "--yes"]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RESERVED_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const RESERVED_RUNTIME_ENV_KEYS = new Set([
  "PATH",
  "PATHEXT",
  "HOME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
  "NODE_OPTIONS",
  "NODE_PATH",
  "PYTHONHOME",
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "RUBYOPT",
  "RUBYLIB",
  "PERL5OPT",
  "PERL5LIB",
  "JAVA_TOOL_OPTIONS",
  "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS",
  "CLASSPATH",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  "BUNDLE_GEMFILE",
  "BUNDLE_PATH",
  "GEM_HOME",
  "GEM_PATH",
  "NPM_CONFIG_PREFIX",
  "NPM_CONFIG_GLOBALCONFIG",
  "NPM_CONFIG_USERCONFIG",
  "NPM_CONFIG_CACHE"
]);
const INTERNAL_AUDIT_ACCESS_FIELD = "_access";

const RATE_WINDOW_MS = Number.parseInt(process.env.AGENT_SECURITY_RATE_WINDOW_MS || "", 10) || 60_000;
const MAX_PROTECTED_REQUESTS_PER_WINDOW = Number.parseInt(process.env.AGENT_SECURITY_RATE_LIMIT || "", 10) || 30;
const MAX_HEALTH_REQUESTS_PER_WINDOW = Number.parseInt(process.env.AGENT_SECURITY_HEALTH_RATE_LIMIT || "", 10) || 60;
const MAX_CONCURRENT_AUDITS = Number.parseInt(process.env.AGENT_SECURITY_MAX_CONCURRENT_AUDITS || "", 10) || 2;
const MAX_CONCURRENT_AUDITS_PER_CALLER = Number.parseInt(process.env.AGENT_SECURITY_MAX_CONCURRENT_AUDITS_PER_CALLER || "", 10) || 1;
const MAX_AUDIT_MS = Number.parseInt(process.env.AGENT_SECURITY_AUDIT_TIMEOUT_MS || "", 10) || 120_000;

const MAX_COMMAND_LENGTH = 32;
const MAX_ARGS = 32;
const MAX_ARG_LENGTH = 1024;
const MAX_ENV_KEYS = 32;
const MAX_ENV_VALUE_LENGTH = 4096;
const MAX_JSON_INPUT_CHARS = 1_000_000;
const MAX_SYSTEM_PROMPT_CHARS = 200_000;
const MAX_TOOLS = 64;
const MAX_TOOL_LENGTH = 256;
const MAX_PACKAGE_NAME_LENGTH = 214;
const MAX_TEST_PII_LENGTH = 2048;
const MAX_SERVERS_PER_CONFIG = 25;

const requestWindows = new Map();
let activeAuditCount = 0;
const activeAuditCountsByCaller = new Map();

const DANGEROUS_ENV_PATTERNS = [
  /^NODE_OPTIONS$/i,
  /^NODE_PATH$/i,
  /^PYTHON(?:PATH|HOME|STARTUP)$/i,
  /^RUBYOPT$/i,
  /^BUNDLE_.+$/i,
  /^GEM_.+$/i,
  /^LD_(?:PRELOAD|LIBRARY_PATH)$/i,
  /^DYLD_.+$/i,
  /^BASH_ENV$/i,
  /^ENV$/i,
  /^SHELLOPTS$/i,
  /^PS4$/i,
  /^(?:npm_config_|NPM_CONFIG_)/,
  /^(?:HTTP|HTTPS|ALL|NO)_PROXY$/i,
  /^SSLKEYLOGFILE$/i
];

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

function getRemoteAddress(req) {
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "unknown";
}

function isLoopbackAddress(address) {
  return !address || address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function isAdminModeEnabled() {
  return process.env.AGENT_SECURITY_ADMIN_MODE === "1";
}

function hasForwardingHeaders(req) {
  return Boolean(req.get("forwarded") || req.get("x-forwarded-for") || req.get("x-real-ip"));
}

function getPresentedCredential(req) {
  const bearerHeader = req.get("authorization") || "";
  const bearerToken = bearerHeader.startsWith("Bearer ") ? bearerHeader.slice(7).trim() : "";
  return req.get("x-api-key") || bearerToken || "";
}

function hashValue(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 16);
}

function getCallerFingerprint(req) {
  const presentedCredential = getPresentedCredential(req);
  const remoteAddress = getRemoteAddress(req);

  if (presentedCredential) {
    return `key:${hashValue(presentedCredential)}:ip:${remoteAddress}`;
  }

  return `ip:${remoteAddress}`;
}

function consumeRateLimit(key, limit, windowMs) {
  const now = Date.now();
  let bucket = requestWindows.get(key);

  if (!bucket || bucket.resetAt <= now) {
    bucket = {
      count: 0,
      resetAt: now + windowMs
    };
  }

  if (bucket.count >= limit) {
    requestWindows.set(key, bucket);
    return {
      allowed: false,
      retryAfterMs: Math.max(1, bucket.resetAt - now)
    };
  }

  bucket.count += 1;
  requestWindows.set(key, bucket);

  if (requestWindows.size > 4096) {
    for (const [entryKey, entryValue] of requestWindows.entries()) {
      if (entryValue.resetAt <= now) {
        requestWindows.delete(entryKey);
      }
    }
  }

  return {
    allowed: true,
    retryAfterMs: 0
  };
}

function rateLimitMiddleware(scope, limit) {
  return (req, res, next) => {
    const key = scope === "health"
      ? `health:${getRemoteAddress(req)}`
      : scope === "protected-attempt"
        ? `protected-attempt:${getRemoteAddress(req)}`
      : `${scope}:${getCallerFingerprint(req)}`;
    const result = consumeRateLimit(key, limit, RATE_WINDOW_MS);

    if (!result.allowed) {
      res.set("retry-after", String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
      res.status(429).json({ error: "Rate limit exceeded. Please retry shortly." });
      return;
    }

    next();
  };
}

function acquireAuditSlot(callerFingerprint) {
  if (activeAuditCount >= MAX_CONCURRENT_AUDITS) {
    return {
      ok: false,
      retryAfterSeconds: 5,
      message: "Too many audit jobs are already running. Retry shortly."
    };
  }

  const callerCount = activeAuditCountsByCaller.get(callerFingerprint) || 0;
  if (callerCount >= MAX_CONCURRENT_AUDITS_PER_CALLER) {
    return {
      ok: false,
      retryAfterSeconds: 5,
      message: "This caller already has an audit job in progress. Retry shortly."
    };
  }

  activeAuditCount += 1;
  activeAuditCountsByCaller.set(callerFingerprint, callerCount + 1);

  let released = false;
  return {
    ok: true,
    release() {
      if (released) {
        return;
      }

      released = true;
      activeAuditCount = Math.max(0, activeAuditCount - 1);

      const nextCallerCount = (activeAuditCountsByCaller.get(callerFingerprint) || 1) - 1;
      if (nextCallerCount <= 0) {
        activeAuditCountsByCaller.delete(callerFingerprint);
      } else {
        activeAuditCountsByCaller.set(callerFingerprint, nextCallerCount);
      }
    }
  };
}

function sanitizeExtraFields(result) {
  const BLOCKED_KEYS = new Set([
    "id", "score", "grade", "findings", "findingsSummary", "executiveSummary",
    "generatedAt", INTERNAL_AUDIT_ACCESS_FIELD, ...RESERVED_OBJECT_KEYS,
    "outputSample", "disclosures", "rawOutput", "samples", "text", "response"
  ]);
  const seen = new WeakSet();

  function scrub(val, depth) {
    if (val === null || typeof val !== "object") {
      return val;
    }
    if (depth > 6) {
      return Array.isArray(val) ? [] : "[truncated]";
    }
    if (seen.has(val)) {
      return "[circular]";
    }

    seen.add(val);
    if (Array.isArray(val)) {
      try {
        return val.map((value) => scrub(value, depth + 1));
      } finally {
        seen.delete(val);
      }
    }

    try {
      const out = {};
      for (const [key, value] of Object.entries(val)) {
        if (!BLOCKED_KEYS.has(key)) {
          out[key] = scrub(value, depth + 1);
        }
      }
      return out;
    } finally {
      seen.delete(val);
    }
  }

  return scrub(result || {}, 0);
}

function isDangerousEnvKey(key) {
  return DANGEROUS_ENV_PATTERNS.some((pattern) => pattern.test(key));
}

function normalizeEnvKey(key) {
  return typeof key === "string" ? key.trim().toUpperCase() : "";
}

function findDisallowedRuntimeEnvKeys(envInput) {
  if (!isPlainObject(envInput)) {
    return [];
  }

  return Object.keys(envInput)
    .filter((key) => RESERVED_RUNTIME_ENV_KEYS.has(normalizeEnvKey(key)) || isDangerousEnvKey(key))
    .sort((left, right) => normalizeEnvKey(left).localeCompare(normalizeEnvKey(right)) || left.localeCompare(right));
}

function sanitizeEnvInput(envInput) {
  if (envInput === undefined) {
    return undefined;
  }

  if (!isPlainObject(envInput)) {
    return null;
  }

  const entries = Object.entries(envInput);
  if (entries.length > MAX_ENV_KEYS) {
    return null;
  }

  const env = Object.create(null);
  for (const [key, value] of entries) {
    if (RESERVED_OBJECT_KEYS.has(key) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof value !== "string") {
      return null;
    }
    if (value.length > MAX_ENV_VALUE_LENGTH || isDangerousEnvKey(key)) {
      return null;
    }
    env[key] = value;
  }

  return env;
}

function looksLikeRemoteSpecifier(value) {
  return /^(?:https?|wss?|ftp|file|git\+|ssh|data):/i.test(String(value || "").trim());
}

function isSafeLocalEntryPoint(value) {
  const input = String(value || "").trim();
  if (!input || input.length > MAX_ARG_LENGTH || input.includes("\0") || /[\r\n]/.test(input)) {
    return false;
  }
  if (input.startsWith("-") || looksLikeRemoteSpecifier(input)) {
    return false;
  }
  return /^[./A-Za-z0-9_@-][./A-Za-z0-9_@-]*$/.test(input);
}

function isSafePythonModule(value) {
  return /^(?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(String(value || "").trim());
}

function isSafeNpmPackageSpec(value) {
  if (typeof value !== "string") {
    return false;
  }

  const spec = value.trim();
  if (!spec || spec.length > MAX_PACKAGE_NAME_LENGTH) {
    return false;
  }

  if (
    spec.startsWith(".") ||
    spec.startsWith("/") ||
    spec.startsWith("~") ||
    spec.includes("\\") ||
    /\s/.test(spec) ||
    /^(?:file|git\+|git:|https?:|ssh:|github:)/i.test(spec)
  ) {
    return false;
  }

  let namePart = spec;
  let versionPart = "";
  if (spec.startsWith("@")) {
    const slashIndex = spec.indexOf("/");
    if (slashIndex <= 1) {
      return false;
    }
    const versionIndex = spec.indexOf("@", slashIndex + 1);
    if (versionIndex !== -1) {
      namePart = spec.slice(0, versionIndex);
      versionPart = spec.slice(versionIndex + 1);
    }
  } else {
    const versionIndex = spec.indexOf("@");
    if (versionIndex !== -1) {
      namePart = spec.slice(0, versionIndex);
      versionPart = spec.slice(versionIndex + 1);
    }
  }

  if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(namePart)) {
    return false;
  }

  return !versionPart || /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(versionPart);
}

function isSafePythonPackageSpec(value) {
  const spec = String(value || "").trim();
  if (!spec || spec.length > MAX_PACKAGE_NAME_LENGTH) {
    return false;
  }

  if (/\s/.test(spec) || spec.includes("/") || spec.includes("\\") || /^(?:file|git\+|git:|https?:|ssh:)/i.test(spec)) {
    return false;
  }

  return /^[A-Za-z0-9][A-Za-z0-9._-]*(?:==[A-Za-z0-9][A-Za-z0-9._-]*)?$/.test(spec);
}

function validateNodeArgs(args) {
  if (!args.length) {
    return "node audits require a local script path.";
  }

  if (String(args[0]).trim().startsWith("-")) {
    return "node audits must launch a local script and do not allow inline evaluation flags.";
  }

  if (!isSafeLocalEntryPoint(args[0])) {
    return "node entrypoints must be local script paths.";
  }

  return null;
}

function validatePythonArgs(args) {
  if (!args.length) {
    return "python audits require a local script path or `-m module`.";
  }

  const firstArg = String(args[0]).trim();
  if (firstArg === "-m") {
    if (!isSafePythonModule(args[1])) {
      return "python module launches must use a simple module name.";
    }
    return null;
  }

  if (firstArg.startsWith("-")) {
    return "python audits must launch a local script or `-m module`, not inline code.";
  }

  if (!isSafeLocalEntryPoint(firstArg)) {
    return "python entrypoints must be local script paths.";
  }

  return null;
}

function validateNpxArgs(args) {
  if (!args.length) {
    return "npx audits require an npm registry package name.";
  }

  let packageIndex = 0;
  while (packageIndex < args.length && String(args[packageIndex]).trim().startsWith("-")) {
    const flag = String(args[packageIndex]).trim();
    if (!NPX_ALLOWED_FLAGS.has(flag)) {
      return `npx flag "${flag}" is not allowed.`;
    }
    packageIndex += 1;
  }

  if (packageIndex >= args.length || !isSafeNpmPackageSpec(args[packageIndex])) {
    return "npx audits require an npm registry package name.";
  }

  return null;
}

function validateUvxArgs(args) {
  if (!args.length) {
    return "uvx audits require a PyPI package name.";
  }

  if (String(args[0]).trim().startsWith("-")) {
    return "uvx flags are not allowed.";
  }

  if (!isSafePythonPackageSpec(args[0])) {
    return "uvx audits require a safe PyPI package name.";
  }

  return null;
}

function validateDenoArgs(args) {
  if (!args.length || String(args[0]).trim() !== "run") {
    return "deno audits must use `deno run <local-script>`.";
  }

  let entryIndex = 1;
  while (entryIndex < args.length && String(args[entryIndex]).trim().startsWith("-")) {
    const flag = String(args[entryIndex]).trim().split("=")[0];
    if (/^--?(?:eval|repl)$/i.test(flag)) {
      return "deno eval/repl modes are not allowed.";
    }
    entryIndex += 1;
  }

  if (entryIndex >= args.length || !isSafeLocalEntryPoint(args[entryIndex])) {
    return "deno entrypoints must be local script paths.";
  }

  return null;
}

function validateBunArgs(args) {
  if (!args.length) {
    return "bun audits require a local script path.";
  }

  const firstArg = String(args[0]).trim();
  if (["x", "create", "install", "add", "pm", "exec", "repl", "upgrade"].includes(firstArg)) {
    return `bun subcommand "${firstArg}" is not allowed.`;
  }

  if (firstArg === "run") {
    let entryIndex = 1;
    while (entryIndex < args.length && String(args[entryIndex]).trim().startsWith("-")) {
      entryIndex += 1;
    }

    if (entryIndex >= args.length || !isSafeLocalEntryPoint(args[entryIndex])) {
      return "bun run requires a local script path.";
    }
    return null;
  }

  if (firstArg.startsWith("-") || !isSafeLocalEntryPoint(firstArg)) {
    return "bun entrypoints must be local script paths.";
  }

  return null;
}

function validateServerLaunchSpec(commandInput, argsInput, envInput) {
  if (typeof commandInput !== "string") {
    return { error: "command must be a string." };
  }

  const command = commandInput.trim();
  if (!command || command.length > MAX_COMMAND_LENGTH || /\s/.test(command)) {
    return { error: "command must be a bare executable name." };
  }

  if (!COMMAND_ALLOWLIST.has(command)) {
    return { error: "Command not allowed. Permitted: " + [...COMMAND_ALLOWLIST].join(", ") };
  }

  if (
    argsInput !== undefined && (
      !Array.isArray(argsInput) ||
      argsInput.length > MAX_ARGS ||
      argsInput.some((arg) => typeof arg !== "string" || arg.length > MAX_ARG_LENGTH || arg.includes("\0") || /[\r\n]/.test(arg))
    )
  ) {
    return { error: `args must be an array of at most ${MAX_ARGS} strings.` };
  }

  const disallowedEnvKeys = findDisallowedRuntimeEnvKeys(envInput);
  if (disallowedEnvKeys.length) {
    return { error: `env contains reserved runtime keys that cannot be overridden: ${disallowedEnvKeys.join(", ")}.` };
  }

  const args = Array.isArray(argsInput) ? argsInput : [];
  const env = sanitizeEnvInput(envInput);
  if (env === null) {
    return { error: "env must be an object of safe string key/value pairs." };
  }

  let validationError = null;
  switch (command) {
    case "node":
      validationError = validateNodeArgs(args);
      break;
    case "python":
    case "python3":
      validationError = validatePythonArgs(args);
      break;
    case "npx":
      validationError = validateNpxArgs(args);
      break;
    case "uvx":
      validationError = validateUvxArgs(args);
      break;
    case "deno":
      validationError = validateDenoArgs(args);
      break;
    case "bun":
      validationError = validateBunArgs(args);
      break;
    default:
      validationError = "Command not allowed.";
      break;
  }

  if (validationError) {
    return { error: validationError };
  }

  return {
    command,
    args,
    env
  };
}

function parseJsonInput(fieldName, value) {
  if (typeof value !== "string") {
    return { error: `${fieldName} must be a JSON string.` };
  }

  if (!value.trim()) {
    return { error: `${fieldName} must be a non-empty JSON string.` };
  }

  if (value.length > MAX_JSON_INPUT_CHARS) {
    return { error: `${fieldName} exceeds the maximum size.` };
  }

  try {
    const parsed = parseConfig(value);
    if (!parsed || typeof parsed !== "object") {
      return { error: `${fieldName} must decode to a JSON object.` };
    }
    return { parsed };
  } catch (error) {
    return { error: `${fieldName} must be valid JSON.` };
  }
}

function sanitizeConfigServerSpec(server, label) {
  if (!isPlainObject(server)) {
    return { error: `${label} must be an object.` };
  }

  const hasLaunchFields = Object.prototype.hasOwnProperty.call(server, "command") ||
    Object.prototype.hasOwnProperty.call(server, "args") ||
    Object.prototype.hasOwnProperty.call(server, "env");

  if (!hasLaunchFields) {
    return { server };
  }

  const validatedTarget = validateServerLaunchSpec(server.command, server.args, server.env);
  if (validatedTarget.error) {
    return { error: `${label}: ${validatedTarget.error}` };
  }

  return {
    server: {
      ...server,
      command: validatedTarget.command,
      args: validatedTarget.args,
      env: validatedTarget.env
    }
  };
}

function validateConfigTopology(parsedConfig, fieldName) {
  const serverEntries = getServerEntries(parsedConfig);
  if (serverEntries.length > MAX_SERVERS_PER_CONFIG) {
    return { error: `${fieldName} may define at most ${MAX_SERVERS_PER_CONFIG} servers.` };
  }

  if (isPlainObject(parsedConfig.mcpServers)) {
    for (const [serverName, server] of Object.entries(parsedConfig.mcpServers)) {
      if (RESERVED_OBJECT_KEYS.has(serverName)) {
        return { error: `${fieldName}: mcpServers.${serverName} uses a reserved server name.` };
      }
      if (!isPlainObject(server)) {
        return { error: `${fieldName}: mcpServers.${serverName} must be an object.` };
      }
    }
  }

  if (Array.isArray(parsedConfig.servers)) {
    for (let index = 0; index < parsedConfig.servers.length; index += 1) {
      const server = parsedConfig.servers[index];
      if (!isPlainObject(server)) {
        return { error: `${fieldName}: servers[${index}] must be an object.` };
      }
      if (typeof server.name === "string" && RESERVED_OBJECT_KEYS.has(server.name)) {
        return { error: `${fieldName}: servers[${index}].name uses a reserved server name.` };
      }
    }
  }

  return {
    parsed: parsedConfig,
    serverEntries
  };
}

function sanitizeConfigLaunchTargets(parsedConfig) {
  const serverEntries = getServerEntries(parsedConfig);
  if (serverEntries.length > MAX_SERVERS_PER_CONFIG) {
    return { error: `mcp_config may define at most ${MAX_SERVERS_PER_CONFIG} servers.` };
  }

  if (isPlainObject(parsedConfig.mcpServers)) {
    const normalizedServers = Object.create(null);
    for (const [serverName, server] of Object.entries(parsedConfig.mcpServers)) {
      if (RESERVED_OBJECT_KEYS.has(serverName)) {
        return { error: `mcpServers.${serverName} uses a reserved server name.` };
      }
      const normalized = sanitizeConfigServerSpec(server || {}, `mcpServers.${serverName}`);
      if (normalized.error) {
        return normalized;
      }
      normalizedServers[serverName] = normalized.server;
    }

    return {
      parsed: {
        ...parsedConfig,
        mcpServers: normalizedServers
      }
    };
  }

  if (Array.isArray(parsedConfig.servers)) {
    const normalizedServers = [];
    for (let index = 0; index < parsedConfig.servers.length; index += 1) {
      const normalized = sanitizeConfigServerSpec(parsedConfig.servers[index] || {}, `servers[${index}]`);
      if (normalized.error) {
        return normalized;
      }
      normalizedServers.push(normalized.server);
    }

    return {
      parsed: {
        ...parsedConfig,
        servers: normalizedServers
      }
    };
  }

  return { parsed: parsedConfig };
}

function configContainsCommandLaunchers(parsedConfig) {
  const serverEntries = Array.isArray(parsedConfig) ? parsedConfig : getServerEntries(parsedConfig);
  return serverEntries.some(([, server]) => isPlainObject(server) && typeof server.command === "string" && server.command.trim());
}

function sanitizeToolsInput(toolsInput) {
  if (toolsInput === undefined) {
    return [];
  }

  if (
    !Array.isArray(toolsInput) ||
    toolsInput.length > MAX_TOOLS ||
    toolsInput.some((tool) => typeof tool !== "string" || !tool.trim() || tool.length > MAX_TOOL_LENGTH)
  ) {
    return null;
  }

  return toolsInput.map((tool) => tool.trim());
}

function buildAuditAccessControl(req) {
  return {
    ownerFingerprint: getCallerFingerprint(req)
  };
}

function getAuditAccessControl(audit) {
  return isPlainObject(audit && audit[INTERNAL_AUDIT_ACCESS_FIELD])
    ? audit[INTERNAL_AUDIT_ACCESS_FIELD]
    : null;
}

function sanitizeAuditResponse(audit) {
  if (!isPlainObject(audit)) {
    return audit;
  }

  const sanitizedAudit = { ...audit };
  delete sanitizedAudit[INTERNAL_AUDIT_ACCESS_FIELD];
  return sanitizedAudit;
}

function canReadAudit(req, audit) {
  const accessControl = getAuditAccessControl(audit);
  if (!accessControl || typeof accessControl.ownerFingerprint !== "string" || !accessControl.ownerFingerprint) {
    return !API_KEY && isLoopbackAddress(getRemoteAddress(req));
  }

  return accessControl.ownerFingerprint === getCallerFingerprint(req);
}

function requireTrustedCaller(req, res, next) {
  if (API_KEY) {
    const candidateKey = getPresentedCredential(req);
    const keyLen = Buffer.byteLength(API_KEY);
    const keyBuf = Buffer.alloc(keyLen);
    const candBuf = Buffer.alloc(keyLen);
    keyBuf.write(API_KEY);
    candBuf.write(candidateKey.slice(0, keyLen));
    const validKey = candidateKey.length === API_KEY.length && crypto.timingSafeEqual(keyBuf, candBuf);
    if (!validKey) {
      res.status(401).json({ error: "Unauthorized." });
      return;
    }
  } else if (!isLoopbackAddress(req.socket && req.socket.remoteAddress) || hasForwardingHeaders(req)) {
    res.status(403).json({ error: "Audit API only accepts direct loopback clients unless AGENT_SECURITY_API_KEY is configured." });
    return;
  }

  next();
}

function withTimeout(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise.finally(() => {
      if (timer) {
        clearTimeout(timer);
      }
    }),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.ceil(timeoutMs / 1000)}s`)), timeoutMs);
      if (typeof timer.unref === "function") {
        timer.unref();
      }
    })
  ]);
}

async function executeAuditJob(type, target, runner, options = {}) {
  const accessControl = isPlainObject(options.accessControl) ? options.accessControl : null;
  const initialFindings = {
    findings: [],
    findingsSummary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    executiveSummary: "Audit is in progress.",
    generatedAt: new Date().toISOString()
  };

  if (accessControl) {
    initialFindings[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
  }

  const audit = store.createAudit({
    type,
    target,
    status: "running",
    findings: initialFindings
  });

  try {
    const result = await runner();
    const extraFields = sanitizeExtraFields(result);
    if (accessControl) {
      extraFields[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
    }
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: Array.isArray(result && result.findings) ? result.findings : [],
      extraFields
    });

    return store.updateAudit(audit.id, {
      status: "completed",
      score: report.score,
      grade: report.grade,
      findings: report
    });
  } catch (error) {
    const failureFinding = createFinding({
      source: "http-api",
      severity: "high",
      confidence: "high",
      cwe: "input_validation",
      description: `${type} audit encountered an internal error.`,
      remediation: "Repair the request payload or target environment and rerun the audit."
    });
    const extraFields = {
      error: "Audit failed. Check server logs for details."
    };
    if (accessControl) {
      extraFields[INTERNAL_AUDIT_ACCESS_FIELD] = accessControl;
    }
    const report = generateReport({
      id: audit.id,
      type,
      target,
      findings: [failureFinding],
      extraFields
    });

    return store.updateAudit(audit.id, {
      status: "failed",
      score: report.score,
      grade: report.grade,
      findings: report
    });
  }
}

async function executeManagedAudit(req, res, type, target, runner, timeoutMs) {
  const callerFingerprint = getCallerFingerprint(req);
  const accessControl = buildAuditAccessControl(req);
  const slot = acquireAuditSlot(callerFingerprint);

  if (!slot.ok) {
    res.set("retry-after", String(slot.retryAfterSeconds));
    res.status(429).json({ error: slot.message });
    return null;
  }

  const runnerPromise = Promise.resolve().then(runner);
  runnerPromise.finally(() => slot.release());

  return executeAuditJob(
    type,
    target,
    async () => withTimeout(runnerPromise, timeoutMs || MAX_AUDIT_MS, `${type} audit`),
    { accessControl }
  );
}

async function generateCombinedReport(auditIds) {
  const ids = Array.isArray(auditIds) ? auditIds.filter(Boolean) : [];

  if (!ids.length) {
    throw new Error("At least one audit ID is required.");
  }

  const audits = ids.map((id) => store.getAudit(id)).filter(Boolean);
  if (!audits.length) {
    throw new Error("No matching audits were found.");
  }

  const missingAuditIds = ids.filter((id) => !audits.find((audit) => audit.id === id));
  const report = generateReport({
    type: "report",
    target: ids.join(", "),
    auditResults: audits,
    extraFields: {
      sourceAuditIds: ids,
      missingAuditIds
    }
  });

  return store.createAudit({
    id: report.id,
    type: "report",
    target: ids.join(", "),
    status: "completed",
    score: report.score,
    grade: report.grade,
    findings: report,
    completed_at: report.generatedAt
  });
}

function asyncRoute(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal audit error. Check server logs." });
      }
    }
  };
}

function createApp() {
  const app = express();
  app.disable("x-powered-by");

  app.use((req, res, next) => {
    res.set("cache-control", "no-store");
    next();
  });

  app.get("/health", rateLimitMiddleware("health", MAX_HEALTH_REQUESTS_PER_WINDOW), asyncRoute(async (req, res) => {
    store.ensureDatabase();
    res.json({ status: "ok", service: "mcp-server-agent-security", timestamp: new Date().toISOString() });
  }));

  app.use(rateLimitMiddleware("protected-attempt", MAX_PROTECTED_REQUESTS_PER_WINDOW));
  app.use(requireTrustedCaller);
  app.use(rateLimitMiddleware("protected", MAX_PROTECTED_REQUESTS_PER_WINDOW));
  app.use((req, res, next) => {
    if (["POST", "PUT", "PATCH"].includes(req.method) && !req.is("application/json")) {
      res.status(415).json({ error: "Content-Type must be application/json." });
      return;
    }
    next();
  });
  app.use(express.json({ limit: "5mb" }));
  app.use((error, req, res, next) => {
    if (!error) {
      next();
      return;
    }
    if (error.type === "entity.too.large") {
      res.status(413).json({ error: "Request body exceeds the 5mb limit." });
      return;
    }
    if (error.type === "entity.parse.failed" || error instanceof SyntaxError) {
      res.status(400).json({ error: "Malformed JSON body." });
      return;
    }
    next(error);
  });
  app.use((req, res, next) => {
    if (["POST", "PUT", "PATCH"].includes(req.method) && req.body != null && !isPlainObject(req.body)) {
      res.status(400).json({ error: "Request body must be a JSON object." });
      return;
    }
    next();
  });

  app.post("/audit/config", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("config", req.body.config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "config",
      "mcp-config",
      async () => analyzeConfig(validatedConfig.parsed),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/server", asyncRoute(async (req, res) => {
    if (!isAdminModeEnabled()) {
      res.status(403).json({ error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE });
      return;
    }

    const validatedTarget = validateServerLaunchSpec(req.body.command, req.body.args, req.body.env);
    if (validatedTarget.error) {
      res.status(400).json({ error: validatedTarget.error });
      return;
    }

    const target = [validatedTarget.command, ...validatedTarget.args].join(" ").trim();
    const result = await executeManagedAudit(
      req,
      res,
      "server",
      target,
      async () => probeServer(validatedTarget),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/injection", asyncRoute(async (req, res) => {
    if (typeof req.body.system_prompt !== "string" || !req.body.system_prompt.trim()) {
      res.status(400).json({ error: "system_prompt must be a non-empty string." });
      return;
    }
    if (req.body.system_prompt.length > MAX_SYSTEM_PROMPT_CHARS) {
      res.status(400).json({ error: "system_prompt exceeds the maximum size." });
      return;
    }

    const tools = sanitizeToolsInput(req.body.tools);
    if (tools === null) {
      res.status(400).json({ error: `tools must be an array of at most ${MAX_TOOLS} non-empty strings.` });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "injection",
      "prompt-surface",
      async () => testPromptInjection(req.body.system_prompt, tools),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/dataflow", asyncRoute(async (req, res) => {
    const parsedConfig = parseJsonInput("mcp_config", req.body.mcp_config);
    if (parsedConfig.error) {
      res.status(400).json({ error: parsedConfig.error });
      return;
    }

    const validatedConfig = validateConfigTopology(parsedConfig.parsed, "mcp_config");
    if (validatedConfig.error) {
      res.status(400).json({ error: validatedConfig.error });
      return;
    }

    if (configContainsCommandLaunchers(validatedConfig.serverEntries) && !isAdminModeEnabled()) {
      res.status(403).json({ error: ACTIVE_SERVER_PROBING_DISABLED_MESSAGE });
      return;
    }

    const normalizedConfig = sanitizeConfigLaunchTargets(validatedConfig.parsed);
    if (normalizedConfig.error) {
      res.status(400).json({ error: normalizedConfig.error });
      return;
    }

    if (req.body.test_pii !== undefined && typeof req.body.test_pii !== "string") {
      res.status(400).json({ error: "test_pii must be a string when provided." });
      return;
    }
    if (typeof req.body.test_pii === "string" && req.body.test_pii.length > MAX_TEST_PII_LENGTH) {
      res.status(400).json({ error: "test_pii exceeds the maximum size." });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "dataflow",
      "mcp-pipeline",
      async () => traceDataFlow(normalizedConfig.parsed, req.body.test_pii),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.post("/audit/package", asyncRoute(async (req, res) => {
    if (typeof req.body.package_name !== "string") {
      res.status(400).json({ error: "package_name must be a string." });
      return;
    }

    const packageName = req.body.package_name.trim();
    if (!isSafeNpmPackageSpec(packageName)) {
      res.status(400).json({ error: "package_name must be a valid npm registry package identifier." });
      return;
    }

    const result = await executeManagedAudit(
      req,
      res,
      "package",
      packageName,
      async () => scanPackage(packageName),
      MAX_AUDIT_MS
    );
    if (result) {
      res.json(sanitizeAuditResponse(result));
    }
  }));

  app.get("/report/:id", asyncRoute(async (req, res) => {
    if (!UUID_PATTERN.test(req.params.id)) {
      res.status(400).json({ error: "Audit report id must be a UUID." });
      return;
    }

    const audit = store.getAudit(req.params.id);
    if (!audit || !canReadAudit(req, audit)) {
      res.status(404).json({ error: "Audit report not found." });
      return;
    }

    res.json(sanitizeAuditResponse(audit));
  }));

  return app;
}

function startServer(port, host) {
  const listenPort = port || PORT;
  const listenHost = host || HOST;
  if (!isLoopbackHost(listenHost) && !API_KEY) {
    throw new Error("Refusing to bind the audit API to a non-loopback interface without AGENT_SECURITY_API_KEY.");
  }

  const app = createApp();
  return app.listen(listenPort, listenHost, () => {
    process.stdout.write(`mcp-server-agent-security listening on ${listenHost}:${listenPort}\n`);
  });
}

if (require.main === module) {
  startServer(PORT, HOST);
}

module.exports = {
  ACTIVE_SERVER_PROBING_DISABLED_MESSAGE,
  PORT,
  HOST,
  createApp,
  startServer,
  executeAuditJob,
  generateCombinedReport,
  isAdminModeEnabled,
  testOnly: {
    buildAuditAccessControl,
    canReadAudit,
    getCallerFingerprint,
    getRemoteAddress,
    isSafeNpmPackageSpec,
    rateLimitMiddleware,
    sanitizeAuditResponse,
    sanitizeConfigLaunchTargets,
    validateServerLaunchSpec
  }
};
