"use strict";

const { isPlainObject } = require("./utils");
const { parseConfig, getServerEntries } = require("./config-analyzer");
const {
  MCP_COMMAND_ALLOWLIST,
  DISALLOWED_RUNTIME_ENV_KEYS,
  findDisallowedRuntimeEnvKeys,
  isDangerousEnvKey
} = require("./runtime-policy");
const {
  MAX_COMMAND_LENGTH,
  MAX_ARGS,
  MAX_ARG_LENGTH,
  MAX_ENV_KEYS,
  MAX_ENV_VALUE_LENGTH,
  MAX_JSON_INPUT_CHARS,
  MAX_SYSTEM_PROMPT_CHARS,
  MAX_TOOLS,
  MAX_TOOL_LENGTH,
  MAX_PACKAGE_NAME_LENGTH,
  MAX_SERVERS_PER_CONFIG,
  NPX_ALLOWED_FLAGS
} = require("./constants");

const COMMAND_ALLOWLIST = MCP_COMMAND_ALLOWLIST;
const RESERVED_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);

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

  const DENO_DANGEROUS_FLAGS = [
    "--allow-all",
    "--allow-sys",
    "--allow-ffi"
  ];
  const DENO_SCOPED_ONLY_FLAGS = [
    "--allow-run",
    "--allow-net",
    "--allow-env",
    "--allow-read",
    "--allow-write"
  ];

  let entryIndex = 1;
  while (entryIndex < args.length && String(args[entryIndex]).trim().startsWith("-")) {
    const rawFlag = String(args[entryIndex]).trim();
    const flag = rawFlag.split("=")[0];
    if (/^--?(?:eval|repl)$/i.test(flag)) {
      return "deno eval/repl modes are not allowed.";
    }
    if (DENO_DANGEROUS_FLAGS.some((blocked) => flag.toLowerCase() === blocked)) {
      return `deno flag "${flag}" is not allowed.`;
    }
    if (DENO_SCOPED_ONLY_FLAGS.some((scoped) => flag.toLowerCase() === scoped)) {
      if (!rawFlag.includes("=")) {
        return `deno flag "${flag}" requires a scope (e.g., ${flag}=<value>).`;
      }
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

module.exports = {
  configContainsCommandLaunchers,
  isSafeLocalEntryPoint,
  isSafeNpmPackageSpec,
  isSafePythonModule,
  isSafePythonPackageSpec,
  parseJsonInput,
  sanitizeConfigLaunchTargets,
  sanitizeConfigServerSpec,
  sanitizeEnvInput,
  sanitizeToolsInput,
  validateBunArgs,
  validateConfigTopology,
  validateDenoArgs,
  validateNodeArgs,
  validateNpxArgs,
  validatePythonArgs,
  validateServerLaunchSpec,
  validateUvxArgs
};
