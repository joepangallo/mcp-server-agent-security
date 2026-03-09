"use strict";

const MCP_COMMAND_ALLOWLIST = new Set(["node", "python3", "python", "npx", "uvx", "deno", "bun"]);
const DISALLOWED_RUNTIME_ENV_KEYS = new Set([
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

function normalizeEnvKey(key) {
  return typeof key === "string" ? key.trim().toUpperCase() : "";
}

function isAdminModeEnabled() {
  return process.env.AGENT_SECURITY_ADMIN_MODE === "1";
}

function getCommandBase(command) {
  if (typeof command !== "string") {
    return "";
  }

  const trimmed = command.trim();
  if (!trimmed) {
    return "";
  }

  return trimmed.split(/\s+/)[0];
}

function isCommandAllowed(command, allowlist) {
  const commandBase = getCommandBase(command);
  const effectiveAllowlist = allowlist instanceof Set ? allowlist : MCP_COMMAND_ALLOWLIST;
  return Boolean(commandBase) && effectiveAllowlist.has(commandBase);
}

function findDisallowedRuntimeEnvKeys(envInput) {
  if (!envInput || typeof envInput !== "object" || Array.isArray(envInput)) {
    return [];
  }

  return Object.keys(envInput)
    .filter((key) => DISALLOWED_RUNTIME_ENV_KEYS.has(normalizeEnvKey(key)))
    .sort((left, right) => left.localeCompare(right));
}

function stripDisallowedRuntimeEnvKeys(envInput) {
  if (!envInput || typeof envInput !== "object" || Array.isArray(envInput)) {
    return undefined;
  }

  const filtered = {};
  for (const [key, value] of Object.entries(envInput)) {
    if (!DISALLOWED_RUNTIME_ENV_KEYS.has(normalizeEnvKey(key))) {
      filtered[key] = value;
    }
  }

  return Object.keys(filtered).length ? filtered : undefined;
}

module.exports = {
  MCP_COMMAND_ALLOWLIST,
  findDisallowedRuntimeEnvKeys,
  getCommandBase,
  isAdminModeEnabled,
  isCommandAllowed,
  stripDisallowedRuntimeEnvKeys
};
