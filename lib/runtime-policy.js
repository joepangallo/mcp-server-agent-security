"use strict";

const MCP_COMMAND_ALLOWLIST = new Set(["node", "python3", "python", "npx", "uvx", "deno", "bun"]);

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

module.exports = {
  MCP_COMMAND_ALLOWLIST,
  getCommandBase,
  isAdminModeEnabled,
  isCommandAllowed
};
