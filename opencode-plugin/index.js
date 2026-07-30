import { tool } from "@opencode-ai/plugin";

import {
  createAuthorityClient,
  guardError,
  normalizedPath,
  option,
  trustedCommand,
} from "./client.js";
import { createGuardHooks } from "./hooks.js";

export const OpenCodeGuardAuthority = async (input, options = {}) => {
  const runID = option(options.runID) || process.env.OPENCODE_GUARD_RUN_ID || "";
  const stateDir = option(options.stateDir) || process.env.OPENCODE_GUARD_STATE_DIR || "";
  if (Boolean(runID) !== Boolean(stateDir)) {
    throw guardError("GUARD_CONFIG_INVALID", "Guarded mode requires run and state IDs.");
  }
  const guarded = Boolean(runID && stateDir);
  const worktree = option(input.worktree) || option(input.directory);
  const authorityCommand = guarded
    ? trustedCommand(
        option(options.authorityCommand) || process.env.OPENCODE_GUARD_AUTHORITY_COMMAND || "",
        worktree,
        "Authority",
      )
    : "";
  const mcpCommand = guarded
    ? trustedCommand(
        option(options.mcpCommand) || process.env.OPENCODE_GUARD_MCP_COMMAND || "",
        worktree,
        "MCP",
      )
    : "";
  const client =
    options.__client ||
    (guarded
      ? createAuthorityClient(authorityCommand, stateDir, options.__spawn)
      : null);
  const request = async (op, params = {}, timeoutMs = 60_000) => {
    if (!client) throw guardError("GUARD_NOT_LAUNCHED", "Start with opencode-guard open.");
    return client.request(op, { run_id: runID, ...params }, timeoutMs);
  };

  const handshakeFile =
    option(options.handshakeFile) || process.env.OPENCODE_GUARD_HANDSHAKE_FILE || "";
  const handshakeNonce =
    option(options.handshakeNonce) || process.env.OPENCODE_GUARD_HANDSHAKE_NONCE || "";
  let handshakePayload = null;
  if (client && (handshakeFile || handshakeNonce)) {
    if (!handshakeFile || !handshakeNonce) {
      throw guardError(
        "HANDSHAKE_CONFIG_INVALID",
        "Guard handshake requires a file and nonce.",
      );
    }
    const status = await request("status");
    if (
      status.run_id !== runID ||
      !worktree ||
      normalizedPath(status.worktree) !== normalizedPath(worktree)
    ) {
      throw guardError(
        "HANDSHAKE_CONTEXT_MISMATCH",
        "OpenCode started outside the guarded worktree.",
      );
    }
    handshakePayload = {
      protocol: 1,
      nonce: handshakeNonce,
      run_id: runID,
      worktree: status.worktree,
    };
  }

  return createGuardHooks({
    tool,
    client,
    request,
    runID,
    stateDir,
    mcpCommand,
    handshakeFile,
    handshakePayload,
  });
};
