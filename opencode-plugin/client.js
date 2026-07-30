import { spawn } from "node:child_process";
import { isAbsolute, relative, resolve, sep } from "node:path";

const MAX_MESSAGE_BYTES = 1024 * 1024;

export function createAuthorityClient(command, stateDir, spawnProcess = spawn) {
  const child = spawnProcess(command, [], {
    env: { ...process.env, OPENCODE_GUARD_STATE_DIR: stateDir },
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let nextID = 1;
  let buffer = "";
  let failure = null;
  const pending = new Map();
  const fail = (error) => {
    if (failure) return;
    failure = error;
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    pending.clear();
  };

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    if (Buffer.byteLength(buffer, "utf8") > MAX_MESSAGE_BYTES) {
      fail(guardError("AUTHORITY_PROTOCOL_ERROR", "Authority response exceeded one MiB."));
      child.kill();
      return;
    }
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      let response;
      try {
        response = JSON.parse(line);
      } catch {
        fail(guardError("AUTHORITY_PROTOCOL_ERROR", "Authority emitted invalid JSON."));
        child.kill();
        return;
      }
      const request = pending.get(response.id);
      if (!request) continue;
      pending.delete(response.id);
      clearTimeout(request.timer);
      if (response.ok) request.resolve(response.result);
      else {
        request.reject(
          guardError(response.error?.code || "AUTHORITY_ERROR", response.error?.message),
        );
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  child.on("error", (error) => fail(guardError("AUTHORITY_UNAVAILABLE", error.message)));
  child.on("exit", (code) =>
    fail(guardError("AUTHORITY_EXITED", "Authority exited with code " + code + ".")),
  );

  return {
    request(op, params, timeoutMs = 60_000) {
      if (failure) return Promise.reject(failure);
      const id = nextID++;
      const payload = JSON.stringify({ id, op, params }) + "\n";
      if (Buffer.byteLength(payload, "utf8") > MAX_MESSAGE_BYTES) {
        return Promise.reject(
          guardError("REQUEST_TOO_LARGE", "Authority request exceeded one MiB."),
        );
      }
      return new Promise((resolveRequest, rejectRequest) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          rejectRequest(
            guardError("AUTHORITY_TIMEOUT", "Authority timed out for " + op + "."),
          );
        }, timeoutMs);
        pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
        child.stdin.write(payload, "utf8", (error) => {
          if (error) fail(guardError("AUTHORITY_UNAVAILABLE", error.message));
        });
      });
    },
    close() {
      fail(guardError("AUTHORITY_CLOSED", "Authority client was closed."));
      child.stdin.end();
      child.kill();
    },
  };
}

export function trustedCommand(value, worktree, label) {
  if (!value || !isAbsolute(value) || !worktree) {
    throw guardError(
      "TRUSTED_COMMAND_REQUIRED",
      label + " command must be an absolute path supplied by opencode-guard.",
    );
  }
  const command = resolve(value);
  const root = resolve(worktree);
  const fromRoot = relative(root, command);
  const inside =
    fromRoot === "" ||
    (fromRoot !== ".." && !fromRoot.startsWith(".." + sep) && !isAbsolute(fromRoot));
  if (inside) {
    throw guardError(
      "TRUSTED_COMMAND_REQUIRED",
      label + " command must be outside the guarded worktree.",
    );
  }
  return command;
}

export function requiredSession(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw guardError("SESSION_REQUIRED", "OpenCode session ID is required.");
  }
  return value.trim();
}

export function option(value) {
  return typeof value === "string" ? value.trim() : "";
}

export function normalizedPath(value) {
  const normalized = resolve(option(value));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

export function guardError(code, message = "Guard rejected the operation.") {
  const error = new Error(code + ": " + message);
  error.code = code;
  return error;
}
