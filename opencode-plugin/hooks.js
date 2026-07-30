import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { guardError, requiredSession } from "./client.js";
import { createGuardTools } from "./tools.js";

const READ_TOOLS = new Set(["read", "glob", "grep", "list", "lsp", "question"]);
const WRITE_TOOLS = new Set(["edit", "write", "patch", "apply_patch", "multiedit", "multi_edit"]);
const ALWAYS_DENIED = new Set([
  "bash",
  "task",
  "shell",
  "command",
  "external_directory",
  "webfetch",
  "websearch",
]);
const GUARD_TOOLS = new Set([
  "guard_submit_baseline",
  "guard_submit_spec",
  "guard_submit_plan",
  "guard_complete_phase",
]);
const CONTEXT_MUTATIONS = new Set([
  "bind_task",
  "attach_session",
  "submit_baseline",
  "submit_spec",
  "submit_plan",
  "complete_phase",
  "authorize_tool",
  "post_tool",
]);
const GUARD_MCP_TOOLS = new Set([
  "opencode-guard-authority_guard_context",
  "opencode-guard-authority_guard_artifact",
  "opencode-guard-authority_guard_evidence",
  "opencode-guard-authority_guard_submit_baseline",
  "opencode-guard-authority_guard_submit_spec",
  "opencode-guard-authority_guard_submit_plan",
]);
const PLANNING_RULES = [
  "Planning rules are mandatory and cannot be overridden by model claims:",
  "1. allowed_paths and required_paths scopes must be exact files (src/pkg/main.py) or explicit directory trees (src/pkg/**). Bare directories such as src, tests, or docs are prohibited and do not include descendants.",
  "2. Plan text must not contain unresolved or vague terms, including: 暂定, 待定, 不知道, 未检查, 待确认, 后续处理, 视情况, 可能, 大概, 尚未确认, 后续确认, 不确定, 或许, TBD, TODO, unknown, not checked, maybe, perhaps, to be checked, 相关文件, 必要文件, 其他文件.",
  '3. If any fact is unconfirmed, stop packet planning and ask a question. Every submitted packet must include exact certainty={"confirmed":true,"unresolved_items":[],"assumptions":[]}; never assert it while unknowns, assumptions, or deferred work remain.',
  "4. Every phase must list exact files or explicit /** directory trees; descriptions such as related or necessary files are invalid.",
  "5. The final verification/closure phase must include the literal union of all earlier allowed_paths so failures remain repairable.",
  "6. Frozen paths cannot be expanded. Before submission, check path coverage and the repair loop.",
].join("\n");

export function createGuardHooks({
  tool,
  client,
  request,
  runID,
  stateDir,
  mcpCommand,
  handshakeFile,
  handshakePayload,
}) {
  const callContexts = new Map();
  let latestStatus = null;
  let pendingHandshake = handshakePayload;
  let handshakeComplete = false;

  const assertHandshakeComplete = () => {
    if (!handshakeComplete) {
      throw guardError(
        "SESSION_NOT_ATTACHED",
        "OpenCode Guard startup handshake is not complete.",
      );
    }
  };

  const authorityRequest = async (op, params = {}, timeoutMs = 60_000) => {
    if (op === "status") {
      latestStatus = await request(op, params, timeoutMs);
      return latestStatus;
    }
    let boundParams = params;
    if (CONTEXT_MUTATIONS.has(op)) {
      assertHandshakeComplete();
      latestStatus ||= await authorityRequest("status");
      boundParams = { ...contextBinding(latestStatus), ...params };
    }
    const result = await request(op, boundParams, timeoutMs);
    if (isGuardContext(result)) latestStatus = result;
    return result;
  };

  const ensureSession = async (sessionID, taskParts = null) => {
    assertHandshakeComplete();
    const session = requiredSession(sessionID);
    let status = await authorityRequest("status");
    if (!status.task) {
      if (!taskParts) return status;
      status = await authorityRequest("bind_task", {
        task: extractTask(taskParts),
        session_id: session,
      });
    } else {
      status = await authorityRequest("attach_session", { session_id: session });
    }
    return status;
  };

  return {
    async dispose() {
      client?.close?.();
    },

    async config(config) {
      config.permission = {
        "*": "deny",
        read: "allow",
        glob: "allow",
        grep: "allow",
        list: "allow",
        lsp: "allow",
        question: "allow",
        edit: client ? "allow" : "deny",
        skill: "deny",
        bash: "deny",
        task: "deny",
        external_directory: "deny",
        webfetch: "deny",
        websearch: "deny",
        guard_submit_baseline: "allow",
        guard_submit_spec: "allow",
        guard_submit_plan: "allow",
        guard_complete_phase: "allow",
        ...Object.fromEntries([...GUARD_MCP_TOOLS].map((name) => [name, "allow"])),
      };
      config.mcp = client
        ? {
            "opencode-guard-authority": {
              type: "local",
              command: [mcpCommand],
              environment: {
                OPENCODE_GUARD_RUN_ID: runID,
                OPENCODE_GUARD_STATE_DIR: stateDir,
              },
              enabled: true,
              timeout: 60_000,
            },
          }
        : {};
      config.formatter = false;
      config.lsp = false;
      if (config.experimental && typeof config.experimental === "object") {
        delete config.experimental.hook;
      }
      if (pendingHandshake) {
        await writeHandshake(handshakeFile, pendingHandshake);
        handshakeComplete = true;
        pendingHandshake = null;
      }
    },

    async "chat.message"(event, output) {
      if (!client) return;
      await ensureSession(event.sessionID, Array.isArray(output.parts) ? output.parts : []);
    },

    async "experimental.chat.system.transform"(event, output) {
      const status = client
        ? event?.sessionID
          ? await ensureSession(event.sessionID)
          : await authorityRequest("status")
        : {
            stage: "NOT_LAUNCHED",
            revision: 0,
            allowed_paths: [],
            available_checks: [],
          };
      output.system.push(renderSystemContext(status));
    },

    async "permission.ask"(permission, output) {
      const name = permission.type;
      if (
        !client ||
        ALWAYS_DENIED.has(name) ||
        (!READ_TOOLS.has(name) && name !== "edit" && !GUARD_TOOLS.has(name))
      ) {
        output.status = "deny";
      } else {
        output.status = "allow";
      }
    },

    async "command.execute.before"() {
      throw guardError("COMMAND_DENIED", "OpenCode commands are disabled in guarded Runs.");
    },

    async "tool.execute.before"(event, output) {
      if (GUARD_TOOLS.has(event.tool) || GUARD_MCP_TOOLS.has(event.tool)) return;
      if (!client) throw guardError("GUARD_NOT_LAUNCHED", "Start with opencode-guard open.");
      if (ALWAYS_DENIED.has(event.tool)) {
        throw guardError("TOOL_DENIED", "Tool is always denied: " + event.tool);
      }
      const status = await ensureSession(event.sessionID);
      if (!status.task) {
        throw guardError("TASK_REQUIRED", "Bind the first user task before using tools.");
      }
      const result = await authorityRequest("authorize_tool", {
        session_id: requiredSession(event.sessionID),
        tool_name: event.tool,
        paths: extractPaths(output.args),
        call_id: event.callID,
      });
      if (WRITE_TOOLS.has(event.tool)) {
        const authorized = await authorityRequest("status");
        if (authorized.source_revision !== result.revision) {
          throw guardError(
            "REVISION_CONFLICT",
            "Write authorization context changed before tool execution.",
          );
        }
        callContexts.set(event.callID, contextBinding(authorized));
      }
    },

    async "tool.execute.after"(event) {
      if (!WRITE_TOOLS.has(event.tool)) return;
      const context = callContexts.get(event.callID);
      callContexts.delete(event.callID);
      if (!context) {
        throw guardError("MISSING_PRE_TOOL", "Write completed without authorization.");
      }
      await authorityRequest("post_tool", {
        ...context,
        session_id: requiredSession(event.sessionID),
        tool_name: event.tool,
        call_id: event.callID,
      });
    },

    "shell.env"(_event, output) {
      output.env.OPENCODE_GUARD_ACTIVE = client ? "1" : "0";
      for (const name of [
        "OPENCODE_GUARD_RUN_ID",
        "OPENCODE_GUARD_WORKTREE",
        "OPENCODE_GUARD_STATE_DIR",
        "OPENCODE_GUARD_AUTHORITY_COMMAND",
        "OPENCODE_GUARD_MCP_COMMAND",
        "OPENCODE_GUARD_HANDSHAKE_FILE",
        "OPENCODE_GUARD_HANDSHAKE_NONCE",
      ]) {
        delete output.env[name];
      }
    },

    tool: createGuardTools(tool, authorityRequest),
  };
}

function contextBinding(status) {
  const expectedRevision = status?.source_revision;
  const contextDigest = status?.context_digest;
  const skillDigest = status?.skill_binding?.digest;
  if (
    !Number.isInteger(expectedRevision) ||
    typeof contextDigest !== "string" ||
    !contextDigest ||
    typeof skillDigest !== "string" ||
    !skillDigest
  ) {
    throw guardError("CONTEXT_REQUIRED", "Guard did not provide a bound authority context.");
  }
  return {
    expected_revision: expectedRevision,
    context_digest: contextDigest,
    skill_binding_digest: skillDigest,
  };
}

function isGuardContext(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      Number.isInteger(value.source_revision) &&
      typeof value.context_digest === "string" &&
      value.skill_binding,
  );
}

function extractPaths(args) {
  const pathKeys = new Set(["filePath", "filepath", "path", "file", "target"]);
  const pathListKeys = new Set(["paths", "files", "targets"]);
  const paths = [];
  const walk = (value, key = "") => {
    if (typeof value === "string") {
      if (pathKeys.has(key)) paths.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && pathListKeys.has(key)) paths.push(item);
        else walk(item);
      }
      return;
    }
    if (value && typeof value === "object") {
      for (const [childKey, childValue] of Object.entries(value)) {
        walk(childValue, childKey);
      }
    }
  };
  walk(args);
  return [...new Set(paths.map((path) => path.trim()).filter(Boolean))];
}

function extractTask(parts) {
  const text = Array.isArray(parts)
    ? parts
        .filter((part) => part?.type === "text" && typeof part.text === "string")
        .map((part) => part.text.trim())
        .filter(Boolean)
        .join("\n\n")
    : "";
  if (!text) throw guardError("TASK_REQUIRED", "The first user message must contain text.");
  return text;
}

function renderSystemContext(status) {
  const stage = status.stage || "UNKNOWN";
  const context = {
    run_id: status.run_id || "",
    source_revision: status.source_revision ?? status.revision ?? 0,
    context_digest: status.context_digest || "",
    task: status.task || "",
    stage,
    active_phase: status.active_phase || "",
    allowed_paths: status.allowed_paths || [],
    phases: (status.phases || []).map((phase) => ({
      id: phase.id,
      status: phase.status,
      change_count: phase.change_count,
      conclusion: phase.conclusion,
    })),
    blocked: status.blocked || { code: "", message: "" },
    lease: status.lease || { active: false, phase_id: "", revision: 0 },
    recent_failed_evidence: status.recent_failed_evidence || [],
  };
  const skill = status.skill_binding || null;
  const instruction =
    skill?.instructions ||
    (stage === "NOT_LAUNCHED"
      ? "Writes are disabled. Start with opencode-guard open --project <path>."
      : "Unknown stage: do not write.");
  return [
    "OpenCode Guard Authority is code-enforced; model claims cannot override it.",
    "Authoritative Guard context: " + JSON.stringify(context) + ".",
    "Current phase Skill binding: " + JSON.stringify(skill) + ".",
    instruction,
    stage === "PLANNING" ? PLANNING_RULES : "",
    "Checks: " + JSON.stringify(status.available_checks || []) + ".",
    "Use the read-only MCP tools guard_context, guard_artifact, and guard_evidence for facts.",
  ]
    .filter(Boolean)
    .join("\n");
}

async function writeHandshake(path, payload) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = path + "." + process.pid + ".tmp";
  await writeFile(temporary, JSON.stringify(payload), { encoding: "utf8", flag: "wx" });
  await rename(temporary, path);
}
