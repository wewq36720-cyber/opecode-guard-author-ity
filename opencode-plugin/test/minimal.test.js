import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import * as pluginEntry from "../index.js";
import { OpenCodeGuardAuthority } from "../index.js";

const AUTHORITY = join(tmpdir(), "opencode-guard-authority.exe");
const MCP = join(tmpdir(), "opencode-guard-mcp.exe");

class FakeClient {
  constructor() {
    this.calls = [];
    this.sessions = new Set();
    this.status = {
      run_id: "run-1",
      worktree: "F:/worktree",
      stage: "PLANNING",
      revision: 0,
      task: "",
      allowed_paths: [],
      available_checks: ["pytest"],
      phases: [],
      blocked: { code: "", message: "" },
      lease: { active: false, phase_id: "", revision: 0 },
      recent_failed_evidence: [],
    };
    this.refreshContext();
  }

  refreshContext() {
    const instructions = {
      PLANNING: "Submit one complete frozen packet before editing.",
      IMPLEMENTING: "Edit only frozen paths and use the Guard write lease.",
      VERIFYING: "Use trusted verification evidence; do not write.",
      REVIEW_REQUIRED: "Use current evidence and wait for external acceptance.",
      ACCEPTED: "Read-only accepted Run; do not mutate state.",
    };
    this.status = {
      ...this.status,
      source_revision: this.status.revision,
      context_digest: "context-" + this.status.revision,
      skill_binding: {
        skill_id: "opencode-guard/" + this.status.stage.toLowerCase(),
        version: "1",
        stage: this.status.stage,
        phase_id: this.status.active_phase || "",
        instructions: instructions[this.status.stage],
        digest:
          "skill-" + this.status.stage + "-" + (this.status.active_phase || "none"),
      },
    };
    return this.status;
  }

  advance(values = {}) {
    this.status = { ...this.status, ...values, revision: this.status.revision + 1 };
    return this.refreshContext();
  }

  async request(op, params) {
    this.calls.push({ op, params });
    if (op === "status") return this.status;
    if (op === "bind_task") {
      this.sessions.add(params.session_id);
      return this.advance({ task: params.task });
    }
    if (op === "attach_session") {
      if (this.sessions.has(params.session_id)) return this.status;
      this.sessions.add(params.session_id);
      return this.advance();
    }
    if (op === "authorize_tool") {
      if (params.tool_name !== "edit") return { allowed: true, revision: this.status.revision };
      const status = this.advance({
        lease: {
          active: true,
          phase_id: this.status.active_phase,
          revision: this.status.revision + 1,
        },
      });
      return { allowed: true, revision: status.revision };
    }
    if (op === "post_tool") {
      return this.advance({ lease: { active: false, phase_id: "", revision: 0 } });
    }
    return this.advance();
  }

  close() {}
}

async function createPlugin(client = new FakeClient(), options = {}) {
  return {
    client,
    plugin: await OpenCodeGuardAuthority(
      { directory: "F:/worktree", worktree: "F:/worktree" },
      {
        runID: "run-1",
        stateDir: "F:/state",
        authorityCommand: AUTHORITY,
        mcpCommand: MCP,
        __client: client,
        ...options,
      },
    ),
  };
}

async function createConfiguredPlugin(t, client = new FakeClient()) {
  const directory = await mkdtemp(join(tmpdir(), "guard-configured-"));
  const created = await createPlugin(client, {
    handshakeFile: join(directory, "ready.json"),
    handshakeNonce: "nonce-test",
  });
  t.after(async () => {
    await created.plugin.dispose();
    await rm(directory, { recursive: true, force: true });
  });
  await created.plugin.config({});
  return created;
}

test("entry exports one OpenCode plugin", () => {
  assert.deepEqual(Object.keys(pluginEntry), ["OpenCodeGuardAuthority"]);
});

test("config exposes declared planning tools and exact MCP reads/writes", async () => {
  const { plugin } = await createPlugin();
  const config = { mcp: { legacy: { enabled: true } }, experimental: { hook: {} } };
  await plugin.config(config);
  assert.equal(config.permission["*"], "deny");
  assert.equal(config.permission.edit, "allow");
  assert.equal(config.permission.bash, "deny");
  assert.equal(config.permission.skill, "deny");
  assert.deepEqual(Object.keys(plugin.tool).sort(), [
    "guard_complete_phase",
    "guard_confirm_fitness",
    "guard_drive_quality",
    "guard_quality_status",
    "guard_submit_baseline",
    "guard_submit_plan",
    "guard_submit_spec",
  ]);
  assert.equal(
    config.permission["opencode-guard-authority_guard_context"],
    "allow",
  );
  assert.equal(
    config.permission["opencode-guard-authority_guard_artifact"],
    "allow",
  );
  assert.equal(
    config.permission["opencode-guard-authority_guard_evidence"],
    "allow",
  );
  assert.equal(config.permission["opencode-guard-authority_guard_list_skills"], undefined);
  assert.equal(
    config.permission["opencode-guard-authority_guard_submit_plan"],
    "allow",
  );
  assert.equal(config.permission["opencode-guard-authority_guard_approve_plan"], undefined);
  assert.deepEqual(Object.keys(config.mcp), ["opencode-guard-authority"]);
});

test("planning tools submit only typed candidate bodies", async (t) => {
  const { client, plugin } = await createConfiguredPlugin(t);
  for (const [toolName, operation] of [
    ["guard_submit_baseline", "submit_baseline"],
    ["guard_submit_spec", "submit_spec"],
    ["guard_submit_plan", "submit_plan"],
  ]) {
    client.calls.length = 0;
    const body = { id: toolName };
    const expectedRevision = client.status.revision;
    const expectedContext = client.status.context_digest;
    await plugin.tool[toolName].execute({ body }, { sessionID: "session-1" });
    assert.deepEqual(client.calls, [
      { op: "status", params: { run_id: "run-1" } },
      {
        op: operation,
        params: {
          run_id: "run-1",
          expected_revision: expectedRevision,
          session_id: "session-1",
          context_digest: expectedContext,
          skill_binding_digest: "skill-PLANNING-none",
          body,
        },
      },
    ]);
  }
});

test("quality-status tool forwards one read-only authority request", async () => {
  const { client, plugin } = await createPlugin();
  await plugin.config({});
  client.calls.length = 0;
  await plugin.tool.guard_quality_status.execute({}, { sessionID: "session-1" });
  assert.deepEqual(client.calls, [{ op: "quality_status", params: { run_id: "run-1" } }]);
});

test("quality write tools read current context before forwarding their requests", async () => {
  const { client, plugin } = await createPlugin();
  await plugin.config({});
  client.calls.length = 0;

  await plugin.tool.guard_drive_quality.execute(
    { request_id: "drive-request" },
    { sessionID: "session-1" },
  );
  assert.deepEqual(client.calls, [
    { op: "status", params: { run_id: "run-1" } },
    {
      op: "drive_quality",
      params: {
        run_id: "run-1",
        expected_revision: 0,
        session_id: "session-1",
        context_digest: "context-0",
        skill_binding_digest: "skill-PLANNING-none",
        request_id: "drive-request",
      },
    },
  ]);

  client.calls.length = 0;
  await plugin.tool.guard_confirm_fitness.execute(
    { request_id: "fitness-request", drive_id: "d-123" },
    { sessionID: "session-1" },
  );
  assert.deepEqual(client.calls, [
    { op: "status", params: { run_id: "run-1" } },
    {
      op: "confirm_fitness",
      params: {
        run_id: "run-1",
        expected_revision: 1,
        session_id: "session-1",
        context_digest: "context-1",
        skill_binding_digest: "skill-PLANNING-none",
        request_id: "fitness-request",
        drive_id: "d-123",
      },
    },
  ]);
});

test("session bind and attach fail closed before the nonce handshake", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "guard-pre-handshake-"));
  const client = new FakeClient();
  const { plugin } = await createPlugin(client, {
    handshakeFile: join(directory, "ready.json"),
    handshakeNonce: "nonce-pre",
  });
  t.after(async () => {
    await plugin.dispose();
    await rm(directory, { recursive: true, force: true });
  });
  client.calls.length = 0;

  await assert.rejects(
    plugin["chat.message"](
      { sessionID: "session-bind" },
      { parts: [{ type: "text", text: "bind" }] },
    ),
    (error) => error.code === "SESSION_NOT_ATTACHED",
  );
  client.status.task = "existing task";
  client.refreshContext();
  await assert.rejects(
    plugin["chat.message"](
      { sessionID: "session-attach" },
      { parts: [{ type: "text", text: "attach" }] },
    ),
    (error) => error.code === "SESSION_NOT_ATTACHED",
  );
  assert.deepEqual(client.calls, []);
});

test("first user message binds the task once", async (t) => {
  const { client, plugin } = await createConfiguredPlugin(t);
  await plugin["chat.message"](
    { sessionID: "session-1" },
    { parts: [{ type: "text", text: "实现功能" }] },
  );
  await plugin["chat.message"](
    { sessionID: "session-1" },
    { parts: [{ type: "text", text: "继续" }] },
  );
  assert.equal(client.calls.filter((call) => call.op === "bind_task").length, 1);
});

test("a fresh session attaches to an existing task before use", async (t) => {
  const client = new FakeClient();
  client.status.task = "existing task";
  client.refreshContext();
  const { plugin } = await createConfiguredPlugin(t, client);
  client.calls.length = 0;

  await plugin["chat.message"](
    { sessionID: "session-2" },
    { parts: [{ type: "text", text: "continue" }] },
  );

  assert.deepEqual(
    client.calls.map((call) => call.op),
    ["status", "attach_session"],
  );
  assert.deepEqual(client.calls[1].params, {
    run_id: "run-1",
    expected_revision: 0,
    context_digest: "context-0",
    skill_binding_digest: "skill-PLANNING-none",
    session_id: "session-2",
  });
});

test("planning context injects the complete immutable packet rules", async () => {
  const { plugin } = await createPlugin();
  const output = { system: [] };
  await plugin["experimental.chat.system.transform"]({}, output);
  const context = output.system.join("\n");
  for (const required of [
    "Authoritative Guard context",
    '"context_digest":"context-0"',
    "Current phase Skill binding",
    '"skill_id":"opencode-guard/planning"',
    "exact files (src/pkg/main.py)",
    "explicit directory trees (src/pkg/**)",
    "Bare directories such as src, tests, or docs are prohibited",
    "尚未确认, 后续确认, 不确定, 或许",
    "maybe, perhaps, to be checked",
    'certainty={"confirmed":true,"unresolved_items":[],"assumptions":[]}',
    "stop packet planning and ask a question",
    "Every phase must list exact files or explicit /** directory trees",
    "literal union of all earlier allowed_paths",
    "Frozen paths cannot be expanded",
  ]) {
    assert.match(context, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("write hooks preserve the before revision for post-tool validation", async (t) => {
  const { client, plugin } = await createConfiguredPlugin(t);
  await plugin["chat.message"](
    { sessionID: "session-1" },
    { parts: [{ type: "text", text: "implement" }] },
  );
  client.calls.length = 0;
  await plugin["tool.execute.before"](
    { tool: "edit", sessionID: "session-1", callID: "call-1" },
    { args: { filePath: "src/app.py", content: "x" } },
  );
  await plugin["tool.execute.after"]({
    tool: "edit",
    sessionID: "session-1",
    callID: "call-1",
  });
  assert.deepEqual(client.calls.find((call) => call.op === "authorize_tool").params, {
    run_id: "run-1",
    expected_revision: 1,
    context_digest: "context-1",
    skill_binding_digest: "skill-PLANNING-none",
    session_id: "session-1",
    tool_name: "edit",
    paths: ["src/app.py"],
    call_id: "call-1",
  });
  assert.deepEqual(client.calls.find((call) => call.op === "post_tool").params, {
    run_id: "run-1",
    expected_revision: 2,
    context_digest: "context-2",
    skill_binding_digest: "skill-PLANNING-none",
    session_id: "session-1",
    tool_name: "edit",
    call_id: "call-1",
  });
});

test("configuration writes a nonce-bound handshake", async () => {
  const directory = await mkdtemp(join(tmpdir(), "guard-handshake-"));
  const handshake = join(directory, "ready.json");
  const { plugin } = await createPlugin(new FakeClient(), {
    handshakeFile: handshake,
    handshakeNonce: "nonce-1",
  });
  try {
    await plugin.config({});
    assert.deepEqual(JSON.parse(await readFile(handshake, "utf8")), {
      protocol: 1,
      nonce: "nonce-1",
      run_id: "run-1",
      worktree: "F:/worktree",
    });
  } finally {
    await plugin.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});

test("failed handshake writes leave session mutation disabled", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "guard-handshake-failure-"));
  const blockedParent = join(directory, "not-a-directory");
  await writeFile(blockedParent, "blocked", "utf8");
  const client = new FakeClient();
  const { plugin } = await createPlugin(client, {
    handshakeFile: join(blockedParent, "ready.json"),
    handshakeNonce: "nonce-failure",
  });
  t.after(async () => {
    await plugin.dispose();
    await rm(directory, { recursive: true, force: true });
  });
  client.calls.length = 0;

  await assert.rejects(plugin.config({}));
  await assert.rejects(
    plugin["chat.message"](
      { sessionID: "session-1" },
      { parts: [{ type: "text", text: "must fail" }] },
    ),
    (error) => error.code === "SESSION_NOT_ATTACHED",
  );
  assert.deepEqual(client.calls, []);
});
