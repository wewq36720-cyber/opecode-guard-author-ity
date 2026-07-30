import { requiredSession } from "./client.js";

function planningArtifactArgs(tool) {
  return { body: tool.schema.any() };
}

function planningTool(tool, request, operation, description) {
  return tool({
    description,
    args: planningArtifactArgs(tool),
    async execute(args, context) {
      const status = await request("status");
      return JSON.stringify(
        await request(operation, {
          expected_revision: status.revision,
          session_id: requiredSession(context.sessionID),
          context_digest: status.context_digest,
          skill_binding_digest: status.skill_binding.digest,
          body: args.body,
        }),
      );
    },
  });
}

export function createGuardTools(tool, request) {
  return {
    guard_submit_baseline: planningTool(
      tool,
      request,
      "submit_baseline",
      "Submit one immutable baseline candidate for external review.",
    ),
    guard_submit_spec: planningTool(
      tool,
      request,
      "submit_spec",
      "Submit one immutable specification candidate for external review.",
    ),
    guard_submit_plan: planningTool(
      tool,
      request,
      "submit_plan",
      "Submit one immutable implementation-plan candidate for external approval.",
    ),
    guard_complete_phase: tool({
      description:
        "Complete the active frozen phase; the Guard starts the next phase or verification.",
      args: {
        phase_id: tool.schema.string().min(1).max(64),
        outcome: tool.schema.enum(["changed", "no-change"]),
        rationale: tool.schema.string().min(1).max(2_000),
      },
      async execute(args, context) {
        const status = await request("status");
        return JSON.stringify(
          await request(
            "complete_phase",
            {
              expected_revision: status.revision,
              session_id: requiredSession(context.sessionID),
              phase_id: args.phase_id,
              outcome: args.outcome,
              rationale: args.rationale,
            },
            3_700_000,
          ),
        );
      },
    }),
    guard_quality_status: tool({
      description: "Read the bounded quality readiness projection for the current Guard Run.",
      args: {},
      async execute(_args, context) {
        requiredSession(context.sessionID);
        return JSON.stringify(await request("quality_status"));
      },
    }),
    guard_drive_quality: tool({
      description: "Persist one idempotent quality drive for the current Guard Run.",
      args: { request_id: tool.schema.string().min(1).max(64) },
      async execute(args, context) {
        const status = await request("status");
        return JSON.stringify(
          await request("drive_quality", {
            expected_revision: status.revision,
            session_id: requiredSession(context.sessionID),
            context_digest: status.context_digest,
            skill_binding_digest: status.skill_binding.digest,
            request_id: args.request_id,
          }),
        );
      },
    }),
    guard_confirm_fitness: tool({
      description: "Persist the idempotent fitness outcome for a quality drive.",
      args: {
        request_id: tool.schema.string().min(1).max(64),
        drive_id: tool.schema.string().min(1).max(64),
      },
      async execute(args, context) {
        const status = await request("status");
        return JSON.stringify(
          await request("confirm_fitness", {
            expected_revision: status.revision,
            session_id: requiredSession(context.sessionID),
            context_digest: status.context_digest,
            skill_binding_digest: status.skill_binding.digest,
            request_id: args.request_id,
            drive_id: args.drive_id,
          }),
        );
      },
    }),
  };
}
