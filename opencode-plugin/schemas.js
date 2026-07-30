export function packetArgs(tool) {
  const id = () => tool.schema.string().min(1).max(64);
  const text = () => tool.schema.string().min(1).max(10_000);
  const textList = () => tool.schema.array(text()).min(1).max(256);
  const idList = () => tool.schema.array(id()).min(1).max(256);
  const pathList = () =>
    tool.schema.array(tool.schema.string().min(1).max(500)).min(1).max(256);
  const requirement = tool.schema.object({
    id: id(),
    statement: text(),
    acceptance_ids: idList(),
  });
  const acceptance = tool.schema.object({
    id: id(),
    criterion: text(),
    verification: textList(),
    required_paths: pathList(),
  });
  const component = tool.schema.object({
    name: id(),
    responsibility: text(),
    dependencies: tool.schema.array(id()).max(256),
  });
  const phase = tool.schema.object({
    id: id(),
    goal: text(),
    requirement_ids: idList(),
    acceptance_ids: idList(),
    allowed_paths: pathList(),
    check_ids: idList(),
  });
  return {
    certainty: tool.schema.object({
      confirmed: tool.schema.literal(true),
      unresolved_items: tool.schema.array(text()).max(0),
      assumptions: tool.schema.array(text()).max(0),
    }),
    requirements: tool.schema.array(requirement).min(1).max(256),
    acceptance: tool.schema.array(acceptance).min(1).max(256),
    constraints: textList(),
    non_goals: textList(),
    stop_conditions: textList(),
    architecture: tool.schema.object({
      objective: text(),
      public_interface: text(),
      dependency_direction: text(),
      components: tool.schema.array(component).min(1).max(256),
      trust_boundaries: textList(),
      data_flows: textList(),
      concurrency: tool.schema.object({
        ordering: text(),
        idempotency: text(),
        backpressure: text(),
        limits: text(),
        failures: text(),
        scaling: text(),
        observability: text(),
      }),
    }),
    phases: tool.schema.array(phase).min(1).max(256),
  };
}
