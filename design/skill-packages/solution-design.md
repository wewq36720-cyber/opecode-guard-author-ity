# solution-design v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包把冻结 Requirements Contract 转成可执行 Solution Design、影响集合、slice、check 和 correction policy。它不能改写 R/AC、读取未授权源码、登记任意命令或扩大路径。

“单一公开入口”是组件 ownership/facade boundary，不等于单方法或单 adapter。多个端口只有在归属同一契约、依赖方向和所有者时才合法；绕过该边界的旁路才阻断。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `architecture-and-interfaces.md` | 组件 ownership、ports/adapters、数据流、容量、观测、R/AC landing | agent-team-design、api-interface-design、context-engineering、observability-design、rag-architect |
| `repository-impact-and-fit.md` | 仓库影响、调用链、风险、canonical path objects、兼容性 | architecture-doubt-review、change-impact-auditor、function-map-scan、pre-routing-check |
| `patterns-and-commands.md` | 已批准 pattern/template、registered checks 和迁移约束 | design-dna-search、template-extract、execution-commands |

## 3. Step-level I/O

| step | 必需输入 | 条件输入 | outcome -> 输出 |
| --- | --- | --- | --- |
| `planning.design.architecture` | Requirements Contract + Check Registry | Repository Context、origin 对应的 Response Bundle | `completed` -> Architecture Fragment；`clarification_required` -> Question Set；`blocked` -> Blocking Record |
| `planning.design.impact` | Requirements + Architecture + Repository Context + Path Policy | 无 | `completed` -> Impact Fragment；`blocked` -> Blocking Record |
| `planning.design.pattern` | Requirements + Architecture + Approved Pattern Registry | 无 | `completed` -> Pattern Fragment；`blocked` -> Blocking Record |
| `planning.design.finalize` | Requirements + Architecture + Check Registry | Impact、Pattern、origin 对应的 Response Bundle | `completed` -> Solution Design；`clarification_required` -> Question Set；`blocked` -> Blocking Record |
| `planning.design.apply_response`（Guard） | Question Set + Question Response | 无 | `response_applied` -> Response Bundle；`blocked` -> Blocking Record |
| `planning.phase_gate`（Guard） | Requirements + Solution Design + registries | 无 | `passed` -> Phase Gate Record；`changes_required` -> Design Issue Set；`blocked` -> Blocking Record |

## 4. Solution Design

`artifact.solution_design.v2` 至少包含：

```text
requirement_revision / acceptance_revision
components[{
  id,owner,public_boundary,ports[],adapters[],
  responsibilities[],dependencies[],data_flows[],
  ordering,idempotency,consistency,
  load,backpressure,timeouts,retries,scaling,observability
}]
requirement_landings[{requirement_id,component_ids[]}]
acceptance_landings[{acceptance_id,component_ids[],check_ids[]}]
impact{
  modify_objects[],create_objects[],delete_objects[],rename_operations[],
  generated_outputs[],unaffected_assumptions[]
}
slices[{
  id,slice_kind,requirement_ids[],acceptance_ids[],
  allowed_path_objects[],required_check_ids[],
  order_key,dependencies[],completion_assertions[]
}]
correction_policy{derivable_changes[],return_to_design_triggers[]}
decisions[] / risks[] / rollback[]
```

path objects 使用 Guard canonical identity，覆盖大小写、重解析点、硬链接、rename/delete 和 source revision。字符串 glob 不能作为唯一权限依据。

Architecture、Impact、Pattern 和 Finalize 通过冻结 ArtifactRef 读取历史 fragment，不依赖“直接前一步”。Architecture/Finalize 的 Question Set 绑定 origin step/profile、resume token 和 input revision；Guard apply 后只恢复该 origin，并传入 Response Bundle。

## 5. Slice 与 Correction

每个 slice 只有一个 `slice_kind`：`standard`、`security_or_refactor`、`model_integration`、`ui`。多 kind 必须拆分。

Correction 只能在 `correction_policy.derivable_changes` 内派生。新增路径、依赖、接口、runner、check 或改变 AC 时必须提升 Design revision 并回到 phase gate。

## 6. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `SOL-AC-01` | 所有 R/AC 有 design landing | always |
| `SOL-AC-02` | component ownership/public boundary/port 关系完整且无旁路 | always |
| `SOL-AC-03` | impact operation set 闭合并使用 canonical path identity | existing repository；greenfield 有 N/A evidence |
| `SOL-AC-04` | 每个 slice 单 kind、范围有界、依赖有序 | always |
| `SOL-AC-05` | ordering/idempotency/backpressure/failure/scaling/observability 有界 | communication present；否则 N/A |
| `SOL-AC-06` | checks 全部来自冻结 registry，AC mapping 完整 | always |
| `SOL-AC-07` | correction policy 不允许静默扩大设计 | always |
| `SOL-AC-08` | 所有 Skill step 有有效 Delivery Receipt 和 Evidence Fragment | always |

聚合为 `all_applicable`。Phase Gate 使用确定性结构和 registry 断言；质量性判断留给后续 architecture review，不在 planning 中隐式等待独立人工审查。
