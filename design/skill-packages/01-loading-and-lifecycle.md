# v3.3 加载与生命周期设计

## 1. 自动启动与唯一加载链

OpenCode 启动受保护项目后，插件只负责握手和任务绑定。正常路径不要求用户执行 init、begin、checkpoint 或选择 Skill。

```text
OpenCode task bound
  -> Guard 创建/恢复 Run 并冻结 current revision
  -> step registry 选择唯一 next step
  -> owner=guard：执行登记的 deterministic algorithm
  -> owner=skill：验证 trust/contract/route/profile/path/runner
  -> canonical render Skill context
  -> provider delivery + Delivery Receipt
  -> 校验 SkillResult 的 step/outcome I/O 与 obligations
  -> 写 Evidence Fragment，刷新 Evidence Index
  -> 选择唯一包内 route；package terminal event 交给 system-lifecycle 选择跨包下一跳
```

模型不能看到候选版本列表，不能选择 profile/reference、审查轴、runner、路径或下一状态。OpenCode 原生 `permission.skill=deny` 保持不变；所有 Skill 内容只经 Guard 受控注入。

## 2. Step registry

公开状态仍为五个；以下使用完整 step ID，禁止 `.final` 等缩写。

| public state | owner=skill | owner=guard |
| --- | --- | --- |
| `PLANNING` | `planning.requirements.analyze`、`planning.requirements.research`、`planning.requirements.finalize`、`planning.design.architecture`、`planning.design.impact`、`planning.design.pattern`、`planning.design.finalize` | `planning.requirements.apply_response`、`planning.design.apply_response`、`planning.phase_gate` |
| `IMPLEMENTING` | `implementing.slice` | `implementing.manifest.append`、`correction.route` |
| `VERIFYING` | `verifying.run`、`verifying.evaluate`、`verifying.diagnose` | `verifying.aggregate` |
| `REVIEW_REQUIRED` | `review.correctness`、`review.architecture`、`review.security`、`record.checkpoint`、`review.handoff.simplicity`、`review.handoff.final` | `review.scope`、`review.aggregate`、`acceptance.apply` |
| `ACCEPTED` | 无 | 只读终态检查 |

`owner=guard` 的 step 不属于任何 Skill profile，不生成 Loading Proof；它生成 algorithm execution proof。`owner=skill` 必须有 package trust proof、SkillInvocation、Delivery Receipt 和 Evidence Fragment。

`public_state` 表示完成转移后的目标状态。`correction.route` 只有 `IMPLEMENTING` 一种状态；verification 或 review 产生 correction terminal event 后，系统必须先以单一原子转移切换到 `IMPLEMENTING`，再执行该 step，不允许在 `VERIFYING` 或 `REVIEW_REQUIRED` 状态下借用它。

## 3. 单边 route 规则

- 一个 route 只从一个 decision point 转到一个 next step 或 terminal outcome。
- 同一 decision point 的 facts 必须互斥且完备；`unknown` 默认阻断，不能归入成功分支。
- Skill outcome 不直接改变 public state；包内 route 不能跳到其他包。跨包 public state 和下一入口只由 `contracts/system-lifecycle.contract.json` 转移。
- contract violation 不进入业务 route，Run 失败关闭。
- 合法 `blocked` 保留 artifact；是否等待、回设计或终止由明确 route 决定。

`system-lifecycle.v1` 是唯一跨包事实源，包含 package contract/version、全局初始节点、包终点转移、四个 clarification suspension、correction、handoff/acceptance 等待点、系统终态和 sidecar。每条 transition 只能选择一组 step/node 来源和一个 step/node 目标；Schema 与 graph checker 独立拒绝双来源、无来源、双目标和无目标。validator 将六包 terminal route 与系统处理规则做双向比对；未消费、重复消费、不可达或无出口均失败。

## 4. 需求阶段

```text
start
  -> planning.requirements.analyze
     -> clarification_required: 等待 question_response
     -> blocked: PLANNING blocked
     -> completed + research_requests=nonempty: research
     -> completed + research_requests=empty: finalize
  -> research
     -> completed: finalize
     -> blocked: PLANNING blocked
  -> finalize
     -> clarification_required: 等待 question_response
     -> blocked: PLANNING blocked
     -> completed: planning.design.architecture
```

`analyze` 永远只产 draft、research request set 或 question set，不直接产最终 Requirements Contract；`finalize` 是唯一最终合同生产者，消除旧文档冲突。

question 必须声明 `must_clarify`、`safe_default` 或 `defer`：

- `must_clarify` 阻断，并等待有权限 actor 的 `question_response.v1`。
- `safe_default` 由 Guard 记录默认值、适用边界、过期和回滚触发，不增加人工介入。
- `defer` 必须绑定后续 requirement/decision owner 和最迟决策点，不得影响当前 blocking AC。

Question Set 冻结 `origin_step_id`、`origin_profile_id`、`resume_token`、`frozen_input_set_revision`、`issued_at/expires_at`。收到 response 后，Guard 执行 `planning.requirements.apply_response`，校验 actor、question revision、过期、resume token 单次消费和 input revision，再由 system suspension 精确恢复 `planning.requirements.analyze` 或 `planning.requirements.finalize`。恢复 invocation 必须包含 Response Bundle ArtifactRef；不要求用户再次 begin，也不能统一回到 analyze。

## 5. 研究阶段

Research request 必须由 analyze 的结构化结果产生，包含 claim、为何需要外部事实、允许来源类型和是否支撑 blocking R/AC。

research 只能访问 Guard allowlist，重定向后目标也必须重新验证。Research Record 必须包含 canonical URL、snapshot digest、license/ToS、privacy/secret classification、retention、prompt-injection status、claim mapping 和 verification status。

`unverified` 或许可/隐私不明的 claim 只能进入 Requirements assumptions；若它是 blocking R/AC 的唯一依据，finalize 必须返回 clarification 或 blocked。

## 6. 设计阶段

```text
planning.design.architecture
  -> clarification_required/blocked: 留在 PLANNING
  -> completed + repository_mode=existing: impact
  -> completed + repository_mode=greenfield + approved_pattern=true: pattern
  -> completed + repository_mode=greenfield + approved_pattern=false: finalize
impact
  -> blocked: 留在 PLANNING
  -> completed + approved_pattern=true: pattern
  -> completed + approved_pattern=false: finalize
pattern
  -> completed: finalize
  -> blocked: 留在 PLANNING
finalize
  -> clarification_required/blocked: 留在 PLANNING
  -> completed: planning.phase_gate
planning.phase_gate
  -> passed: IMPLEMENTING/首个 implementing.slice
  -> failed: 回到对应需求或设计 step
```

`planning.design.architecture` 和 `planning.design.finalize` 的 clarification 使用同样的 Question Set 字段，由 `planning.design.apply_response` 校验并精确恢复 origin。两个恢复 step 都必须消费 Response Bundle；impact/pattern 不产生 clarification，因此不进入 suspension 表。

repository mode、approved pattern、path policy 和 check registry 在进入设计前冻结。组件允许多个明确 port/adapter，但必须归属一个 ownership/facade boundary；只有绕过该边界的旁路才是 contract violation。

Solution Design 为每个 slice 指定一个 `slice_kind`、canonical path objects、required checks、顺序键和 correction policy。一个 slice 需要多个 kind 时必须拆分，不能靠多 profile 混载。

## 7. 执行与修复

```text
implementing.slice
  -> completed: implementing.manifest.append
  -> correction_required: correction.route
  -> blocked: IMPLEMENTING blocked
implementing.manifest.append
  -> next_slice: 下一个 implementing.slice
  -> all_slices_complete: VERIFYING/verifying.run
correction.route
  -> retry_current_slice: 同一范围内有限重试
  -> create_bounded_correction: 新的受限 correction slice
  -> return_to_design: PLANNING/planning.design.finalize
  -> blocked: 当前状态 blocked
```

`implementing.slice=completed` 必须同时满足：actual diff 与 record 一致、所有操作属于 lease path objects、所有 required checks 已记录且按冻结 pass policy 通过、workspace revision CAS 成功。只记录失败检查不能完成 slice。

Correction Proposal 不得新增文件对象、依赖、接口、runner、check 或 AC。需要任何扩大时只能 `return_to_design`，提升 design revision 并使受影响下游 evidence 失效。

## 8. 验证与诊断

```text
verifying.run
  -> blocked: VERIFYING blocked
  -> completed + quality_scope=true: verifying.evaluate
  -> completed + quality_scope=false + failures=nonempty: verifying.diagnose
  -> completed + quality_scope=false + failures=empty: verifying.aggregate
verifying.evaluate
  -> blocked: VERIFYING blocked
  -> completed + combined_failures=nonempty: verifying.diagnose
  -> completed + combined_failures=empty: verifying.aggregate
verifying.diagnose
  -> correction_required: correction.route
  -> blocked: VERIFYING blocked
verifying.aggregate
  -> passed: REVIEW_REQUIRED/review.scope
  -> blocked: VERIFYING blocked
```

`verifying.run=completed` 表示注册检查已经可信执行并产出完整结果，不表示检查全通过；通过与否由结果和 `verifying.aggregate` 判断。

runner policy 必须冻结 image digest、command/args/cwd/env、mount、timeout 和 pass policy。验证在隔离 snapshot 上运行；cache、coverage、snapshot 等只能写登记的 ephemeral/output mount。受保护源码 revision 变化才构成 workspace violation。

Evaluation 只有在冻结 `evaluation_policy.v1` 和 anchors 时适用。Diagnosis 必须引用原始 failure event、verification/evaluation digest、source revision 和 implementation manifest。

## 9. 审查与聚合

`review.scope` 是 Guard step，根据 actual diff、path labels、依赖变化、权限、secret、供应链和 Skill/Guard 文件计算：

- correctness 始终适用；
- architecture 在模块边界、依赖、完整性、容量或 public contract 变化时适用；
- security 在信任边界、凭据、权限、网络、依赖供应链、Skill/Guard 变化时适用；
- 任一适用性为 unknown 时按适用处理。

```text
review.scope -> review.correctness
review.correctness completed
  -> architecture applicable: review.architecture
  -> architecture not applicable + security applicable: review.security
  -> both not applicable: review.aggregate
review.architecture completed
  -> security applicable: review.security
  -> security not applicable: review.aggregate
review.security completed -> review.aggregate
any review axis blocked -> REVIEW_REQUIRED blocked
review.aggregate
  -> pass: review.handoff.simplicity 或 review.handoff.final
  -> changes_required: correction.route
  -> block: REVIEW_REQUIRED blocked + 自动 checkpoint
  -> advisory: REVIEW_REQUIRED，不能进入 acceptance
```

审查 axis 的业务发现写入单个 Review Fragment，axis step正常 outcome 为 `completed`；Guard 校验后将 fragment 追加到按 `review_id + axis + revision` 索引的冻结 collection。下一 axis 和 `review.aggregate` 读取该 CollectionRef，而不是直接前一步输出；不能用 `changes_required` 提前短路后续安全轴。`review.aggregate` 根据完整 collection、严重级别、scope coverage 和 reviewer attestation 产生最终 candidate gate；`changes_required` 同时生成受限 Correction Proposal。

Reviewer attestation 由控制面签发并绑定 actor、session、model/build、实现者关系、输入 Evidence Index digest、权限和过期时间。仅字符串 ID 不同不构成独立；无法证明独立时 aggregate 只能 `advisory`。

## 10. Checkpoint、最终交接与接受

`record.checkpoint` 是旁路只读报告 step，可在自动暂停、重试耗尽、等待问题或用户查询状态时运行。它不推进状态，也不要求 verification/review artifact 存在。

最终交接只在 `review.aggregate=pass` 后运行：

```text
simplicity entries present -> review.handoff.simplicity -> review.handoff.final
no simplicity entries      -> review.handoff.final
review.handoff.final completed -> system.awaiting_acceptance
external acceptance decision  -> acceptance.apply
acceptance.apply approved       -> ACCEPTED
acceptance.apply blocked        -> 保持 REVIEW_REQUIRED
```

最终 handoff 的 Requirements、Design、Implementation Manifest、Verification Summary、Review Record 和 Evidence Index 都是必需输入，不再声明 optional。Simplicity Record 只有适用时才必需。

`acceptance.apply` 只接受 `acceptance_decision.v1`，逐 blocking AC 验证 authority scope、actor attestation、evidence revision、过期和 expected run revision。CI 不能批准未在 acceptance policy 中授权的产品/用户 AC。

`acceptance_transition` 不参加 `before_external_acceptance` 的 record 包聚合。它只由 `acceptance.apply=approved` 产生，并由 system lifecycle 的 `SYS-AC-12` 在 `after_acceptance_apply` 检查，避免用未来产物证明当前 gate。

## 11. Evidence Index 与失效

| 变化 | 最小失效范围 |
| --- | --- |
| Requirements revision | 全部 design/implementation/verification/review/handoff/decision |
| Design revision | 受影响 slice 及其 implementation/verification/review/handoff/decision |
| Workspace protected source revision | verification/review/handoff/decision |
| Check/runner/evaluation policy | 对应 verification、diagnosis、review、handoff/decision |
| Skill manifest/render policy/provider delivery | 由该调用产生的 fragment 及所有依赖 artifact |
| Predicate/review scope/actor attestation | 对应 applicability/review/acceptance 结论 |

Correction 不删除旧 evidence；新 artifact 以 `superseded_by` 取代旧结论。Evidence Index 聚合顺序固定为 revision、producer step order、attempt、artifact id；digest 相同去重，结论冲突时阻断而不是最后写覆盖。

Handoff 读取 index revision N；其自身 fragment 只进入 N+1，因此不会被当前 handoff 读取。Acceptance Decision 绑定明确 index revision，任何新失效事件都使 decision 不可用。

## 12. 人工介入、重试和停滞

- 正常路径人工操作：提交任务一次；从任务绑定到最终候选 handoff 不需要 init/begin/checkpoint/Skill 选择。
- 合法人工介入：`must_clarify` 问题答复，以及最终用户批准；其他 intervention 必须记录原因和触发 step。
- 同一冻结 step 最多自动重试 2 次；contract violation、权限逃逸、签名/receipt 失败不重试到宽松模式。
- lease/actor/receipt 过期、两次重试无进展或 route facts 无法确定时，Guard 自动生成 checkpoint 并转 blocked。
- 未来 benchmark 必须记录每 Run 的人工介入次数、自动恢复、重试、停滞时间、context budget、Delivery Receipt 覆盖和边界拒绝率。

## 13. 必需反绕过测试

- 替换 manifest registry、使用未知/撤销签名 key、大小写碰撞或 junction bundle。
- provider 截断上下文、opaque receipt、attestation 缺签名绑定、nonce 重放、消息顺序或 tool schema digest 不匹配。
- manifest 把 payload hash/signature 放入 unsigned payload，或 domain/算法/key usage 不匹配。
- 条件步骤不适用时伪造 N/A；适用性 unknown 时试图跳过。
- failed required check 仍声明 slice completed。
- correction proposal 扩大路径、依赖或 check。
- correctness 发现 changes 后跳过已适用 security axis。
- reviewer 只更换 ID 自审、CI 越权批准业务 AC、Skill 输出 ACCEPTED。

上述场景均应失败关闭，且不得自动降级到 v2、无 Skill、宿主机 runner 或人工手动推进。
