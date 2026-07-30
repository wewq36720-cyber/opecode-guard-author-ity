# execute-in-slices v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包一次只执行一个冻结 slice，并报告真实 diff、工具事件和 required checks。只有本包的 Skill step 可在有效 lease 下请求写项目文件；它不能扩大 lease、修改冻结设计、伪造工具结果或批准完成。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `slice-discipline.md` | 增量实现、TDD、简洁实现、来源约束 | incremental-implementation、tdd、clean-code、source-driven-development、ponytail |
| `integration-patterns.md` | JSON、prompt、cache、CopilotKit 集成 | json-mode-patterns、prompt-engineering、prompt-caching-patterns、copilotkit-integration |
| `change-safety.md` | refactor/security 不变量 | refactor、security-hardening |
| `ui-slice-patterns.md` | UI 组件和动画 slice 约束 | ui-component-library、ui-animation |

standard 只加载 slice-discipline；其他 profile 再加载一个对应 reference。

## 3. Step-level I/O

| step | 必需输入 | outcome -> 输出 |
| --- | --- | --- |
| `implementing.slice` | Requirements + Design + current Slice + Write Lease + Workspace Snapshot + Check Registry | `completed` -> Implementation Record；`correction_required` -> attempted Implementation Record + Correction Proposal；`blocked` -> Blocking Record |
| `implementing.manifest.append`（Guard） | Implementation Record + Design | `completed` -> ordered Implementation Manifest；`blocked` -> Blocking Record |
| `correction.route`（Guard） | Correction Proposal + Design + Workspace Snapshot | `retry_current_slice/create_bounded_correction/return_to_design` -> Correction Decision；`blocked` -> Blocking Record |

## 4. Completion Gate

`implementing.slice=completed` 必须同时满足：

1. write lease 未过期并绑定 workspace-before revision；
2. actual operation-level diff 与 Implementation Record 一致；
3. create/modify/delete/rename 均属于冻结 path objects；
4. 所有 required checks 均有可信 tool event；
5. 每个 required check 满足冻结 pass exit policy；
6. workspace-after CAS 成功；
7. 没有修改 Requirements、Design、registry、Run 或 approval。

`checks_recorded` 和 `required_checks_passed` 是两个独立 assertion。检查失败只能产生 Correction Proposal 或 Blocking Record。

## 5. Implementation Record 与 Manifest

Record 包含 slice/design revision、before/after workspace digest、operation diff、tool event digests、check results、remaining risk 和 proposal refs。即使需要 correction，也必须先记录本次真实 diff/tool events，不能只有 Proposal。Manifest 只追加 `completed` slice，按 slice order/revision/attempt 保存记录；correction attempt 保留在 Evidence Index，成功 correction 后再 supersede，不删除历史。

## 6. Correction 规则

Correction Proposal 必须引用失败 evidence、父 slice 和设计允许的 path/check 集合。Guard 只能有限重试、建立有界 correction 或返回设计；不能从自然语言建议自动扩大权限。

## 7. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `EXE-AC-01` | write lease、workspace CAS 和 path identity 有效 | every slice |
| `EXE-AC-02` | actual operation diff 属于冻结 slice | completed slices |
| `EXE-AC-03` | 每次 invocation 只实现一个 slice 且没有旁路写 | every slice |
| `EXE-AC-04` | tool events 与 Implementation Record digest 一致 | completed/correction slices |
| `EXE-AC-05` | 所有适用 required checks 已记录且通过 | completed slices |
| `EXE-AC-06` | security/refactor 不变量通过 | corresponding slice kind；否则 N/A |
| `EXE-AC-07` | Correction Proposal 未扩大 design/path/check | correction present；否则 N/A |
| `EXE-AC-08` | 已完成 slice 的 Manifest 完整且相关 Skill step 有 Delivery Receipt | completed slices；否则 N/A |
