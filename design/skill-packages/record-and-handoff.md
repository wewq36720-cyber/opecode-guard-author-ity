# record-and-handoff v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包从一个冻结 Evidence Index 生成阶段 checkpoint、simplicity record 和最终 handoff。它不重新验证、不拼接不同 revision、不隐藏 blocker、不修改历史，也不能批准自身工作。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `evidence-and-decisions.md` | evidence/decision 的引用、状态与历史边界 | architecture-decision、material-format、vector-maintain |
| `completion-and-handoff.md` | 完成、未完成、验证、风险、复查和下一动作 | completion-report、handoff |
| `simplicity-ledger.md` | 已记录的简化收益、债务和边界，不创造新事实 | ponytail-debt、ponytail-gain、ponytail-help |

## 3. Step-level I/O

| step | 必需输入 | 条件输入 | outcome -> 输出 |
| --- | --- | --- | --- |
| `record.checkpoint` | Evidence Index | 当前已有 Requirements/Design/Manifest/Verification/Review | `completed` -> checkpoint Handoff；`blocked` -> Blocking Record |
| `review.handoff.simplicity` | Evidence Index + Simplicity Entries | 无 | `completed` -> Simplicity Record；`blocked` -> Blocking Record |
| `review.handoff.final` | Evidence Index + Requirements + Design + Implementation Manifest + Verification Summary + Review Record | Simplicity Record | `completed` -> final Handoff；`blocked` -> Blocking Record |
| `acceptance.apply`（Guard） | Evidence Index + Review Record + final Handoff + Acceptance Decision + Acceptance Policy | 无 | `approved` -> Acceptance Transition Record；`blocked` -> Blocking Record |

最终 handoff 的上游 artifact 全部必需；只有 checkpoint 可消费部分进度。Simplicity 仅在 entries 存在时适用。

## 4. Handoff 结构

`artifact.handoff.v2` 包含 report kind、source Evidence Index ID/revision、completed/blocked/advisory 分区、R/AC coverage、验证摘要、review disposition、风险、决策、下一动作、复查命令/路径和 claim evidence refs。

每个 claim 必须引用 Evidence Index 中的有效 artifact。Handoff 消费 index N，自身 fragment 只进入 N+1，避免自引用。

## 5. Acceptance Decision

外部控制面提交 `artifact.acceptance_decision.v1`，逐 blocking AC 声明 actor role、authority scope 和 decision，并绑定 candidate review、index revision、签名/来源、签发/过期和 expected Run revision。

`acceptance.apply` 是 Guard step。它验证证据未失效、全部 blocking AC 获授权决定、CAS 成功后才产生 Acceptance Transition；system lifecycle 再写 `ACCEPTED`。CI 只能批准 policy 授权的技术 AC；用户/产品 AC 不能被 CI 默认替代。

## 6. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `REC-AC-01` | 报告只消费一个冻结 Evidence Index revision | always |
| `REC-AC-02` | 每个 claim 可追溯且没有孤立事实 | always |
| `REC-AC-03` | completed/blocked/advisory/unknown 分区准确 | always |
| `REC-AC-04` | checkpoint 明确阶段且不冒充 final | checkpoint；否则 N/A |
| `REC-AC-05` | final 覆盖 Requirements/Design/Manifest/Verification/Review 和全部 blocking AC | final；否则 N/A |
| `REC-AC-06` | 历史不可改写，handoff 无自引用 | always |
| `REC-AC-07` | Simplicity Record 不删除职责、安全或 AC | simplicity entries；否则 N/A |
| `REC-AC-08` | 预接受 Handoff 不包含 acceptance 或自批结论 | always；实际 transition 由 system `SYS-AC-12` 在 apply 后验证 |

聚合为 `all_applicable`。Checkpoint、final、simplicity 和 acceptance 的条件验收分别有 Guard applicability evidence，不再因 optional artifact 缺失而死锁。
