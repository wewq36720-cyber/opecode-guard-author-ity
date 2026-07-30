# verify-and-diagnose v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包执行冻结 checks/evaluation，保存可复查结果，并在失败时生成有界 Correction Proposal。它不修改项目源码、不更换 runner、不批准实现，也不把“命令执行完成”解释为通过。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `verification-strategy.md` | test/lint/typecheck/build/smoke/browser 的注册执行和覆盖 | testing-strategies、eval-harness、playwright-testing、browser-devtools-testing |
| `diagnosis-and-stability.md` | 分类、复现、根因、flaky/null/pipeline 追踪 | debug、flaky-test-debugging、null-chain-detect、pipeline-trace |
| `model-and-retrieval-evaluation.md` | 冻结 sample/anchor/metric/judge 的模型与 RAG 评测 | llm-judge-eval、rag-eval |

## 3. Step-level I/O

| step | 必需输入 | 条件输入 | outcome -> 输出 |
| --- | --- | --- | --- |
| `verifying.run` | Implementation Manifest + Records + Check Registry + Runner Policy + Workspace Snapshot | 无 | `completed` -> Verification Run；`blocked` -> Blocking Record |
| `verifying.evaluate` | Verification Run + Evaluation Policy + Anchors | 无 | `completed` -> Evaluation Record；`blocked` -> Blocking Record |
| `verifying.diagnose` | Failure Event Set + Verification/Evaluation digest + Manifest | 无 | `correction_required` -> Diagnosis Record + Correction Proposal；`blocked` -> Diagnosis Record + Blocking Record |
| `verifying.aggregate`（Guard） | Verification Run | Evaluation Record | `passed` -> Verification Summary；`blocked` -> Blocking Record |

## 4. Runner 与 Workspace

Runner Policy 冻结 image digest、command、args、cwd、environment allowlist、input/output mounts、timeout 和 pass policy。要求 Docker 的 check 不得回退宿主机。

验证运行在隔离 snapshot；cache、coverage、snapshot、报告等只能进入登记的 ephemeral/output mount。`workspace_stable` 比较受保护 source revision，而不是禁止所有测试生成物。

## 5. Evaluation 与 Diagnosis

`evaluation_policy.v1` 包含 sample/anchor digest、metric、scale、threshold、judge model/build、prompt digest、重复次数和 decision weight。缺少任何冻结项时 evaluate 不适用或 blocked，不能临时选择 judge。

Diagnosis Record 必须引用原始 failure event IDs、source revision、manifest digest、最小复现、分类、flaky 状态、root-cause confidence 和 next action。Correction Proposal 仍受原 Design correction policy 限制。

## 6. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `VER-AC-01` | 所有 required checks 完整执行并判定 pass/fail | always |
| `VER-AC-02` | runner command/env/mount/image/pass policy 未变化 | always |
| `VER-AC-03` | protected source revision 稳定，生成物位于允许 mount | always |
| `VER-AC-04` | 每个 blocking AC 有实际 verification coverage 或明确 unsupported blocker | always |
| `VER-AC-05` | Diagnosis 可追溯到原始 failure 和 manifest | failures present；否则 N/A |
| `VER-AC-06` | Evaluation 使用冻结 samples/metrics/judge/anchors | quality scope；否则 N/A |
| `VER-AC-07` | Correction Proposal 未扩大设计且 diagnosis 可追溯 | correction present；否则 Guard 证明无 proposal |
| `VER-AC-08` | 所有 Skill step 有 Delivery Receipt 和有效 Evidence Fragment | always |
