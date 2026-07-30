# requirements-contract v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包把用户任务转换为可追踪的 Requirements Contract，显式记录目标用户、决策责任、范围、风险、问题策略、R/AC 和来源。它不能批准需求、选择研究来源白名单、修改 Run 或自行进入设计。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `intake-and-scope.md` | 目标、required/optional/non-goal、风险、假设、停止条件、R/AC | requirements-analysis、user-story-writing、prd-generator、requirement-grill、intake-review |
| `stakeholders-and-priority.md` | actor、stakeholder、beneficiary、decision owner、优先级和冲突 | stakeholder-mapping、prioritization-framework、multi-perspective-review |
| `research-and-evidence.md` | research request、来源质量、许可/隐私、claim 映射和不可信内容隔离 | web-research、scrapling、aliens-eye、research-source-quality |

analysis profile 加载前两份；research profile 只加载第三份。每个调用不超过两个 references。

## 3. Step-level I/O

| step | 必需输入 | 条件输入 | outcome -> 输出 |
| --- | --- | --- | --- |
| `planning.requirements.analyze` | Request | Project Context、origin 对应的 Response Bundle | `completed` -> Draft + Research Request Set；`clarification_required` -> Draft + Question Set；`blocked` -> Blocking Record |
| `planning.requirements.research` | Draft + Research Request Set + Research Policy | 无 | `completed` -> Research Record；`blocked` -> Blocking Record |
| `planning.requirements.finalize` | Draft | Research Record、Question Response Bundle | `completed` -> Requirements Contract；`clarification_required` -> revised Draft + Question Set；`blocked` -> Blocking Record |
| `planning.requirements.apply_response`（Guard） | Question Set + Question Response | 无 | `response_applied` -> Response Bundle；`blocked` -> Blocking Record |

`analyze` 不得直接产最终合同；`finalize` 是唯一生产者。当前 step 不允许输出表中未声明的 artifact。

所有输入都由 Guard 解析为绑定 artifact ID/revision/digest 的 ArtifactRef；research 后的 finalize 继续读取 analyze 产生的冻结 Draft，而不是把 research 的直接输出误当 Draft。

## 4. Requirements Contract

`artifact.requirements_contract.v2` 至少包含：

```text
actors[{id,role,authority_scope}]
stakeholders[{id,impact,priority}]
beneficiaries[] / decision_owner
objective / observable_outcomes[]
requirements[{id,statement,priority,source_refs[]}]
acceptance_criteria[{
  id,requirement_ids[],criterion,
  preconditions,environment,observer,
  verification_method,threshold,tolerance,
  required_evidence[],blocking
}]
scope{required[],optional[],non_goals[]}
constraints[] / risks[] / assumptions[] / stop_conditions[]
questions[{
  id,class:must_clarify|safe_default|defer,
  owner,default_value,boundary,expires_at,
  rollback_trigger,latest_decision_point,status
}]
research_claims[{claim_id,status,source_refs[],supports[]}]
```

每个 R 至少映射一个 AC；每个 AC 至少映射一个 R。`safe_default` 必须可撤销且不能弱化 blocking AC；`defer` 不得影响当前 phase gate。

## 5. Research Record

每个来源记录 canonical URI、redirect chain、snapshot digest、captured_at、publisher、license/ToS、privacy/secret classification、retention、prompt-injection status、引用片段 digest 和 claim mapping。

`verified` claim 才能支撑 blocking R/AC。`unverified`、许可不明或隐私未处理的 claim 只能进入 assumptions；如果没有其他依据，finalize 必须 clarification 或 blocked。

## 6. 权限与恢复

- analyze/finalize：只读 Guard summary；无网络、命令、runner、browser。
- research：仅 Guard allowlist 网络和 registered target；重定向重新校验；落盘只进入 Guard temp directory。
- Question Response 由外部控制面写入；Guard 校验 actor authority、question revision 和过期后自动恢复，无需人工 begin。
- `artifact.question_set.v2` 必须包含 origin step/profile、单次 resume token、frozen input-set revision 和过期时间。apply 后由 system lifecycle 恢复原 analyze/finalize；恢复 step 必须消费 Response Bundle。

## 7. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `REQ-AC-01` | Requirements Contract schema/ID 有效 | always |
| `REQ-AC-02` | R/AC 双向覆盖且 blocking AC 可执行 | always |
| `REQ-AC-03` | actor、stakeholder、decision owner 和 outcome 完整 | always |
| `REQ-AC-04` | question class/default/response 控制转移 | questions present；否则 Guard 证明无问题 |
| `REQ-AC-05` | research provenance、许可、隐私和注入状态完整 | research executed；否则 Guard 证明未请求研究 |
| `REQ-AC-06` | blocking external claims 全部 verified | blocking external claims present；否则 Guard 证明不存在 |
| `REQ-AC-07` | 未验证 claim 未支撑 blocking R/AC | always |
| `REQ-AC-08` | 所有 Skill step 有有效 Delivery Receipt 和 Evidence Fragment | always |

聚合方式为 `all_applicable`；N/A 只能由 Guard predicate 生成 evidence。包级验收在 external acceptance 前聚合，不隐藏成 planning 阶段的独立人工审查。
