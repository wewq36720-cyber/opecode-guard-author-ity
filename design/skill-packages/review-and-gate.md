# review-and-gate v3.3

## 1. 目标与边界

唯一代理入口为 `SKILL.md`。本包只读审查冻结 revision。Skill step 只生成单轴 Review Fragment；适用轴由 Guard 决定，最终候选门禁由 Guard 聚合。本包不能写项目文件、跳过其他轴、修改严重级别 registry 或产生 ACCEPTED。

## 2. 内部 references

| reference | 职责 | 来源 Skill |
| --- | --- | --- |
| `correctness-and-completeness.md` | bug、范围、R/AC、失败路径、完整性 | code-review、code-review-quality-gate、project-completeness-check、scope-alignment-review |
| `architecture-and-maintainability.md` | ownership、依赖、容量、可维护性和过度设计 | architecture-audit、kb-coverage-scan、ponytail-audit、ponytail-review |
| `security-and-supply-chain.md` | secrets、输入、权限、依赖、Skill/Guard 信任 | secret-scan-review、security-review、skill-quality-audit、skill-security-audit |

## 3. Step-level I/O

| step | owner | 必需输入 | outcome -> 输出 |
| --- | --- | --- | --- |
| `review.scope` | Guard | actual diff、Design、path/dependency/security labels | `completed` -> Review Scope；`blocked` -> Blocking Record |
| `review.correctness` | Skill | frozen packet + Evidence Index + Scope + Reviewer Attestation | `completed` -> correctness Fragment；`blocked` -> Blocking Record |
| `review.architecture` | Skill | 同上 + frozen Review Fragment Collection | `completed` -> architecture Fragment；`blocked` -> Blocking Record |
| `review.security` | Skill | 同上 + frozen Review Fragment Collection | `completed` -> security Fragment；`blocked` -> Blocking Record |
| `review.aggregate` | Guard | Scope + frozen Review Fragment Collection + Reviewer Attestation | `pass/block/advisory` -> Review Record；`changes_required` -> Review Record + Correction Proposal |

## 4. Scope 与不短路规则

correctness 始终适用。architecture/security 由 Guard 根据实际变更计算；unknown 默认适用。Skill 和上游 artifact 不能提交 scope boolean。

每个轴正常 outcome 只有 `completed`，findings 和建议 disposition 写在一个 fragment 内。Guard 校验后以 CAS 追加到按 `review_id + axis + revision` 索引的 collection；后续轴与 aggregate 读取冻结 CollectionRef，因此不会只看到最后一轴。即使 correctness 已发现必须修改，已适用 architecture/security 仍执行；只有 contract violation、输入完整性失败或无法读取证据才可 blocked。

## 5. 独立性

`identity.reviewer_attestation.v2` 由控制面签发，包含 actor、session、model/build、implementer relationship、input Evidence Index digest、authority scope、issued/expires 和证明。字符串 `reviewer_id` 不足以证明独立。

无法证明独立时允许生成审查材料，但 `review.aggregate` 只能 advisory，不能进入 final handoff 或 acceptance。

## 6. Review Record

Guard 聚合时验证 scope coverage、fragment digest、finding evidence、严重级别、重复 finding、required actions、independence 和 source revision。聚合算法固定：任何 blocking finding -> block；任何 required change -> changes_required；仅非阻断建议且独立性不足 -> advisory；全部适用轴通过且独立性满足 -> pass。

## 7. 逐包验收

| ID | assertion | applicability |
| --- | --- | --- |
| `REV-AC-01` | Review Scope 由 actual diff/registry 决定，unknown 默认适用 | always |
| `REV-AC-02` | 所有适用轴都有恰好一个有效 fragment | always |
| `REV-AC-03` | findings 绑定具体 artifact/diff/evidence | findings present；否则证明 no findings |
| `REV-AC-04` | aggregate 与 severity/coverage 算法一致 | always |
| `REV-AC-05` | reviewer attestation 绑定 session/model/input digest，独立性不足仅 advisory | always |
| `REV-AC-06` | 审查全过程只读且未运行未注册命令 | always |
| `REV-AC-07` | 一个轴不能覆盖或跳过另一个适用轴 | multiple axes；否则 N/A |
| `REV-AC-08` | Review Record 只产生 candidate gate，所有 Skill step 有 Delivery Receipt | always |
