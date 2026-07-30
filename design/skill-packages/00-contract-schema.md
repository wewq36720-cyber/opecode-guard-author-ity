# 六包统一契约 v3.3

本文件定义未来六个外置 Skill 包共同遵守的 `skill-contract.v3` 修正版。六份包契约版本为 `3.3.0`；它与 v3.2、v3.1、旧 v3 草案及 v2 均不兼容。调用级 artifact cardinality 下沉到 step/outcome；验收改为 `all_applicable`；Skill step 与 Guard-owned deterministic step 分离；完整性 hash 之外增加来源信任、实际投递收据和外部接受事件。

## 1. 责任边界

```text
<skill-id>/
├── SKILL.md                 # 唯一代理入口
├── contract.json            # Guard-facing 机器契约
├── agents/openai.yaml       # UI 元数据，不参与门禁
├── references/              # 一层目录，每个文件一个稳定职责
└── scripts/                 # 可选，只放受注册的确定性检查
```

- `SKILL.md` 只能执行 Guard 已冻结的一个 Skill step。
- `contract.json` 是机器事实源，但不能替代 Guard 的 schema、predicate、route、actor、runner 和 trust registry。
- references 不互相读取，只消费 invocation 中声明的 artifact。
- scripts 不能自行选命令、runner、工作目录或环境变量。
- Skill、reference 和 script 均不能修改 Run 状态、批准、版本、profile、reference、路径或权限。
- “一个公开入口”指一个稳定 ownership/facade boundary；允许同一边界下存在有界 adapter/port，不允许绕过公开契约建立旁路。

## 2. 顶层结构

未知顶层字段拒绝。六份契约只允许：

```json
{
  "schema_version": "skill-contract.v3",
  "skill": {},
  "trust": {},
  "artifact_catalog": [],
  "lifecycle": {},
  "reference_catalog": [],
  "profiles": [],
  "permissions": {},
  "evidence": {},
  "acceptance": {},
  "errors": {},
  "upgrade": {}
}
```

`skill` 必填 `id`、`version`、`stage`、`entrypoint`。目录名必须等于 `id`，修正版版本为 `3.3.0`，入口只能是 `SKILL.md`。

## 3. 包信任：真实性先于完整性

安装器必须先生成 `unsigned_manifest`，再生成 detached signature envelope。hash/signature 字段绝不进入被 hash 的 payload：

```text
unsigned_manifest{
  schema: package-manifest.v2
  skill_id / skill_version / contract_schema
  canonicalization_policy_id
  files[{normalized_relative_path,role,byte_length,sha256}]
  installer_id / installed_at
}
signature_envelope{
  payload_type: package-manifest.v2
  payload_hash_algorithm: sha256
  payload_hash
  signature_algorithm: ed25519
  key_id / signature / signed_at
}
```

规范化使用 RFC 8785 JSON Canonicalization Scheme 的 UTF-8 bytes。`payload_hash = SHA-256(UTF8("opencode.skill-manifest.v2") || 0x00 || JCS(unsigned_manifest))`；签名载荷为 `UTF8("opencode.skill-manifest-signature.v1") || 0x00 || payload_hash_bytes`。`payload_hash` 和整个 `signature_envelope` 均在 `unsigned_manifest` 外，消除自引用。验证顺序固定为：严格解析/schema -> JCS -> 重算 payload hash -> trust store/key usage -> key revocation/time -> Ed25519 signature -> registry approval record -> bundle file/path/hash -> atomic install。任一步失败即拒绝。

`trust` 必须声明：

```text
manifest_schema: package-manifest.v2
canonicalization_policy_id
signature_policy_id
trust_store_id
revocation_policy_id
registry_record_required: true
atomic_install_required: true
```

Guard 只有同时满足以下条件才可把包标记为 trusted：

1. 路径按冻结 policy 规范化：UTF-8、`/` 分隔、禁止绝对路径和 `..`、拒绝大小写碰撞、ADS、junction、symlink、hardlink 和其他重解析点。
2. canonical bytes、文件列表、role、长度和 hash 与 manifest 一致。
3. manifest 签名由 trust store 中未撤销 key 验证。
4. 只读 registry 中存在相同 `skill_id/version/manifest_hash/signature key` 的批准记录。
5. 安装目录通过原子 rename 切换，验证期间和 Run 冻结后不可原位修改。

hash 只证明“当前内容等于受信预期值”；没有签名和 registry 预期值时不得称为 trusted。撤销影响新 Run；已运行 Run 按冻结 policy 决定立即阻断或迁移，不能静默换版本。

## 4. Artifact catalog 与公共封套

`artifact_catalog` 只登记本包会引用的逻辑名、schema 和生产责任，不声明某次调用是否必需：

```text
artifact_catalog[]:
- name
- schema_id
- producer: skill | guard | external_control
```

调用级必需性只能写在 step 的 `inputs` 和 `outputs_by_outcome`。所有 artifact 使用：

```text
artifact_id / schema_id / schema_version
run_id / producer_step / producer_owner / revision
input_refs[{artifact_id,digest}]
payload / digest / created_at
validity{
  source_revision,
  requirements_revision,
  design_revision,
  workspace_revision,
  registry_revisions{},
  expires_at,
  invalidated_by[],
  superseded_by
}
```

`superseded_by` 必须是 schema 字段。历史 artifact 不删除；Evidence Index 只把当前有效且未被 supersede 的 artifact 计入当前结论。

Step 输入不直接嵌入“latest”对象，而是由 Guard 在 invocation 冻结以下引用：

```text
ArtifactRef.v1{
  artifact_id / schema_id / producer_step_id / producer_owner
  revision / digest / evidence_index_id / evidence_index_revision
  validity_digest / frozen_at
}
ArtifactCollectionRef.v1{
  collection_id / schema_id / revision / digest
  index_keys[] / member_refs[ArtifactRef.v1]
  evidence_index_id / evidence_index_revision / frozen_at
}
```

同一个 invocation 中引用的 Evidence Index revision 必须一致。`ArtifactRef` 的 revision/digest 不匹配、producer 不在 contract allowlist、collection member 缺失/重复/乱序或 validity 失效都阻断。`previous_step` 只可能表示直接前一步的单一输出，但 v3 修正版不再使用它承载历史输入；跨中间 step 的输入一律从冻结 run artifact index 解析。

## 5. Step-level I/O

每个 lifecycle step 使用以下结构：

```text
lifecycle.steps[]:
- step_id
- owner: skill | guard
- kind: primary | support | aggregate | report | transition
- public_state | public_states
- preconditions[]
- allowed_outcomes[]
- profile_ids[]                  # owner=guard 时必须为空
- inputs[]:
  - artifact
  - cardinality: one | optional | ordered_many
  - source:
      kind: artifact_ref | artifact_collection_ref
      authority: skill | guard | external_control | skill_or_guard
      producer_step_ids[]
      revision: invocation_frozen
      digest: required
      collection_id / index_keys[]   # collection 时必填
- outputs_by_outcome{}:
  <outcome>:
  - artifact
  - cardinality: one | optional | ordered_many
  - source: skill | guard
- exit_assertions_by_outcome{}
```

规则：

- `owner=skill` 才构造 SkillInvocation，且必须选择一个 profile。
- `owner=guard` 只能调用版本化 deterministic algorithm，不加载 Skill，profile 必须为空。
- 每个 allowed outcome 必须在 `outputs_by_outcome` 和 `exit_assertions_by_outcome` 中存在。
- 当前 invocation 只校验当前 step/outcome 的 I/O；不得从包级 catalog 推导必需输出。
- `cardinality=ordered_many` 必须使用 `artifact_collection_ref`；其他 cardinality 必须使用 `artifact_ref`。Skill 无权追加集合；Guard 以 CAS 将合法输出加入新 collection revision。
- 不属于当前 outcome 的 artifact 禁止出现，避免 Skill 伪造未来步骤结果。
- `blocked`、`clarification_required`、`correction_required` 等合法结果必须产生结构化 blocking/question/correction artifact。

## 6. Route 作为单边转移

v3 route 不再一次打包多个 substeps。包契约 route 只描述包内下一跳或向系统编排器返回一个 package terminal event：

```text
lifecycle.routes[]:
- route_id
- decision_point: start | after:<step_id>
- facts                         # Guard 已冻结的枚举事实，必须包含 outcome
- next:
    step_id
    profile_id                  # Guard step 为 null
  或
    terminal_outcome              # package event，不是跨包下一跳
- selection: exactly_one
```

同一 decision point 的 facts 必须互斥且覆盖 registry 中有限 domain 允许的全部组合；unknown 不能落入默认成功路径。route facts 只能来自 decision point 前已冻结的 artifact 或 Guard registry，不能依赖未来输出。合法 outcome 必须有唯一下一跳或 package terminal event；contract violation 不走业务 route，直接失败关闭。

route 完备性不是“遍历现有 route 后自洽”即可满足：validator 从每个 package 的 `start` 和每个 step 派生必需 decision group。缺失任一 start、中间或 terminal group 直接失败；每组仍必须覆盖该 step 的全部 outcome 和已声明 fact domain，且每个有限组合只有一个目标。

跨包转移只允许出现在 `system-lifecycle.v1`。每条 transition 的来源必须且只能是 `from_step_id + terminal_outcome` 或 `from_node_id + event_id`，目标必须且只能是 `next_step_id` 或 `next_node_id`；Schema 和 graph checker 分别执行 XOR，禁止一条契约同时表示执行 step 和停留/进入 node。六个 package contract 不得声明其他 package 的 step 为 next。

## 7. Profile 与上下文容量

- 每个 Skill step 只能有一个冻结 profile；每个 profile 加载一至两个 references。
- Guard step 不加载 profile/reference。
- profile 只能绑定声明的 step；模型看不到候选版本、profile 或 reference 列表。
- `render_policy.v1` 冻结消息顺序、入口、reference、artifact summary、tool schema、byte 上限和 provider token estimate 上限。
- 默认设计预算：完整 rendered Skill context 不超过 64 KiB；超限必须由 Guard 生成新的有损/无损摘要 artifact 并重新冻结，禁止 provider 静默截断。

## 8. Invocation、Delivery Receipt 与 Result

Guard 对 Skill step 构造 `SkillInvocation.v2`：

```text
run_id / step_id / attempt / input_set_digest
skill_id / skill_version
manifest_hash / signature_key_id / contract_hash / load_set_hash
profile_id / selected_references[{id,path,sha256}]
input_artifacts[{artifact_id,schema_id,digest,location}]
allowed_path_objects / network_policy / check_ids / runner_policy
render_policy_id / context_budget
actor_id / issued_at / expires_at
```

Guard 在调用 provider 后生成 `artifact.delivery_receipt.v2`。它必须包含 provider 对实际接收内容的 detached attestation，不接受 opaque receipt ID：

```text
invocation_digest
rendered_context_digest / message_sequence_digest / tool_schema_digest
delivered_bytes / estimated_tokens / budget
provider_id / provider_build / session_id / request_nonce
truncation: false
delivered_at
```

并附加以下可验证字段：

```text
provider_id / provider_build / session_id / request_nonce
provider_attestation{
  payload_type: provider-delivery.v1
  payload_hash_algorithm: sha256
  payload_hash
  signature_algorithm / issuer_key_id / signature
  issued_at / expires_at
}
```

attestation unsigned payload 精确为 `{provider_id,provider_build,session_id,request_nonce,invocation_digest,rendered_context_digest,message_sequence_digest,tool_schema_digest,delivered_bytes,estimated_tokens,budget,truncation,issued_at,expires_at}` 的 RFC 8785 bytes。`payload_hash = SHA-256(UTF8("opencode.provider-delivery.v1") || 0x00 || JCS(payload))`，signature payload 使用 `opencode.provider-delivery-signature.v1` 域。Guard 验证 provider trust store、key usage/revocation、signature、时效、nonce 单次消费和所有本地 digest/计数相等。

兼容矩阵：`signed_attestation` 可执行强制 Skill step；`trusted_local_bridge` 只有在受信本地 bridge 对同一 payload 签名且证明 provider session 绑定时可执行；`opaque_receipt`、`local_render_only`、`unsupported` 均返回 `DELIVERY_UNVERIFIED` 并阻断。发生截断、缺字段或重放时同样阻断；不能用 `skill_loaded=true`、模型复述或本地 render hash 代替实际投递证明。

Skill 返回 `SkillResult.v2`：

```text
run_id / step_id / attempt / invocation_digest
outcome
output_artifacts[{logical_name,schema_id,payload}]
obligations[{assertion_id,evidence_refs[]}]
findings / unresolved / proposed_next_step
```

Guard 重算输出 digest、校验当前 outcome I/O 和 obligation。`proposed_next_step` 只是建议；出现 Run 状态写入、权限扩大、版本替换、审查轴选择或 `ACCEPTED` 均为 contract violation。

## 9. 权限与路径对象

权限字段保持能力白名单：

```text
project_files: none | guard_summary | allowed_read_objects | lease_write_objects
network: deny | guard_allowlist
commands: deny | registered_checks_only
runner: none | registry_selected
browser: deny | registered_target_only
temp_artifacts: deny | guard_directory
run_state / approval / version_selection / profile_selection / reference_selection: deny
```

这些控制字段由 validator 作为不变量重新检查，不能只依赖 schema 的字段形状：`self_test_is_acceptance` 必须为 `false`，acceptance `aggregation` 必须为 `all_applicable`，trust 的 `registry_record_required` 和 `atomic_install_required` 必须为 `true`。reference catalog 的路径必须是 bundle 内 canonical `references/<name>.md`，profile 只能选择已登记且一至两个 references，受保护权限在 default 和 step override 中都只能是 `deny`。

文件权限不得使用未经解析的字符串路径。`path.object.v1` 至少包含：workspace identity、canonical root-relative path、case-fold key、operation（read/create/modify/delete/rename）、resolved file identity、reparse/hardlink 状态和 source revision。rename 同时验证源和目标；生成物只能进入 runner policy 明确的 ephemeral/output mount。

`registered_checks_only` 同时冻结 command、args、cwd、environment allowlist、input/output mounts、timeout、pass exit policy 和 image digest。Skill 不能改参数或把 Docker check 回退到宿主机。

## 10. 验收适用性

逐包验收结构：

```text
acceptance:
  evaluation_point: before_external_acceptance
  aggregation: all_applicable
  criteria[]:
  - id
  - assertion_id
  - verifier_authority_id           # 必须解析到 guard registry
  - evidence_schema_ids[]
  - applicability_predicate
  - not_applicable_assertion_id
  - blocking: true
  self_test_is_acceptance: false
```

- applicability 只由 Guard predicate registry 计算，并生成 `artifact.applicability_evidence.v1`。
- `true` 时必须满足 assertion；`false` 时必须满足 not-applicable assertion；`unknown` 阻断。
- 包级 AC 在 `before_external_acceptance` 聚合，不隐式阻断早期 phase。step/phase 推进只使用 step exit assertions 和显式 phase gate。
- “完整、合理、高质量”等自由文本不能作为 assertion；predicate registry 必须冻结输入 schema、算法版本和 hash。

## 11. Correction、Review 与 Acceptance

`artifact.correction_proposal.v1` 必须包含：失败 evidence refs、父 requirements/design/slice revision、建议操作、允许 path objects、required checks、slice kind、顺序键和为何不扩大范围。Guard 只能产生：

- `retry_current_slice`：同一冻结范围内有限重试；
- `create_bounded_correction`：冻结设计已明确允许的修复；
- `return_to_design`：需要新增路径、依赖、接口、check 或改变 AC；
- `blocked`：证据不足或冲突。

Review scope 由 Guard 根据 actual diff、依赖、权限、secret、供应链和 Skill/Guard 标签生成；unknown 默认适用。各审查轴只生成 fragment，不能提前终止其他适用轴；`review.aggregate` 是 Guard step。

最终外部控制面提交 `artifact.acceptance_decision.v1`：

```text
run_id / candidate_review_id / evidence_index_id / evidence_revision
decisions[{acceptance_id,decision,actor_role,authority_scope}]
actor_attestation / source / signature_or_provider_proof
issued_at / expires_at / expected_run_revision
```

Guard 验证所有 blocking AC 均获有权限的有效决定、证据未失效且 compare-and-swap revision 相同后，才可写 `ACCEPTED`。CI 只批准其 policy 声明的技术 AC；不得默认代替产品/用户批准。

## 12. Evidence 与失效

证据链为：

```text
package trust proof
  -> SkillInvocation
  -> Delivery Receipt
  -> SkillResult + tool events
  -> Evidence Fragment
  -> revision-filtered Evidence Index
  -> Review Record / Handoff
  -> external Acceptance Decision
```

Evidence Fragment 必须绑定 invocation、delivery、输入输出、actor、tool event 和 validity。Evidence Index 由 Guard 按依赖图、revision 和 superseded 状态确定性聚合；Skill 只能读取冻结 index。

Review Fragment 不是 Skill 可写的 `ordered_many` 输入。每个 axis 只产一个 fragment；Guard 在校验 axis/result/attestation 后以 CAS 追加到 `review-fragments:<review_id>` collection，新 revision 绑定 `review_id + axis + fragment revision`。后续 axis 与 `review.aggregate` 都只读取冻结 `ArtifactCollectionRef.v1`，因此不会丢失前序轴。

失效规则至少覆盖：需求、设计、workspace、check registry、runner image、Skill manifest、predicate、review scope、actor attestation 和 acceptance policy。Handoff 不进入其所消费的 Evidence Index；新 handoff 的 fragment 只进入下一 revision，避免自引用。

## 13. 错误、重试和升级

- 合法业务 outcome：`completed`、`clarification_required`、`correction_required`、`changes_required`、`blocked`、`advisory`、`approved`。
- contract violation：输入/输出 schema 错误、未知字段、包/签名/receipt 失败、profile/route 错误、路径/runner 逃逸、冻结值修改、伪造 actor/tool event、自批准。
- contract violation 不自动回退到旧版、无 Skill、宽松 profile 或宿主机 runner。
- 同一冻结 step 最多自动重试两次；输入变化必须新 attempt。达到上限或无进展时 Guard 自动 checkpoint 并阻断。
- 契约、入口、reference、script、artifact schema、predicate、trust 或验收语义变化都需要新版本、新 manifest 和独立迁移审查。

## 14. Registry 与设计期验证接口

`contracts/guard-registry.json` 是唯一 registry 组件索引，八类事实分别放在 `contracts/registries/`：authority、algorithm、fact domain、predicate、assertion、artifact schema、schema attestation 和 crypto policy。组件文件不是第二套公共接口；消费者必须先校验 index 与 `guard-registry.v1.schema.json`，再按 index 中的相对路径加载组件，并校验 `guard-registry-component.v1.schema.json`、kind 唯一性和所有跨引用。组件路径只能位于 `contracts/registries/`，不能逃逸或由目录扫描隐式补全。

registry 的 crypto policy 不是可替换标签：manifest、provider delivery 和 schema registry policy 必须分别保持登记的 JCS、SHA-256、Ed25519/registry-selected 和 domain 组合；每个 package 的 `signature_policy_id` 必须精确为 `skill-signature-ed25519.v1`，已登记但属于 provider、schema registry 或其他域的 policy 不能用于 package manifest。`guard.acceptance` 必须是 `acceptance_validator` 且只能验证 `acceptance_assertion`；`SYS-AC-12` 必须使用 `acceptance_transition_post_apply` 并由 `guard.acceptance` 验证，该 assertion 的 `authority_ids` 也必须精确为 `guard.acceptance`。任何 hash/signature/authority weakening 或跨域错绑都失败关闭。所有 package/system profile、AC、route/step、transition、suspension 和 package binding ID 在对应命名空间内唯一，重复项在构造索引前报告 namespace-aware 错误。

artifact schema 条目只有两种状态：

- `defined`：绑定 `schema_path + fragment + schema_uri + file_sha256`。validator 限制路径只能位于本设计的 `schemas/`，复算文件 SHA-256，解析 `#` 或本地 JSON Pointer fragment，并要求目标 `$id`、registry `schema_uri` 和由 artifact ID 推导的 canonical URI 完全一致；同一 `(path, fragment)` 只能绑定一个 ID。
- `external_registered`：绑定 registry ID、SemVer version、canonical HTTPS schema URI、schema digest 和 registry attestation ID。原始 URI 必须在解析前精确以小写 `https://` 开头且完全不含 `?`、`#`，因此空 query/fragment 分隔符也非法；不接受先规范化 scheme 再查重。URI path 的每个 segment 只允许 RFC 3986 `pchar` 中的 unreserved、sub-delims、`:` 和 `@`，`/` 只作分隔符；当前策略禁止 `%`，因此不接受 percent-encoded 形式。可打印 ASCII 和 `urlsplit()` 的解析结果都不是 canonical 合法性的充分条件。attestation registry 记录 issuer authority、signature policy、trust store、attestation URI 和 external binding set digest，并明确 `runtime_required/unverified`。设计期 validator 只证明绑定字段、URI 规范化和信任描述完整且一致；未来 runtime 必须验证 attestation 签名、trust store 和下载内容 digest。无法验证时阻断，不能把设计期结构检查称为外部 schema 真实性证明。

设计期验证只公开一个命令：

```powershell
python design/skill-packages/validation/validate_contracts.py
```

入口内部职责固定为：`validate_contracts.py` 只负责标准库 snapshot、隔离启动、父子协议和报告；`isolated_worker.py` 只编排检查；`model.py` 对每个输入文件只消费一次已冻结 bytes，从同一 snapshot 同时计算 SHA-256 和解析 JSON，并拒绝重复键；三个 checker 分别承担 schema、registry 和 graph 规则。P25-P28 的同进程配置/import/global/object-anchor 自指纹已由隔离进程边界替代并删除，不再维护双重信任链。validator 自身的最终信任仍来自独立 review 或 CI，不能用父进程污染自测替代。

P29 已将上述同进程 runtime/source 自指纹替换为一个更小的进程边界；它不是在现有 manifests/anchors 之上再叠一层。公开 `validate_contracts.py` 只保留 supervisor 职责：解析公开参数但不导入 `model.py`、`schema_checks.py`、`registry_checks.py`、`graph_checks.py` 或 worker；使用 bounded reader 对所有设计输入和全部 validator source（supervisor、worker、`model.py` 及三个 checker）各打开一次，单文件最多 8 MiB、总量最多 64 MiB、文件最多 128 个；计算逐文件和 aggregate digest；显式拒绝位于仓库内的 `TemporaryDirectory`，写入规范相对路径后复核摘要，并把镜像内全部冻结文件设置和验证为只读。Windows 的目录只读属性不是 ACL，故不把临时目录本身描述为 OS 写隔离；实际执行只消费已加载内存 bytes。结束时恢复权限用于清理，清理失败只能作为诊断，不能改写已产生的校验结论。

supervisor 先要求 `sys.executable` 是非空绝对路径且可执行，否则返回稳定启动错误；随后以参数序列调用 `[sys.executable, "-I", "-S", "-c", <fixed bootstrap>, ...]`。固定 bootstrap 只把已复核的临时镜像 validator 目录显式加入 `sys.path` 并启动一个内部 worker；不得把原仓库、调用者 cwd、`PYTHONPATH` 或 user site 加回路径。调用使用 `Popen`、`shell=False`、仓库外临时 cwd、仅含平台启动所需项的显式环境和 UTF-8 bytes I/O；request 在启动前限制为 256 KiB，stdout/stderr 分别由受限 reader 线程读取，内存最多各保留 1 MiB，越界立即终止 worker。180 秒 monotonic deadline 在 `Popen` 返回后、启动 stdin writer 前建立，覆盖 stdin/stdout/stderr 完整通信；worker 不读取 stdin 也必须 timeout，而不能等待自然退出。Python 官方文档警告直接 `.stdin.write` 与 PIPE 组合可能阻塞，并以 `communicate(input, timeout)` 定义完整通信 timeout；本实现采用等价的统一 deadline，但因 `communicate()` 会在内存缓存输出而继续保留有界 reader。来源：https://docs.python.org/3.11/library/subprocess.html#subprocess.Popen.communicate 。Python 3.11 中 `-I` 隐含 `-E`、`-P`、`-s`，`-S` 禁止自动导入 `site`；该边界不构成文件系统、网络或原生代码沙箱。

父子协议只接受一个版本化 JSON object。request 绑定 protocol version、按路径排序的 source/input digest、aggregate input digest、scope baseline canonical digest、公开参数和实际容量限制。worker 启动后对临时镜像中的每个 source/input 路径恰好读取一次，立即复核请求 digest；随后由最小 snapshot loader 从内存 source bytes `compile`/`exec` 四个内部模块，并把现有 input loader 的 reader 注入为内存 bytes 映射，普通 import 和文件 API 不得再次读取这些路径。worker 在执行检查前证明模块逻辑路径属于临时镜像、实际 source/input digest 与请求一致且容量声明匹配，再运行检查。response 只包含 protocol/validator version、request digest、semantic payload/digest 和 worker exit status；解析拒绝重复键、未知/缺失字段、非 UTF-8、尾随数据和超限内容，并强制 semantic schema/version/correlation、`status`、`errors`、逐 check `error_count/status`、响应退出码和进程退出码一致。unscoped 请求必须按固定顺序返回六个基础 check 且 `scope_evidence=null`；scoped 请求必须再包含末项 `forbidden_scope`，scope evidence 的 before canonical digest 和 before/after root 必须绑定请求，数量与 aggregate digest 必须与 `matches` 一致，并与 forbidden check 错误数绑定。timeout、启动失败、信号/崩溃、非零退出、stdout/stderr 超限、非 JSON、协议/请求/digest/语义不一致一律由 supervisor 非零失败关闭，不得回退到进程内 validator。正式 report 仍由唯一公开 CLI 按现有 canonical digest 规则原子写入；worker 不直接写用户指定 report 路径。

P29 已把 P25-P28 的 mutation 转为 supervisor 隔离回归：在父进程预先导入并篡改 checker/helper、`sys.modules`、import hook、模块/类/callable、`PYTHONPATH`/`PYTHONHOME` 和 site customization，worker 结果仍必须等于干净基线。现有单次 snapshot、schema/registry/graph 规则和 digest 定义继续复用；递归 import/global manifest 和 exact object anchors 已在替代证据成立后删除，避免双重信任链。

使用 `--report <path>` 时，报告必须记录 validator 版本、实际命令、按路径规范排序的输入文件及 SHA-256、总体 input digest、逐项结果和完整 errors。正式 evidence report 必须由同一条同时带 `--scope-root`、`--scope-before` 和 `--report` 的命令生成，记录 7 个 checks，其中 `forbidden_scope=OK`，且 `scope_evidence` 非空、`matches=true`；不得把另一条命令的 7/7 或 scope 结果拼接到 6 项报告。`report_digest` 是排除自身字段后完整报告 canonical JSON 的 SHA-256；它包含原始命令，等价命令也可以得到不同值。`semantic_result_digest` 只绑定 validator 版本、输入、检查结果、errors 和范围结果，排除命令与输出路径，因此同一输入的等价命令必须相同。`--scope-root` 与 `--scope-before` 只比较允许目录之外的文件数和聚合 SHA-256；其证明范围从 before 捕获时刻开始，不能替代不存在的 Git 历史或事前快照。

该 validator 是设计契约检查器，不是 runtime。它不执行真实 Ed25519/provider attestation、runner 隔离、OpenCode 生命周期或低性能模型 benchmark；这些仍需未来 runtime、集成测试和独立验收证明。
