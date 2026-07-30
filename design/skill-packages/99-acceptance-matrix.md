# 六包 Skill v3.3 设计引用与验收矩阵

> **状态：仅文档（DOCUMENTATION ONLY）。** 本仓库未发布下表列出的任何实际 Skill 包；不包含其 `SKILL.md`、脚本、资源或可安装内容。
>
> 下表中的名称仅用于说明历史设计中的引用关系和验收目标，不表示这些 Skill 在本仓库中可用、可加载或已上传。

## 1. 67 个设计参考名称的唯一映射

| 顶层包 | 内部 reference | 设计参考名称（未随仓库发布） |
| --- | --- | --- |
| requirements-contract | intake-and-scope | requirements-analysis; user-story-writing; prd-generator; requirement-grill; intake-review |
| requirements-contract | stakeholders-and-priority | stakeholder-mapping; prioritization-framework; multi-perspective-review |
| requirements-contract | research-and-evidence | web-research; scrapling; aliens-eye; research-source-quality |
| solution-design | architecture-and-interfaces | agent-team-design; api-interface-design; context-engineering; observability-design; rag-architect |
| solution-design | repository-impact-and-fit | architecture-doubt-review; change-impact-auditor; function-map-scan; pre-routing-check |
| solution-design | patterns-and-commands | design-dna-search; template-extract; execution-commands |
| execute-in-slices | slice-discipline | incremental-implementation; tdd; clean-code; source-driven-development; ponytail |
| execute-in-slices | integration-patterns | json-mode-patterns; prompt-engineering; prompt-caching-patterns; copilotkit-integration |
| execute-in-slices | change-safety | refactor; security-hardening |
| execute-in-slices | ui-slice-patterns | ui-component-library; ui-animation |
| verify-and-diagnose | verification-strategy | testing-strategies; eval-harness; playwright-testing; browser-devtools-testing |
| verify-and-diagnose | diagnosis-and-stability | debug; flaky-test-debugging; null-chain-detect; pipeline-trace |
| verify-and-diagnose | model-and-retrieval-evaluation | llm-judge-eval; rag-eval |
| review-and-gate | correctness-and-completeness | code-review; code-review-quality-gate; project-completeness-check; scope-alignment-review |
| review-and-gate | architecture-and-maintainability | architecture-audit; kb-coverage-scan; ponytail-audit; ponytail-review |
| review-and-gate | security-and-supply-chain | secret-scan-review; security-review; skill-quality-audit; skill-security-audit |
| record-and-handoff | evidence-and-decisions | architecture-decision; material-format; vector-maintain |
| record-and-handoff | completion-and-handoff | completion-report; handoff |
| record-and-handoff | simplicity-ledger | ponytail-debt; ponytail-gain; ponytail-help |

计数为 12 + 12 + 13 + 10 + 12 + 8 = 67。此计数仅表示设计参考名称，每个名称只出现一次；不表示 67 个来源 Skill 已随本仓库发布。

明确排除的 14 个网文 Skill：`arc-causality-check`、`chapter-checklist`、`de-ai-detection`、`dialogue-voice`、`hook-structure`、`novel-glossary`、`pacing-math`、`prompt-quality`、`style-fingerprint`、`style-voice-check`、`thread-balance`、`webnovel-rhythm-analysis`、`webnovel-storytelling`、`webnovel-template-audit`。

## 2. 逐包验收

所有包均使用 `evaluation_point=before_external_acceptance`、`aggregation=all_applicable` 和 `self_test_is_acceptance=false`。

| 包 | AC | 核心判定 | 条件适用性 | 外部接受权 |
| --- | --- | --- | --- | --- |
| requirements-contract | `REQ-AC-01..08` | R/AC、actor/outcome、问题策略、研究来源、未验证 claim、Delivery Receipt | questions/research/external claims | 无 |
| solution-design | `SOL-AC-01..08` | design landing、ownership、impact/path、slice、通信、checks、correction | existing repo/communication | 无 |
| execute-in-slices | `EXE-AC-01..08` | lease/CAS、operation diff、tool events、required checks pass、manifest | completed/security/correction slices | 无 |
| verify-and-diagnose | `VER-AC-01..08` | checks、runner、隔离 workspace、coverage、diagnosis、evaluation | failures/quality scope | 无 |
| review-and-gate | `REV-AC-01..08` | Guard scope、全轴 coverage、findings、聚合、attestation、只读 | findings/multiple axes | 仅 candidate gate |
| record-and-handoff | `REC-AC-01..08` | 单 index、claim、状态、checkpoint/final、历史、simplicity、acceptance | report kind/simplicity/acceptance | 只有 Guard 的 `acceptance.apply` |

N/A 必须有 `artifact.applicability_evidence.v1`；predicate 为 unknown 时阻断。不得把不存在的条件 artifact 当失败，也不得静默忽略 blocking AC。

## 3. 上轮质疑问题的修正追踪

| 问题 | v3 设计落点 | 未来阻断测试 |
| --- | --- | --- |
| 包级 I/O 强迫无关输出 | 每个 step 的 `inputs`、`outputs_by_outcome` | research/diagnose/simplicity 不产生 final artifact 仍合法 |
| `required_result=all` 死锁 | `all_applicable` + N/A evidence | 无 research/evaluation/diagnosis/simplicity 的正常路径 |
| Review 状态机不闭合 | axis 只 completed；Guard `review.aggregate` 产生 disposition | 三轴全 pass、单轴变化、多轴 finding 均唯一终点 |
| manifest 只有 hash | canonical manifest v2 + Ed25519 policy + trust store + revocation + atomic install | 替换 registry、撤销 key、大小写碰撞、junction/symlink |
| correction scope 不明 | `correction_proposal.v1` + Guard `correction.route` | 新路径/依赖/check 必须 return_to_design |
| 检查只记录不判定通过 | `required_slice_checks_passed` 独立 assertion | 记录非零退出码不能 completed |
| ACCEPTED 无可信事件 | `acceptance_decision.v1` + policy + actor + expiry + CAS | Skill 自批、越权 CI、过期/旧 revision decision |
| Review scope 可伪造 | Guard `review.scope` 读取 actual change，unknown 默认适用 | 上游 false boolean 不能跳过 security |
| 需求角色和默认缺失 | actor/stakeholder/outcome + question class/default/rollback | safe default、must clarify、defer 三类恢复 |
| Research 来源不足 | snapshot/license/privacy/retention/injection/claim mapping | unverified claim 不能支撑 blocking AC |
| Windows 路径逃逸 | canonical path object + operation + reparse/hardlink/case policy | junction、hardlink、rename target、case collision |
| Evaluation/Diagnosis 不可复查 | evaluation policy/anchors + failure event/source revision refs | 临时 judge、换 sample、丢失原 failure 被拒绝 |
| Reviewer 独立性可伪造 | 控制面签发 reviewer attestation | 仅换 reviewer_id 仍 advisory |
| 测试生成物误伤 workspace | 隔离 snapshot + declared ephemeral/output mounts | coverage/cache 合法，受保护源码变化非法 |
| Loading Proof 不证明投递 | Delivery Receipt + rendered/message/tool digest + truncation=false | provider receipt 缺失/截断/消息变化阻断 |
| 缺少系统效果指标 | 本文件第 5 节 NFR | 固定低性能模型 benchmark 和人工介入审计 |

## 4. 跨包机器不变量

| ID | 标准 | 验证方式 |
| --- | --- | --- |
| `SYS-AC-01` | 系统全图可达，且 transition 只有一种 source/target 组合；start、package route、system transition、suspension 的目标状态与目标 step/node 一致 | graph/state/schema mutation probes |
| `SYS-AC-02` | 每个 package terminal event 只有一个 system handler | terminal deletion/duplication probes |
| `SYS-AC-03` | 有限 fact domain 下 system transition 互斥完备，unknown 阻断 | transition partition probes |
| `SYS-AC-04` | ArtifactRef/CollectionRef 可达、冻结且通过 schema 实例检查 | producer/ref/member mutation probes |
| `SYS-AC-05` | clarification 绑定 origin/resume token，apply 后精确恢复原 step | suspension graph checks |
| `SYS-AC-06` | Review aggregate 读取 Guard CAS 维护的完整 fragment collection | review collection checks |
| `SYS-AC-07` | correction、verification 和 pre-acceptance AC 不依赖未来 artifact | conditional AC cycle checks |
| `SYS-AC-08` | registry 引用均解析；本地 schema path/fragment/hash/`$id` 可复算且 identity 唯一，外部 schema binding 具有唯一小写 scheme、无 query/fragment 分隔符、RFC 3986 `pchar` path、SemVer 和可解析 attestation 描述 | registry/schema binding/attestation/raw-URI/illegal-path probes |
| `SYS-AC-09` | package manifest 使用 detached signature、受信 key、撤销和原子安装 | trust tamper tests（runtime） |
| `SYS-AC-10` | provider attestation 绑定实际投递内容、nonce、时效和 truncation=false | delivery tamper tests（runtime） |
| `SYS-AC-11` | 同一输入的等价命令产生相同 semantic result digest；完整 report digest 保留命令差异 | digest comparison |
| `SYS-AC-12` | Acceptance Transition 只能在有权限的 `acceptance.apply=approved` 后产生 | transition authorization tests（runtime） |

## 5. 系统效果指标

这些是未来 runtime/集成验收目标，不是本阶段已经达到的结果。

| ID | 指标 | 初始门槛 |
| --- | --- | --- |
| `NFR-01` | 正常路径人工流程操作 | 任务提交后，init/begin/checkpoint/Skill 选择均为 0 次 |
| `NFR-02` | 合法人工介入 | 只允许 must_clarify 答复和最终用户批准；每次有 reason/step evidence |
| `NFR-03` | 自动恢复与停滞 | 同一冻结 step 最多 2 次重试；无进展自动 checkpoint + blocked |
| `NFR-04` | Skill 实际投递 | 所有已执行 Skill step Delivery Receipt 覆盖率 100%，truncation 必须 false |
| `NFR-05` | 上下文容量 | 单 invocation rendered context 不超过 64 KiB，并记录 provider token estimate |
| `NFR-06` | 边界安全 | 权限逃逸、Skill 自批、route/profile 绕过的固定攻击用例拒绝率 100% |
| `NFR-07` | 低性能模型流程完成率 | 冻结 benchmark 中正常任务候选 handoff 完成率不低于 80% |
| `NFR-08` | 质量约束 | NFR-07 的成功 Run 必须同时满足全部 blocking AC；边界违规 Run 计失败，不得冲抵完成率 |
| `NFR-09` | 证据新鲜度 | 使用失效、过期或旧 revision evidence 的接受率为 0 |

Benchmark 实现前必须冻结模型/build、provider 参数、样例、seed、runner、环境、最大重试和评分规则。至少包含六阶段正常任务、clarification、research、check failure、correction、multi-axis review、restart/resume 和十类反绕过场景。

## 6. 必需成功/失败/绕过路径

- 成功：无 research 的正常任务；带 verified research；无 quality scope；带 evaluation；三轴 review；无 simplicity final；带 simplicity final；有权限 external acceptance。
- 合法失败：must clarify；research source blocked；required check failed；diagnosis return_to_design；review changes/block/advisory；acceptance stale/unauthorized。
- 契约绕过：伪造 N/A、替换签名 registry、把 package 改绑到其他已登记 crypto policy、把 `SYS-AC-12`/assertion authority 同步改绑、URI 使用空 `?/#` 分隔符或 scheme 大小写变体、URI path 注入 `<` 等非 `pchar` 字符、替换 validator snapshot source、污染父进程已加载 validator/`sys.modules`/import hook/Python 环境或 site、provider 截断、三 reference、未知 runner、失败 check 伪装 completed、skip security、伪造 reviewer、自批 ACCEPTED、Evidence Index 自引用。

全面终审新增固定 mutation 矩阵：

| 验收 ID | 不变量 | 必需负向证据 |
| --- | --- | --- |
| A29 | 安全/接受控制失败关闭 | `self_test_is_acceptance=true`、`aggregation=first_passing`、受保护权限 `allow`、关闭 registry record/atomic install、reference 路径逃逸/未知/超过两个、`md5`/`none` crypto、弱化 `guard.acceptance` 均命中各自稳定错误码 |
| A30 | package route group 存在且互斥完备 | 删除 start、`after:planning.requirements.research` 中间组或 `after:acceptance.apply` terminal 组均命中 `ROUTE_GROUP_MISSING`；合法组继续覆盖全部 outcome/fact domain |
| A31 | 稳定 ID 与 package binding 唯一 | 重复 profile、package AC、system transition、suspension 或 package binding 均命中 namespace-aware duplicate 错误，输入顺序不改变诊断 |
| A32 | 摘要与解析共享单次 bytes snapshot | 可控 reader 只调用一次；解析值和 SHA-256 同时绑定第一次 bytes；registry 的本地 Schema digest/fragment/`$id` 检查复用同一 snapshot |
| A33 | crypto/acceptance 精确用途绑定 | package 改绑 provider/schema policy、新增 `md5/none` policy 后改绑 package、同步把 `SYS-AC-12` 和 assertion authority 改绑 `guard.validator` 均命中固定域绑定错误；合法基线通过 |
| A34 | 生产 loader 与执行代码身份绑定 | probe 调用生产 `load_contract_inputs(root, reader=...)` 且每路径恰好读取一次；五个 validator source 全替换为未执行的合法 Python bytes 时命中 `VALIDATOR_RUNTIME_SOURCE_MISMATCH`；身份比较同时绑定函数字节码、defaults/kwdefaults 和版本化模块配置 manifest |
| A35 | 正式报告绑定 scope 检查 | 同一条带 scope/report 参数的命令生成 7 项报告；`forbidden_scope=OK`、`scope_evidence.matches=true` 且 before/after 相等；semantic/report digest 可独立复算 |
| A36 | 模块配置与函数默认值不可脱离 snapshot | 仅修改已加载 `PACKAGE_SIGNATURE_POLICY_ID`、positional default 或 keyword-only default 均命中对应模块的 `VALIDATOR_RUNTIME_SOURCE_MISMATCH`；新增可识别顶层配置自动进入 manifest，未知表达式失败关闭 |
| A39 | 导入执行绑定不可脱离 snapshot | import/global binding manifest 绑定 canonical owner、模块路径、函数所属模块/限定名/代码身份、真实 `__globals__` namespace 和递归全局绑定图；仅重绑定 `validate_contracts.check_registry`、`registry_checks.sha256_bytes`，或用相同代码构造伪 globals 函数，均命中目标模块的 `VALIDATOR_RUNTIME_SOURCE_MISMATCH`，合法基线通过 |
| A40 | 模块/类/callable 绑定不可伪造 | validator 加载完成时捕获 exact object anchors，并比较模块稳定导出 surface、类 MRO/成员语义和 callable 类型身份；同名同路径 `re` proxy、同 owner/qualname/path `Path` 伪类、同步替换 `urllib.parse.urlsplit` 与 `registry_checks.urlsplit` 的伪 callable，以及删除 anchor 初始化的 source mutation，均使完整 validator 非零退出并命中 `VALIDATOR_RUNTIME_SOURCE_MISMATCH`，合法基线通过 |
| A41 | 正式校验只在冻结 snapshot 的全新隔离 Python 子进程执行 | supervisor 不预导入 worker/checker，以 8 MiB 单文件、64 MiB 总量、128 文件上限单读 input/source，显式拒绝仓库内镜像并验证冻结文件只读；worker 由有效 `sys.executable -I -S`、清理环境、固定临时 cwd 和 `shell=False` 启动，以内存 loader 执行已摘要 bytes。request 启动前限制 256 KiB，stdout/stderr 由受限 reader 各限制 1 MiB，越界终止。父进程 checker/helper monkeypatch、`sys.modules`/import hook、Python 环境和 site customization 不改变结果；矛盾 status/errors/checks/exit、无效解释器、timeout、崩溃、超限/畸形 JSON、重复/未知字段、protocol/request/source/input digest mismatch 均失败且不回退。`tests/unit/test_contract_validator_isolation.py` 固化矩阵；文档明确该进程边界不是 OS sandbox |
| A42 | 响应完整性、完整通信 deadline 与污染矩阵不可绕过 | unscoped/scoped 响应分别精确绑定固定 6/7 check 顺序及 null/匹配 scope evidence；deadline 在 stdin writer 前开始，128 KiB request 遇到不读 stdin 的 worker时命中 timeout；生产 probe 实际注入并由测试观察模块/函数/类 monkeypatch、`sys.modules`、import hook、Python 环境和 site customization，删除 probe 调用时测试失败 |

## 7. 当前设计验证与未来 runtime 实现顺序

设计层已提供 `guard-registry.v1` 组件索引、八类 registry 组件、JSON Schema 和唯一入口 `validation/validate_contracts.py`。P29 已把入口收敛为 supervisor，并在冻结临时镜像的全新 `sys.executable -I -S` worker 中执行本地 schema/实例、registry binding、包内 route、artifact 可达性、状态一致性、系统生命周期、负向探针和禁止范围。现有报告证明 v3.3 设计 artifact 的静态一致性和本轮隔离执行证据；外部 schema attestation、真实签名及业务 runtime 行为仍不在该结论内。

未来 runtime 实现顺序：

1. 消费 v3.3 registry/schema，并在运行时实现相同的 artifact/predicate/route/actor/trust 判定。
2. 实现 canonical manifest、签名、trust store、撤销和 Delivery Receipt。
3. 实现 requirements/design step I/O、question/research 恢复和 planning gate。
4. 实现 canonical path objects、lease、Implementation Manifest、Correction Route。
5. 实现 runner/evaluation/diagnosis 和隔离 workspace。
6. 实现 Review Scope、全轴执行、Reviewer Attestation 和 Aggregate。
7. 实现 Handoff、Acceptance Decision、系统指标采集和 benchmark。

每一步必须独立 review；自测只作为 evidence。

## 8. 当前剩余风险

- 当前 Python/Node runtime 仍使用旧 packet/phase/evidence 模型，尚不执行 v3.3；不得通过插件提示词模拟。
- P30 将隔离 validator 升级为 1.5.2，补齐 exact response shape、覆盖 stdin 的统一 deadline 和可观察污染矩阵；该实现者证据仅支持 A41/A42 复审输入，不替代新的独立 review/CI，也不得据此宣称 A18 已满足。
- P31 将 validator 升级为 1.5.3，以 exact set 拒绝 scope snapshot 未知字段；同时修复现有 runtime 的插件/Node 依赖、Docker cache 与 Git mode 完整性边界。P31 后 baseline、7/7 报告、mutation 和全量门禁仍是实现者证据，不替代新的独立 review/CI，也不得据此宣称 A18 已满足。
- 标准库 validator 实现的是设计期结构、注册表、有限域和图不变量，不执行真实签名、provider 投递、runner 隔离或 runtime 性能 benchmark。
- provider 是否能返回可信 delivery receipt 需要实现阶段验证；不能证明时强制 Skill step 应阻断。
- trust store 的密钥保管、轮换和撤销操作手册尚未实现。
- 80% benchmark 是初始产品目标，必须在模型和样例冻结后由用户或独立评测批准。
