# OpenCode Guard Authority

OpenCode Guard 是一个本地、故障关闭的开发流程约束内核。它只负责创建受控 Run、冻结开发包、授权文件写入、运行可信验证并保存证据；它不读取外部项目源码来替模型制定方案，也不提供 Skill、Memory 或项目汇总功能。

## 最小运行链路

```text
opencode-guard open
  -> Git 基线与隔离 worktree
  -> OpenCode nonce 握手
  -> 首条用户消息自动绑定任务
  -> guard_submit_packet 冻结需求/架构/阶段/验收
  -> edit/write 经过 before-tool 授权和 after-tool 核验
  -> 最后阶段自动 Docker 验证
  -> REVIEW_REQUIRED
  -> 外部 review/CI/用户批准后 ACCEPTED
```

运行阶段只有：`PLANNING`、`IMPLEMENTING`、`VERIFYING`、`REVIEW_REQUIRED`、`ACCEPTED`。

## 安装

环境要求：Windows、Python 3.11+、Node.js、Git、Docker Desktop、OpenCode 1.18.3。

在仓库目录执行：

```powershell
Set-Location "F:\OpenCode\mcp"
.\scripts\install.ps1
```

安装器会：

- 安装 Python 包及 `opencode-guard-authority`、`opencode-guard-mcp` 命令；
- 在 OpenCode 配置目录安装顶层 loader 和五文件插件 bundle；
- 写入 ownership manifest，并对六个受管文件保存 SHA-256；
- 不修改 `opencode.json`/`opencode.jsonc`。

卸载 Guard 插件：

```powershell
.\scripts\uninstall.ps1
```

卸载器只删除带有本 Guard ownership manifest 且摘要匹配的文件。若安装前存在旧顶层插件，会自动恢复备份。需要同时移除 Python 包时显式加入 `-RemovePythonPackage`。

## 启动和使用

不要先手工 `init`，也不要手工创建任务。Guard 启动器会完成初始化并直接拉起 OpenCode：

```powershell
opencode-guard open --project "F:\path\to\project"
```

项目必须是 Git 仓库、存在有效 `HEAD`，且工作区干净。Docker 不可用、插件未安装、插件摘要不匹配、项目配置声明主机可执行扩展或 nonce 握手失败时，启动会拒绝并关闭。

启动成功时，终端会输出包含 `guard: ACTIVE`、`run_id` 和受控 worktree 的 JSON。进入 OpenCode 后直接输入真实开发需求。第一条用户消息会自动绑定为当前 Run 的唯一任务。

模型必须一次提交完整开发包，内容包括：

- `requirements`：稳定的 `R*` 需求 ID；
- `acceptance`：稳定的 `A*` 验收 ID、验证命令和必需路径；
- `constraints`、`non_goals`、`stop_conditions`；
- `architecture`：组件、依赖方向、信任边界、数据流和并发策略；
- `phases`：每阶段的 R/A 映射、允许路径和已注册检查。

开发包冻结后，只有当前阶段允许路径上的写入工具可用。`bash`、`task`、外部目录、网络抓取和额外插件始终拒绝。写入必须同时通过 before-tool 授权和 after-tool 实际变更核验；失败会锁定 Run。

插件只提供两个控制工具：`guard_submit_packet`、`guard_complete_phase`。MCP 只读工具只有：`guard_context`、`guard_artifact`、`guard_evidence`。MCP 不能写状态、执行检查或产生批准。

## 查询和外部验收

```powershell
opencode-guard inspect --run "run-..."
opencode-guard review --run "run-..." --decision approve --reviewer "name" --source user
```

`review` 只接受 `user`、`ci` 或 `independent-review` 来源。自测是证据，不是最终验收；没有独立 review、CI 或用户明确批准，不得声称最终通过。

## 包入口

- Python 门面：`opencode_guardian.Guardian`；
- RPC：`opencode-guard-authority`；
- 只读 MCP：`opencode-guard-mcp`；
- OpenCode 插件：`opencode-plugin/index.js`。

旧版本、Skill/Memory 资料、旧测试和构建产物均在桌面归档目录，不参与运行、安装或测试。
