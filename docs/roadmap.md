# 路线图

本文档把项目目标拆成可执行里程碑。每个里程碑都以 harness 为核心：明确输入、输出、验证方式和失败反馈。

## 里程碑 0：项目 Harness

目标：让项目具备可开发、可验证、可回滚的基础工程环境。

当前状态：已完成基础 harness，进入后续里程碑时继续增量维护。

- Python 3.10 + `uv` 工程已建立。
- `pytest`、`ruff`、`uv build` 已接入 `./scripts/check`。
- GitHub Actions 已接入 `./scripts/check`。
- Git 管理文档已建立。
- 项目目标已形成第一版文档。
- 技术方向确定为语言无关核心模型 + Semgrep 适配层。
- 语言无关核心数据模型已建立。
- 分析任务 YAML/JSON 输入格式已建立。
- Semgrep finding 归一化已建立。
- Semgrep taint-mode 候选路径归一化已建立。
- 外部工具 fixture 分层与生成脚本已建立。
- benchmark/case harness 已开始建立，用于持续验证真实/半真实 case 上的能力边界。

完成标准：

- `./scripts/check` 通过。
- Git 初始提交完成。
- 后续任务可以在分支上开发。
- CI 可以在 `main` push 和 pull request 中运行统一检查。

## 里程碑 1：sink 函数生成

目标：根据输入线索生成或确认漏洞 sink 函数。

当前状态：最小 sink candidate pipeline 已实现，支持 known sink、Semgrep finding、diff artifact、漏洞片段、证据不足和 malformed artifact 场景。

输入：

- 漏洞描述。
- 目标 GitHub repo。
- 受影响版本。
- 修复版本或候选 PR。
- 可选：用户提供的 sink 函数签名和漏洞代码片段。

输出：

- 候选 sink 函数列表。
- 最终确认或推荐的 sink 函数。
- 每个 sink 的证据链。

关键能力：

- 获取目标仓库指定版本。
- 解析修复 diff 或候选 PR。
- 从漏洞描述和 diff 中提取危险行为。
- 将危险行为映射到函数、方法或 API 调用。
- 为候选 sink 排序并给出置信度。

验证方式：

- 使用人工构造 fixture 验证候选 sink 提取。
- 使用已知漏洞样例验证能否命中已知 sink。
- 输出必须包含代码位置、diff 证据和推理说明。

## 里程碑 2：污点路径生成与可触达确认

目标：从 sink 出发，在项目中找到潜在污点路径，并确认哪些路径可触达。

当前状态：M2 第一版最小闭环已完成。当前已经具备最小 taint path candidate generation、本地 reachability evidence model，以及基于 source root 的 `reachable=true|false|null` 三态证据。`true` 需要入口到候选路径上下文的静态证据；`false` 需要明确阻断证据；缺证据保持 `null`。

输入：

- sink 函数。
- 目标仓库与版本。
- 漏洞描述。
- 可选：source 类型、入口类型、框架信息。

输出：

- 潜在污点路径。
- 已确认可触达污点路径。
- 不可达或未确认路径的原因。
- 每条路径的证据链。

关键能力：

- 构建调用关系或近似调用图。
- 识别 source、propagator、sanitizer 和 sink。
- 路径搜索。
- 入口可达性分析。
- 将静态分析结果和 agent 推理结果交叉验证。

验证方式：

- 使用小型 fixture 项目验证路径搜索。
- 对每条可触达路径提供文件、行号、函数链和判断依据。
- 对无法确认的路径标记不确定性，而不是强行下结论。

## 里程碑 3：PoC 生成

目标：基于确认的可触达污点路径生成 PoC。

当前状态：M3 第一版最小闭环已完成。当前已经可以把 `reachable=true` 的路径转换成默认 `execution_state=not_run` 的结构化 PoC planning report；`reachable=false` 与 `reachable=null` 会继续保留为阻断/证据不足，不进入 PoC 执行语义。

输入：

- 已确认可触达污点路径。
- 漏洞描述。
- 目标项目运行方式。
- 受影响版本。

输出：

- PoC 代码或请求样例。
- PoC 运行步骤。
- 预期触发效果。
- 证据链。

关键能力：

- 从路径反推触发入口。
- 构造最小输入。
- 生成可复现步骤。
- 区分安全验证 PoC 与破坏性利用。

验证方式：

- 优先在本地、容器或隔离环境中验证。
- PoC 应能说明触发条件和预期结果。
- 如果不能运行，必须说明缺失环境和未验证风险。

## 里程碑 4：exp 验证与生成

目标：生成并执行 exp 脚本，用于验证漏洞判断是否正确。

当前状态：M4 第一版最小闭环已完成，并已推进到 M4.3。当前已经可以把 `PocPlan(execution_state=not_run)` 转换成结构化 exp verification report，并结合本地 execution evidence、loopback live HTTP replay、仓库内置 managed fixture runtime 或 opt-in live case 对 affected / fixed 版本做最小差分验证；当前 verdict 支持 `verified`、`not_verified`、`inconclusive`，runner 仍保持窄类型 `http_request_replay`，effect observation 当前仅覆盖 Flask open redirect。

输入：

- PoC。
- 可运行目标环境。
- 受影响版本和修复版本。

输出：

- exp 脚本。
- 执行日志。
- 受影响版本验证结果。
- 修复版本对照结果。
- 最终漏洞判断。

关键能力：

- 自动化搭建或连接测试环境。
- 执行 exp。
- 比较受影响版本与修复版本行为。
- 输出结构化验证报告。

验证方式：

- exp 必须能在隔离环境运行。
- 需要同时验证受影响版本和修复版本。
- 结果必须包含日志、退出码、请求响应或其他可复现证据。

## 当前下一步

当前主线已经完成 M4 第一版最小闭环，并补上了 M4.1 的 loopback live runner、M4.2 的 managed fixture runtime 和 M4.3 的第一条 opt-in live case。下一步优先扩 M4 的 effect coverage，而不是重新回到 M2/M3 语法角落。

M1 当前已经具备：

- 最小 sink candidate pipeline。
- `generate-sinks` JSON 报告入口。
- 本地 sink heuristic pack。
- benchmark/case harness。
- `./scripts/benchmark` 独立回归入口。

这些能力已足够支撑 M3 的第一版输入，并已形成第一版最小闭环。除非 M4 实现暴露新的 M2/M3 blocker，否则暂停继续加深 benchmark 工具链、sink heuristic 或更多局部入口模型支线。

此外，项目已经具备未来 LLM 语义增强层的最小结构化 contract：`SemanticHint` /
`SemanticHintReport` 可用于承载 unfamiliar API 的 source/sink/candidate_sanitizer
候选语义、适用版本、前提、失败模式和 unknowns，但当前仍未接入真实 LLM provider 或在线检索。

M2/M3/M4 当前闭环能力：

- `generate_taint_path_report` 最小候选路径生成入口。
- `generate-taint-paths` JSON 报告入口。
- Semgrep taint-mode `TaintPath(reachable=None)` 归一化能力。
- sink candidate 与 Semgrep taint path 的最小对齐能力。
- M2 taint path candidate 已纳入 benchmark/case harness。
- M2 reachability evidence model 已完成 Insight 和 ADR。
- `ReachabilityAssessment`、`ReachabilityReport` 和 `confirm-reachability` 最小本地入口。
- 最小 Flask route 入口提取、Flask method-specific decorator 入口提取（当前已回归 `@*.get(...)`）、Blueprint + `register_blueprint(..., url_prefix=...)` 组合入口提取、模块级 `app.add_url_rule(...)` 入口提取、同文件 helper call chain、direct import 的跨文件一层 helper call chain、module alias attribute call 的一层 helper call chain、`ImportFrom` module attribute call / alias call 的一层 helper call chain、最多两层 helper hop 的有界局部 helper chain、handler-local 相对路径 guard 的 blocking evidence，以及基于 `source.location` 本地赋值语句的 source controllability AST 证据已接入 source root fixture。
- `reachable=true|false|null` 三态都已有本地 source root 或本地 evidence fixture 驱动的 curated 回归。
- 普通 assignment alias、动态 registration 变体、未注册 Blueprint、跨函数 guard/sanitizer 和未回归的 decorator alias 当前已被显式锁在边界外，证据不足时继续保持 `reachable=null`。
- `generate-poc` 已接入最小结构化 PoC planning report，可从 `reachable=true` 的 Flask open redirect 路径恢复 method/path、参数位置、参数键名、最小样例值、预期效果和前提条件。
- `reachable=false` 与 `reachable=null` 已分别具备 M3 负边界回归，确保阻断证据和证据不足不会被误升级为可执行 PoC。
- M3 executable suite 已覆盖 `reachable=true`、`reachable=false` 与 `reachable=null` 三类 planning 结果。
- `verify-exp` 已接入最小结构化 exp verification report，可从 M3 plan 派生出 `http_request_replay` request artifact，并结合本地 execution evidence 或 loopback live HTTP replay 输出 `execution_state`、`effect_state` 和最终 `verdict`。
- M4 executable suite 已覆盖 `verified`、`not_verified` 与 `inconclusive` 三类差分验证结果。
- M4.1 已有 loopback live runner 的单元测试与 CLI 回归；当前只允许 `localhost` / `127.0.0.1` / `::1`，不自动启动服务，不跟随 redirect。
- M4.2 已有仓库内置 managed fixture runtime，可由内部 helper 受控地启动 `open_redirect_pair` 并复用现有 live runner；当前不暴露为公开 startup CLI。
- M4.3 已有单独的 `benchmarks/live-cases/` opt-in live suite，并回归 `managed_fixture=open_redirect_pair` 的 `verified` 正例；默认 `./scripts/benchmark` 不消费该 root。

建议下一个 M4 扩展任务：

```md
## 任务

在保持当前差分 verification contract 稳定的前提下，继续扩 M4 的 observation contract，而不是把 live suite 混进默认 benchmark root。

## 背景

当前 M4 已经具备 report-first 差分验证闭环，并已能通过内部 managed fixture runtime 启动最小 loopback 服务；但仍未进入真实项目服务自动启动或容器环境。

## 范围

- 保持 `verified`、`not_verified`、`inconclusive` 三态 verdict 语义不回退。
- 保持 `execution_state`、`effect_state` 与最终 verdict 三层分离。
- 只为窄场景引入真实本地 runner，不进入通用 exploit 执行器。

## 非目标

- 不连接真实公网目标。
- 不处理 secrets 或登录态自动获取。
- 不直接放开任意 shell/code 执行。
- 不把 runner 扩成通用攻击平台。

## 验收标准

- 新增 opt-in live case 或更强 observation 对应的 fixture、case 或隔离测试。
- `./scripts/benchmark` 继续通过。
- `./scripts/check` 通过。
```
