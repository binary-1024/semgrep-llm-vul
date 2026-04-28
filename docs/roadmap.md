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

当前状态：M2 已开始建立最小 taint path candidate generation，第一版只对齐 M1 sink candidate 与 Semgrep taint-mode 候选路径，不做可触达确认。

M2 可触达确认已完成方法决策：第一版采用本地、确定性、证据优先的 reachability evidence model，将 `reachable` 明确为 `true`、`false`、`null` 三态。`true` 需要入口到候选路径上下文的静态证据；`false` 需要明确阻断证据；缺证据保持 `null`。

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

下一步继续推进里程碑 2：污点路径生成与可触达确认。

M1 当前已经具备：

- 最小 sink candidate pipeline。
- `generate-sinks` JSON 报告入口。
- 本地 sink heuristic pack。
- benchmark/case harness。
- `./scripts/benchmark` 独立回归入口。

这些能力已足够支撑 M2 的第一版输入。除非 M2 实现暴露新的 M1 blocker，否则暂停继续加深 benchmark 工具链和 sink heuristic 支线。

M2 当前已经具备：

- `generate_taint_path_report` 最小候选路径生成入口。
- `generate-taint-paths` JSON 报告入口。
- Semgrep taint-mode `TaintPath(reachable=None)` 归一化能力。
- sink candidate 与 Semgrep taint path 的最小对齐能力。
- M2 taint path candidate 已纳入 benchmark/case harness。
- M2 reachability evidence model 已完成 Insight 和 ADR。
- `ReachabilityAssessment`、`ReachabilityReport` 和 `confirm-reachability` 最小本地入口。

建议下一个 M2 具体任务：

```md
## 任务

扩展 M2 可触达确认的真实入口模型。

## 背景

项目已经具备最小 taint path candidate generation、稳定 JSON 报告、CLI 入口、benchmark/case 回归、reachability evidence model 决策和本地 evidence JSON 驱动的最小实现。下一步需要让系统从小型 fixture 项目中提取第一类真实入口证据，而不是完全依赖手写 reachability JSON。

## 范围

- 选择一个最小框架入口模型，例如 Python Flask route。
- 从本地 fixture 源码或结构化 artifact 中提取 entrypoint evidence。
- 将入口证据接入现有 `ReachabilityAssessment`。
- 保持 source control、blocking factors 和 unknowns 的三态语义。

## 非目标

- 不调用真实 LLM provider。
- 不联网拉取真实 GitHub repo。
- 不实现完整跨语言调用图。
- 不进入 PoC 或 exp 阶段。
- 不把 candidate path 标记为 verified。

## 验收标准

- 新增最小入口模型单元测试。
- 新增或扩展 M2 benchmark/case 回归。
- 缺入口模型时继续保持 `reachable=null`。
- `./scripts/benchmark` 继续通过。
- `./scripts/check` 通过。
```
