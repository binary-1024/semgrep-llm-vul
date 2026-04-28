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

完成标准：

- `./scripts/check` 通过。
- Git 初始提交完成。
- 后续任务可以在分支上开发。
- CI 可以在 `main` push 和 pull request 中运行统一检查。

## 里程碑 1：sink 函数生成

目标：根据输入线索生成或确认漏洞 sink 函数。

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

下一步进入里程碑 1：sink 函数生成的最小实现。

`sink generation pipeline` 的 Insight 和 ADR 已明确采用证据优先、多阶段、本地确定性的第一版流程。决策合入 `main` 后，应在 `codex/feature-sink-generation` 分支中实现最小 sink candidate 生成能力。

建议第一个具体任务：

```md
## 任务

实现最小 sink candidate 生成 pipeline。

## 背景

项目已经具备基础输入模型、Semgrep finding 归一化、候选 taint path 归一化，以及 sink generation pipeline 决策。下一步需要把决策落成可测试的最小实现。

## 范围

- 从 `VulnerabilityInput` 生成 sink candidate report。
- 已知 sink 场景：用户提供 signature 时生成高优先级候选，并保留 evidence。
- 未知 sink 场景：从本地 fixture 中的 diff 线索、Semgrep finding 或代码片段生成候选。
- 实现稳定排序和低证据时的明确失败原因。
- 添加 fixture 和测试覆盖 known sink、unknown sink、insufficient evidence、malformed evidence。

## 非目标

- 不调用真实 LLM provider。
- 不联网拉取真实 GitHub repo。
- 不实现完整 diff parser。
- 不进入污点路径、PoC 或 exp 阶段。

## 验收标准

- known sink 输入能生成带 evidence 的 sink candidate。
- unknown sink fixture 能生成候选或明确说明证据不足。
- Semgrep finding 只能作为候选证据，不能被当成最终安全结论。
- 候选排序稳定。
- `./scripts/check` 通过。
```
