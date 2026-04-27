# Agent Instructions

## 项目概览

本项目将围绕 Semgrep 输出和 LLM 工作流，支持 AI 辅助漏洞分析。

技术栈定位：Python 3.10 系列，使用 `uv` 管理虚拟环境、依赖、测试和构建。

当前阶段：Python/uv 基础工程。后续优先实现 Semgrep JSON 解析与 finding 归一化能力。

`uv.toml` 已配置国内镜像。运行 `uv sync`、`uv run`、`uv build` 时应优先使用项目内配置，不要绕过该配置。

## 沟通与文档语言

默认使用中文：

- Codex 与用户沟通使用中文。
- 项目文档、任务说明、交付总结、风险说明默认使用中文。
- 代码注释优先使用中文，但简单自解释代码不需要注释。

以下内容保留原文或英文：

- 文件名、目录名、命令、环境变量、API 名称、包名、协议名。
- 第三方错误日志、扫描输出、接口返回内容。
- Semgrep、LLM、finding、fixture、CI 等常用技术术语，必要时可在中文中直接使用。

面向外部用户或开源发布的英文文档，需要单独确认后再编写。

## 常用命令

- 安装/同步依赖：`uv sync --dev`
- 查看 Git 状态：`git status --short`
- 测试：`./scripts/test`
- Lint：`./scripts/lint`
- 构建：`./scripts/build`
- 完整检查：`./scripts/check`

## Git 管理

项目 Git 使用方式见 `docs/git.md`。

默认要求：

- 主干分支使用 `main`。
- 任务分支使用 `codex/<type>-<topic>` 格式。
- 提交信息使用 Conventional Commits 风格。
- 提交前运行 `./scripts/check`。
- `uv.lock` 应提交，`.venv/`、`dist/`、缓存和敏感数据不得提交。
- Codex 不得回滚用户已有改动，除非用户明确要求。

## Insight 决策流程

项目关键决策必须先记录到 `Insight/`，再进入实现。

必须写 Insight 的情况：

- 项目架构调整。
- 数据模型、核心抽象或模块边界变化。
- 分析流程、agent 流程或证据链格式变化。
- 引入新的程序分析工具、LLM provider、数据库、队列、执行环境或外部服务。
- PoC/exp 安全边界变化。
- 影响后续多个里程碑的工程决策。

通用决策使用 `Insight/templates/decision-insight.md`。

架构决策使用 `Insight/templates/architecture-insight.md`。

每份 Insight 至少包含三轮讨论：

1. 第一性原理拆解。
2. 业界做法与备选方案。
3. 交叉质询与收敛。

通用决策默认从程序分析专家、工程化专家、漏洞安全专家三个视角讨论。

架构决策默认从资深 agent 开发架构师、软件工程师两个视角讨论；必要时补充程序分析专家和漏洞安全专家。

Insight 形成最终决策后，如该决策需要长期保留，应同步新增或更新 `docs/decisions/`。

## 架构边界

架构尚未最终确定。在架构明确之前：

- 没有任务文档或用户明确要求时，不引入复杂生产应用代码。
- Python 源码放在 `src/semgrep_llm_vul/`。
- 可复用文档放在 `docs/`。
- 可执行工作流入口放在 `scripts/`。
- 示例放在 `examples/`，fixture 放在 `fixtures/`，测试放在 `tests/`。

## 代码风格

- 优先做小而可审查的变更。
- 一旦存在实现代码，遵循项目已有模式。
- 避免无关格式化改动。
- 使用 Python 3.10 兼容语法。
- 使用 `uv` 管理依赖，不手动维护虚拟环境目录内容。
- 新增依赖前确认必要性，并写入 `pyproject.toml`。
- 处理 Semgrep 输出或其他机器可读数据时，优先使用结构化解析方式，避免临时字符串拼接。

## 安全规则

- 未经明确要求，不删除或覆盖用户创建的文件。
- 不运行破坏性命令。
- 未经明确确认，不新增联网服务调用、付费 API 调用、数据上传或凭据处理。
- 将漏洞数据、源码片段和扫描输出视为潜在敏感信息。
- 生成文件或临时产物不要纳入版本化源码，除非它们明确属于 fixture 或 example。

## 验证要求

完成任务前，运行与变更范围最相关的检查命令：

- 仅文档变更：检查链接，并运行 `./scripts/check`。
- 脚本或 harness 变更：运行 `./scripts/check`。
- 未来后端或 CLI 变更：运行 `./scripts/test` 和 `./scripts/lint`。
- 未来 UI 变更：运行 `./scripts/test`、`./scripts/lint` 和 `./scripts/build`。

当前 Python/uv harness 已接入 `pytest`、`ruff` 和 `uv build`。如果验证失败，需要先修复失败项，再交付总结。
