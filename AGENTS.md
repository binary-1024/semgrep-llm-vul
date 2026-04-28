# Agent Instructions

## 项目概览

本项目将围绕 Semgrep 输出和 LLM 工作流，支持 AI 辅助漏洞分析。

技术栈定位：Python 3.10 系列，使用 `uv` 管理虚拟环境、依赖、测试和构建。

当前阶段：M0 基础 harness 已完成，M1 sink generation pipeline 决策已完成。下一步优先实现本地、确定性、证据优先的最小 sink candidate 生成能力。

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

## 项目记忆与上下文管理

不要只依赖聊天上下文。长期有效的信息必须沉淀到项目文档或 Git 提交中。

开始非小型任务前，采用分层读取，不要默认读取整个 `docs/`。

第一层，每次优先确认：

- `README.md`
- `AGENTS.md`
- 当前 Git 状态：`git status --short`

第二层，按任务类型选择性读取：

- `docs/product.md`
- `docs/methodology.md`
- `docs/roadmap.md`
- `docs/architecture.md`
- `docs/development.md`
- `docs/testing.md`
- `docs/git.md`

第三层，只在涉及具体决策、架构或历史背景时读取：

- 与当前任务相关的 `docs/Insight/<topic>.md`
- 与当前任务相关的 `docs/decisions/<id>.md`

第四层，作为历史材料按需读取：

- 旧 Insight
- 已被取代的 ADR
- 失败复盘或长期归档材料

长文档应优先阅读标题、摘要、状态和适用范围，再决定是否阅读全文。

如果任务涉及新的架构、核心模型、agent 流程、证据链格式或安全边界，先创建或更新 `docs/Insight/`，再进入实现。

如果对话中出现长期有效的新规则、目标或约束，优先更新项目文档，而不是只在聊天中保留。

## 主线校准

项目采用“主线骨架优先，支线够用即停”的开发策略。

主线里程碑顺序：

1. M1：sink 函数生成。
2. M2：污点路径生成与可触达确认。
3. M3：PoC 生成。
4. M4：exp 验证与生成。

每次开始非小型任务前，Codex 必须先确认：

- 当前任务服务哪个主线里程碑。
- 如果是支线任务，它解除哪个主线 blocker，或支撑哪个主线验证。
- 做到什么程度就停止。
- 明确非目标，避免支线继续膨胀。

每 3 到 5 个 PR，或连续多个任务都在同一支线时，必须做一次主线校准：

- 当前是否仍在推进 M1/M2/M3/M4。
- 最近支线是否已经够用。
- 下一步是否应回到主线骨架。

当前原则：benchmark/case harness 已足够支撑 M1 回归，除非主线需要新的验证样例，否则暂停继续加深 benchmark 工具链，优先回到 M2 最小污点路径候选。

## Git 管理

项目 Git 使用方式见 `docs/git.md`。

默认要求：

- 主干分支使用 `main`。
- 任务分支使用 `codex/<type>-<topic>` 格式。
- 关键决策使用 `codex/docs-<topic>` 分支，只写 Insight、ADR 和相关文档。
- 实现工作使用 `codex/feature-<topic>` 分支，并基于已合入 `main` 的决策文档进行。
- 提交信息使用 Conventional Commits 风格。
- 提交前运行 `./scripts/check`。
- `uv.lock` 应提交，`.venv/`、`dist/`、缓存和敏感数据不得提交。
- Codex 不得回滚用户已有改动，除非用户明确要求。

## Insight 决策流程

项目关键决策必须先记录到 `docs/Insight/`，再进入实现。

必须写 Insight 的情况：

- 项目架构调整。
- 数据模型、核心抽象或模块边界变化。
- 分析流程、agent 流程或证据链格式变化。
- 引入新的程序分析工具、LLM provider、数据库、队列、执行环境或外部服务。
- PoC/exp 安全边界变化。
- 影响后续多个里程碑的工程决策。

通用决策使用 `docs/Insight/templates/decision-insight.md`。

架构决策使用 `docs/Insight/templates/architecture-insight.md`。

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

## 外部工具 Adapter 规则

处理 Semgrep、CodeQL、SARIF、Joern、GitHub API、LLM 输出等外部格式时：

- 不要只用理想化手写 fixture 驱动实现。
- 至少覆盖 `minimal`、`realistic`、`malformed` 三类测试样例中的相关类型。
- realistic fixture 应尽量贴近真实工具输出结构；如果是合成样例，需要在 README 或测试中说明。
- Insight 中提到的格式风险和失败模式，必须转化为 fixture 或测试断言。
- Review adapter 时必须确认：fixture 是真实输出、真实输出裁剪版，还是合成的近似结构。

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

## 任务收尾检讨

每次任务完成后，必须做一次综合性检讨与 check：

- 查看 `git status --short --branch`，确认只包含本任务相关改动。
- 查看 `git diff --stat` 和关键 diff，确认没有无关格式化、缓存、构建产物或敏感数据。
- 根据变更范围运行最相关的验证命令；默认优先运行 `./scripts/check`。
- 文档变更需要检查本地 Markdown 相对链接。
- 对照任务目标、非目标和验收标准，确认没有越界实现或遗漏测试。
- 检查是否需要同步更新 `README.md`、`AGENTS.md`、`docs/roadmap.md`、`docs/architecture.md`、`docs/testing.md`、`fixtures/` 或 ADR。
- 如果存在失败、未验证项或残余风险，先修复；暂时无法修复时必须在交付总结中说明。

## 单元测试与回归测试

测试规范见 `docs/testing.md`。

默认要求：

- 新功能必须补单元测试。
- bug fix 必须补回归测试，证明修复前会失败、修复后通过。
- 外部工具 adapter 必须覆盖 minimal / realistic / malformed 中相关 fixture 类型。
- Insight 中列出的失败模式，应转化为测试或明确记录无法自动化的原因。
- CLI 行为需要测试 exit code、stdout 和 stderr。
