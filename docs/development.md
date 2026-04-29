# 开发

## 工作流

以项目管理规范作为流程来源：

1. 理解目标。
2. 阅读相关文件。
3. 确认任务服务的主线里程碑和实现边界。
4. 制定简短计划。
5. 实施范围内变更。
6. 运行验证命令。
7. 修复失败项。
8. 做任务收尾检讨。
9. 总结变更、验证结果和风险。

## 双轨协作模式

当任务涉及算法、架构、方法论、agent 流程、证据链语义或能力边界时，默认采用“主实现 agent + 研究型 agent”的双轨协作模式。

角色分工：

- 主实现 agent：负责界定主线目标、非目标和停止条件，并承担仓库修改、测试、benchmark、验证和交付责任。
- 研究型 agent：负责提供理论依据、论文或经典算法线索、行业做法、备选方案、风险和失败模式。

建议输出格式：

- 研究型 agent：`主张 / 适用前提 / 预期收益 / 失败模式 / 最小实验 / kill criterion`
- 主实现 agent：`实现变更 / 验证结果 / 残余 unknowns`

推荐执行顺序：

1. 主实现 agent 先确认任务服务哪个主线里程碑，以及做到什么程度就停。
2. 如果属于关键决策或高不确定性任务，研究型 agent 并行输出理论支撑和方案比较。
3. 主实现 agent 同步读取代码和文档，推进最小实现、最小 harness 或最小验证。
4. 将“理论结论 + 实践反馈”收敛为 Insight、ADR、任务边界或具体实现计划。
5. 把研究输出中真正长期有效的部分沉淀到项目文档、测试、fixture 或 benchmark。

默认启用场景：

- 架构调整或 agent 流程变化。
- 程序分析算法选择，例如调用图、污点传播、入口模型、版本对照策略。
- 方法论、证据链语义、阶段结论语义调整。
- 会影响多个里程碑的关键工程决策。

默认不必启用场景：

- 小范围文档修正。
- 已有决策下的直接实现。
- 局部 bug fix、测试补充、fixture 更新。
- 不涉及能力边界变化的日常维护任务。

停止条件：

- 已经足够支撑下一步主线决策、最小实现或验证。
- 研究结论若暂时无法转化为仓库工件，应降级为待验证假设并写入 Insight，而不是继续无限扩展研究支线。
- 当连续两轮实验都无法产生新的区分证据时，应停止继续加深当前支线，并记录为 `known gap`、后续 Insight 问题或 roadmap 待办。

## 主线校准

项目优先推进 M1 到 M4 的主线骨架：

```text
M1 sink 函数生成
  ↓
M2 污点路径生成与可触达确认
  ↓
M3 PoC 生成
  ↓
M4 exp 验证与生成
```

支线任务可以做，但必须服务主线。常见支线包括 benchmark/case harness、CI、fixture 生成、文档导航和开发体验。

开始任务前，必须回答：

- 这个任务推进哪个主线里程碑？
- 如果它是支线，解除哪个 blocker 或支撑哪个验证？
- 做到什么程度就停？
- 本次明确不做什么？

支线做到“能支撑下一个主线决策或验证”就应暂停，不追求在支线上一次性做完整平台。

每 3 到 5 个 PR，或者连续多个 PR 都在同一支线时，必须回看 `docs/roadmap.md` 并做主线校准。校准结论应写进任务总结；如果形成长期规则，应更新 `AGENTS.md`、`docs/development.md` 或 `docs/roadmap.md`。

## 任务收尾检讨

每次任务完成后，Codex 必须做一次综合性检讨与 check，再提交或交付总结。

收尾检讨至少包括：

- 查看 `git status --short --branch`，确认只包含本任务相关改动。
- 查看 `git diff --stat` 和关键 diff，确认没有无关格式化、缓存、构建产物或敏感数据。
- 根据变更范围运行最相关的验证命令；默认优先运行 `./scripts/check`。
- 文档变更需要检查本地 Markdown 相对链接。
- 对照任务目标、非目标和验收标准，确认没有越界实现或遗漏测试。
- 对照主线校准规则，确认本次任务没有让支线替代主线。
- 检查是否需要同步更新 `README.md`、`AGENTS.md`、`docs/roadmap.md`、`docs/architecture.md`、`docs/testing.md`、`fixtures/` 或 ADR。
- 如果发现失败、未验证项或残余风险，先修复；暂时无法修复时必须在交付总结中说明。

## 文档读取策略

为了节省模型上下文，任务开始时不要默认读取整个 `docs/`。

默认先确认：

- `README.md`
- `AGENTS.md`
- 当前 Git 状态

再根据任务类型选择性读取：

- 产品或目标变化：`docs/product.md`
- 漏洞分析方法论、阶段结论语义、证据链原则：`docs/methodology.md`
- 里程碑和下一步：`docs/roadmap.md`
- 架构和模块边界：`docs/architecture.md`
- 开发流程：`docs/development.md`
- 测试策略：`docs/testing.md`
- Git 流程：`docs/git.md`
- 决策背景：相关 `docs/Insight/` 和 `docs/decisions/`

旧 Insight、已被取代的 ADR 和历史复盘只在需要追溯背景时读取。

## 文档职责边界

- `README.md` 保持稳定，负责说明项目是什么、如何开始、常用命令和核心文档入口。
- `docs/methodology.md` 负责说明漏洞分析方法论、证据链原则、阶段结论语义和工具/LLM 分工。
- `docs/roadmap.md` 负责记录当前阶段、下一步任务和里程碑计划。
- 高频变化的计划、阶段状态和下一步清单不要放在 `README.md` 中，避免 README 与路线图漂移。

## 决策前置流程

进入实现前，先判断是否属于关键决策：

- 架构调整。
- 数据模型、核心抽象或模块边界变化。
- 分析流程、agent 流程或证据链格式变化。
- 引入新的外部工具、服务或执行环境。
- PoC/exp 安全边界变化。

如果属于关键决策，必须先在 `docs/Insight/` 下创建记录，并按模板完成三轮讨论：

1. 第一性原理拆解。
2. 业界做法与备选方案。
3. 交叉质询与收敛。

讨论完成后，再形成最终决策，并按需同步到 `docs/decisions/`。

## 任务模板

```md
## 任务

## 背景

## 范围

## 非目标

## 验收标准

## 风险

## 验证
```

## 本地命令

项目使用 Python 3.10 系列，并通过 `uv` 管理虚拟环境和依赖：

```bash
uv sync --dev
uv run python --version
```

项目内 `uv.toml` 已配置国内镜像：

- `[[index]]` 使用清华 PyPI 镜像，并设置为默认 index。
- `python-install-mirror` 使用 NJU 的 `python-build-standalone` GitHub Release 镜像。

常用检查命令：

```bash
./scripts/check
./scripts/test
./scripts/lint
./scripts/build
./scripts/benchmark
./scripts/benchmark-summary
./scripts/update-semgrep-fixtures
```

`./scripts/check` 会依次运行 lint、测试和构建。

`./scripts/benchmark` 会先校验 benchmark/case 目录，再执行当前 benchmark/case harness。
它作为独立回归入口，不默认并入 `./scripts/check`，避免未来真实 case 扩展后拖慢基础 harness。

`./scripts/benchmark-summary` 输出 benchmark/case harness 的短摘要，适合日常人工查看。
需要更新 baseline 文档时，优先使用 `uv run semgrep-llm-vul benchmark-baseline --markdown`
生成当前计数和 gaps，再人工补充能力边界解释。

`./scripts/update-semgrep-fixtures` 用于从 `examples/semgrep/` 中的样例项目和规则生成 Semgrep JSON fixture。

## Worktree 与分支

本项目可能同时存在多个 Git worktree。新任务开始前必须：

- 运行 `git fetch origin main`。
- 查看 `git log --oneline --decorate --graph --left-right HEAD...origin/main`，确认主干是否已有相同方向的工作。
- 从 `origin/main` 创建新任务分支，例如 `git switch -c codex/feature-topic origin/main`。
- 如果发现本地实现已被主干 supersede，优先缩小为真实增量，避免提交重复实现。

校验分析任务输入：

```bash
uv run semgrep-llm-vul validate-input examples/analysis/known-sink.yaml
```

生成 sink candidate JSON 报告：

```bash
uv run semgrep-llm-vul generate-sinks \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/basic-result.json
```

## CI

GitHub Actions 会在 push 到 `main` 和 pull request 时运行：

```bash
uv sync --dev
./scripts/check
```

CI 配置位于 `.github/workflows/check.yml`。本地提交前仍需先运行 `./scripts/check`。

## Python 项目约定

- 源码放在 `src/semgrep_llm_vul/`。
- 测试放在 `tests/`。
- fixture 放在 `fixtures/`。
- 使用 `ruff` 做静态检查。
- 使用 `pytest` 做测试。
- 使用 `uv build` 验证包构建。
- 项目 Python 版本约束为 `>=3.10,<3.11`。

## 外部工具 Adapter 开发约定

实现 Semgrep、CodeQL、SARIF、Joern、GitHub API、LLM 输出等外部格式 adapter 时：

- 先确认是否已有相关 `docs/Insight/` 或 ADR。
- 不要只用理想化手写 fixture 驱动实现。
- 至少根据场景覆盖 `minimal`、`realistic`、`malformed` fixture。
- realistic fixture 应尽量贴近真实工具输出，或说明它依据官方文档/已知样例构造。
- Insight 中提到的格式风险，必须转化成测试断言。
- adapter 只做解析、归一化和证据保留，不直接做最终安全结论。
