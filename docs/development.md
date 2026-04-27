# 开发

## 工作流

以项目管理规范作为流程来源：

1. 理解目标。
2. 阅读相关文件。
3. 确认实现边界。
4. 制定简短计划。
5. 实施范围内变更。
6. 运行验证命令。
7. 修复失败项。
8. 总结变更、验证结果和风险。

## 文档读取策略

为了节省模型上下文，任务开始时不要默认读取整个 `docs/`。

默认先确认：

- `README.md`
- `AGENTS.md`
- 当前 Git 状态

再根据任务类型选择性读取：

- 产品或目标变化：`docs/product.md`
- 里程碑和下一步：`docs/roadmap.md`
- 架构和模块边界：`docs/architecture.md`
- 开发流程：`docs/development.md`
- 测试策略：`docs/testing.md`
- Git 流程：`docs/git.md`
- 决策背景：相关 `docs/Insight/` 和 `docs/decisions/`

旧 Insight、已被取代的 ADR 和历史复盘只在需要追溯背景时读取。

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
```

`./scripts/check` 会依次运行 lint、测试和构建。

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
