# 测试

## 当前状态

仓库已经接入 Python/uv 测试 harness。当前测试覆盖包导入、核心数据模型、分析任务 YAML/JSON 输入解析、CLI 行为、Semgrep finding 归一化、Semgrep taint trace 归一化和最小 sink generation pipeline。

## 测试策略

未来测试应优先覆盖：

1. Semgrep 结果解析与归一化
2. 漏洞分类行为
3. 权限和数据安全边界
4. 畸形输入的错误处理
5. 来自真实 findings 的回归案例
6. 便于人工审查的输出格式

## 测试分类

### 单元测试

单元测试用于验证单个函数、类或小模块的确定性行为。

适用范围：

- 数据模型校验
- 输入解析
- Semgrep finding 归一化
- Semgrep taint trace 归一化
- sink candidate 生成、排序、证据链和证据不足场景
- CLI 参数解析和 exit code
- 错误处理和边界输入

要求：

- 不访问网络。
- 不依赖真实外部仓库。
- 不修改工作区中非测试产物。
- 使用 `fixtures/` 或内联小样例。
- 每个 bug fix 至少补一个能失败再通过的单元测试。

命名：

```text
tests/test_<module>.py
test_<行为>_<预期结果>()
```

示例：

```text
tests/test_analysis_input.py
test_known_sink_requires_signature()
```

### 回归测试

回归测试用于锁定已经发现过的问题、外部格式差异或真实样例行为，防止未来改动再次破坏。

适用范围：

- 已修复 bug
- Semgrep / CodeQL / SARIF 等外部工具输出格式差异
- 真实或 realistic fixture
- 安全边界和误报/漏报案例
- CLI 行为兼容性

要求：

- 测试名或注释应说明回归点。
- 如果来自 bug，测试应引用相关 Insight、ADR、issue、commit 或 fixture 名。
- 回归 fixture 必须脱敏。
- 外部工具输出回归应优先使用 `realistic` 或 generated fixture。
- 回归测试不能只覆盖 happy path。

命名建议：

```text
test_regression_<问题摘要>()
```

示例：

```text
test_regression_nested_semgrep_trace_location()
```

### 集成测试

集成测试用于验证多个模块之间的协作，例如 CLI 读取 YAML 并走完整解析流程。

当前阶段集成测试仍放在 `tests/`，但应保持快速、离线、可重复。

未来如果出现耗时测试，可增加 marker：

```text
@pytest.mark.integration
```

并在 `scripts/test` 中区分快速测试和完整测试。

### 报告契约测试

报告契约测试用于保护 agent 和后续阶段会消费的 JSON 输出结构。

适用范围：

- sink generation report。
- taint path generation report。
- reachability report。
- benchmark summary 和 baseline 输出。
- 未来 PoC/exp report。

要求：

- 对关键字段、枚举值和三态语义做稳定性断言。
- 对 evidence、location、unknowns、blocking factors 等证据链字段做结构断言。
- 对语义命名做断言；例如 benchmark summary 应使用 `inventory_evaluation`，不得退回容易误读的 `evaluation`。
- 当报告字段重命名或语义调整时，应提升 `schema_version`，并补充对应 CLI 或报告契约测试。
- 避免对非关键排序或完整大 JSON 做脆弱断言；必要时先生成摘要再断言。
- 如果需要 snapshot，应优先 snapshot 小型、脱敏、稳定的报告片段。

## 回归测试触发条件

以下情况必须补回归测试：

- Review 发现解析器对真实格式支持不足。
- 修复过的 bug 可能再次出现。
- 新增或修改外部工具 adapter。
- 修改证据链、输入格式、路径归一化或 CLI exit code。
- Insight 中列出明确失败模式。

如果暂时无法补自动化回归测试，必须在最终说明中写明原因和人工验证步骤。

## 任务收尾验证

每次任务完成后，需要在交付前做一次综合性检讨：

- 新功能：确认有单元测试或集成测试覆盖主要成功路径和至少一个失败路径。
- bug fix：确认有回归测试覆盖已修复问题。
- 外部工具 adapter：确认 fixture 类型覆盖 minimal、realistic、malformed 中相关类别。
- CLI 变更：确认测试覆盖 exit code、stdout 和 stderr。
- 文档变更：确认本地相对链接不缺失，并运行 `./scripts/check`。
- 如果验证无法自动化，必须记录人工验证步骤和残余风险。

## Fixtures

使用 `fixtures/` 存放代表性的 Semgrep 输出和最小漏洞代码样例。除非明确允许包含真实项目数据，否则 fixture 应使用合成数据或脱敏数据。

### Fixture 真实性分层

外部工具 adapter 的 fixture 需要标注或说明类型：

- `minimal`：最小合法结构，只覆盖核心字段。
- `realistic`：尽量贴近真实工具输出结构，可以是真实输出的脱敏裁剪版。
- `malformed`：刻意缺字段、结构不完整或格式异常，用于验证错误处理。

适配 Semgrep、CodeQL、SARIF、Joern、GitHub API、LLM 输出等外部格式时，不应只依赖手写理想化 fixture。

Insight 中列出的格式风险和失败模式，必须转化为 fixture 或测试断言。

Review adapter 测试时必须确认：

```text
这个 fixture 是真实输出、真实输出裁剪版，还是合成的近似结构？
```

如果是合成的近似结构，需要明确其依据，并尽量补充 realistic fixture。

Semgrep fixture 可以通过以下命令从样例项目和规则生成：

```bash
./scripts/update-semgrep-fixtures
```

该命令应在更新 Semgrep adapter 或 Semgrep 规则样例时运行。

### Fixture Provenance

新增或修改外部工具 fixture 时，应在就近 README、case notes 或 fixture manifest 中说明：

- fixture 类型：`minimal`、`realistic`、`malformed` 或 generated。
- 来源：真实工具输出、真实输出裁剪、官方文档样例、项目内合成样例。
- 生成或裁剪命令。
- 是否经过脱敏。
- 覆盖的失败模式或回归点。

如果当前没有统一 manifest 文件，至少要在相关 `README.md` 或 benchmark `notes.md` 中记录这些信息。等 fixture 数量继续增加后，再通过 Insight/ADR 决定是否引入统一 `fixture_manifest` schema。

## 命令

```bash
./scripts/test
./scripts/check
./scripts/benchmark
./scripts/benchmark-summary
```

底层命令：

```bash
uv run pytest
uv run ruff check .
uv build
uv run semgrep-llm-vul validate-benchmarks
uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root . --summary-only
uv run semgrep-llm-vul benchmark-baseline --artifact-base . --repo-root . --markdown
```
