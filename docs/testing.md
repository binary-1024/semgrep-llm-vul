# 测试

## 当前状态

仓库已经接入 Python/uv 测试 harness。当前包含一个最小包级测试，用于确认 `pytest` 能通过 `uv` 正常运行。

## 测试策略

未来测试应优先覆盖：

1. Semgrep 结果解析与归一化
2. 漏洞分类行为
3. 权限和数据安全边界
4. 畸形输入的错误处理
5. 来自真实 findings 的回归案例
6. 便于人工审查的输出格式

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

## 命令

```bash
./scripts/test
./scripts/check
```

底层命令：

```bash
uv run pytest
uv run ruff check .
uv build
```
