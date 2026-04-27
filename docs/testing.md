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
