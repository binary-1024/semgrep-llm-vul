# Semgrep Fixtures

本目录存放 Semgrep 输出样例，用于测试 Semgrep adapter。

## Fixture 类型

每个 fixture 应在用途上明确属于以下类型之一：

- `minimal`：最小合法结构，只覆盖核心字段。
- `realistic`：尽量贴近真实 Semgrep 输出结构，可以是真实输出的脱敏裁剪版。
- `malformed`：刻意缺字段、结构不完整或格式异常，用于验证错误处理。

## 命名建议

```text
<feature>-minimal.json
<feature>-realistic.json
<feature>-malformed-<case>.json
```

当前 fixture：

- `basic-result.json`：minimal，覆盖普通 Semgrep finding。
- `taint-result-with-trace.json`：realistic，覆盖 `dataflow_trace` 中常见的 `location` 嵌套和 `CliLoc` 结构。
- `taint-result-without-trace.json`：minimal，覆盖 taint finding 缺少 trace 的情况。
- `taint-result-malformed-trace.json`：malformed，覆盖 trace 缺少 source 的情况。
- `taint-result-with-source-control-local-var-trace.json`：realistic，覆盖 `source.name` 只是局部变量、但 `source.location` 对应赋值语句直接从 Flask request 读取的情况。
- `taint-result-generated.json`：generated，由 `scripts/update-semgrep-fixtures` 基于 `examples/semgrep/` 生成。当前使用 Semgrep OSS 输出，通常不包含 `dataflow_trace`。

## 生成方式

运行：

```bash
./scripts/update-semgrep-fixtures
```

该脚本会使用：

- 样例项目：`examples/semgrep/project`
- Semgrep 规则：`examples/semgrep/rules/open-redirect-taint.yml`
- 输出文件：`fixtures/semgrep/taint-result-generated.json`

生成后脚本会通过项目的 Semgrep adapter 读取 fixture，确保至少包含一个 finding。

## 规则

- 外部工具 adapter 不应只依赖手写理想化 fixture。
- 如果没有真实输出，应写 realistic fixture，并明确它是根据官方结构或已知样例构造的。
- 解析逻辑的失败模式必须反映到 malformed fixture。
- Insight 中列出的格式风险，应转化为 fixture 或测试断言。
- fixture 不应包含真实项目敏感源码、凭据、私有仓库路径或未脱敏漏洞数据。
