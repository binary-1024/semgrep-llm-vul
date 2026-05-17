# Live Cases

本目录存放 **opt-in** 的 live benchmark cases。

这些 case 与 `benchmarks/cases/` 的区别是：

- 它们会触发真实 loopback live replay；
- 它们可能通过仓库内置 `managed_fixture` 自动启动最小本地服务；
- 它们默认 **不** 被 `./scripts/benchmark`、`./scripts/benchmark-summary` 和默认 baseline 消费。

## 使用方式

评估单个 live case：

```bash
uv run semgrep-llm-vul evaluate-case \
  benchmarks/live-cases/curated-open-redirect-exp-live-verified \
  --repo-root .
```

批量评估 opt-in live cases：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/live-cases --repo-root .
./scripts/benchmark-live
```

## 当前边界

- 当前只支持 M4 live case。
- 当前只允许仓库内置 `managed_fixture`，不允许任意脚本、命令或公网目标。
- 当前唯一内置 fixture 为 `open_redirect_pair`。
