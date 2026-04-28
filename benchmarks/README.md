# Benchmarks

本目录存放 benchmark 与 case harness 的轻量入口。

当前阶段只提交：

- case schema。
- 小型 curated case。
- 外部 benchmark 的引用和抽样说明。

当前阶段不提交：

- 完整 SARD、Juliet、OWASP Benchmark、Vul4J、CVEfixes 数据集。
- 下载缓存。
- 构建产物。
- 真实凭据、敏感源码或未授权利用脚本。

详细方法见 [Benchmark 与 Case Harness](../docs/benchmark.md)。

## 目录

```text
benchmarks/
  README.md
  cases/
    README.md
    <case-id>/
      case.yaml
      expected.json
      notes.md
```

## 最小要求

每个 case 必须说明：

- 来源类型：`synthetic_benchmark`、`real_vulnerability` 或 `curated_minimal`。
- 目标阶段：M1、M2、M3 或 M4。
- 输入材料：描述、repo、版本、diff、Semgrep finding 或片段。
- 期望输出：sink、路径、PoC、exp 或明确的 unsupported/blocked。
- 证据链：文件、行号、patch、规则命中或人工说明。
- 安全边界：是否包含 PoC/exp、是否需要隔离环境。

## 运行单个 case

当前 evaluator 支持 M1 sink candidate case：

```bash
uv run semgrep-llm-vul evaluate-case \
  benchmarks/cases/curated-open-redirect-safe-wrapper \
  --repo-root .
```
