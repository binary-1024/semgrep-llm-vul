# Benchmarks

本目录存放 benchmark 与 case harness 的轻量入口。

当前阶段只提交：

- case schema。
- 小型 curated case。
- 外部 benchmark 的引用和抽样说明。
- 来源候选目录：[sources.md](sources.md)。
- 新增 case 模板：`templates/`。

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
  templates/
    case.yaml
    expected.json
    notes.md
  sources.md
```

## 最小要求

每个 case 必须说明：

- 来源类型：`synthetic_benchmark`、`real_vulnerability` 或 `curated_minimal`。
- 目标阶段：M1、M2、M3 或 M4。
- 输入材料：描述、repo、版本、diff、Semgrep finding 或片段。
- 期望输出：sink、路径、PoC、exp 或明确的 unsupported/blocked。
- 证据链：文件、行号、patch、规则命中或人工说明。
- 安全边界：是否包含 PoC/exp、是否需要隔离环境。

新增 case 时可从 `benchmarks/templates/` 复制三件套，然后替换占位字段。

## 执行

新增或修改 case 后，先校验目录结构和 schema：

```bash
uv run semgrep-llm-vul validate-benchmarks
```

该命令只读取 case，不执行 sink generation。输出为 `benchmark_case_inventory`，
用于快速查看 `type`、`status`、`source` 和 safety 信息。

当前支持 M1 sink generation evaluator：

```bash
uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .
```

输出为 JSON，包含每个 case 的 `passed`、`failed`、`blocked`、`unsupported`
或 `error` 状态。默认不展开完整 sink generation report；需要调试时可加
`--include-reports`。

每个 case 输出会保留：

- `type`：`curated_minimal`、`synthetic_benchmark` 或 `real_vulnerability`。
- `declared_status`：case.yaml 中声明的状态。
- `outcome`：本次 evaluator 运行后的结果。
- `source`：来源名称、URL 和许可证边界。

`coverage` 字段按 `type`、`stage` 和 `source` 聚合，用来快速观察样本库是否过度偏向某类来源或某个里程碑。

`gaps` 字段把未通过、阻塞或暂不支持的 case 转成开发反馈，例如：

- `blocked_runtime`：需要隔离 checkout、构建或运行边界。
- `unsupported_source_ingestion`：当前不支持直接导入某类外部数据源。
- `unsupported_stage`：当前 evaluator 尚未支持该里程碑。
- `missing_expected_candidate`：应生成的候选没有出现。
- `forbidden_candidate`：不应生成的候选被误报。

`gaps` 只用于工程排队和能力边界记录，不代表漏洞最终结论。
