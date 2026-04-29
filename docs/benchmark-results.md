# Benchmark Baseline

本文档记录 benchmark/case harness 的当前基线，用于后续判断能力提升、退化和边界变化。

记录日期：2026-04-29。

## 当前结论

当前 benchmark/case harness 已经可以稳定回答三类问题：

- `validate-benchmarks`：仓库内有哪些 case、来源是什么、处于哪个阶段、当前状态如何。
- `evaluate-benchmarks`：M1 sink generation inventory evaluator 能通过哪些 case，哪些 case 暂时 unsupported 或 blocked。
- `evaluate-cases`：可执行的 M1/M2 case suite 是否满足每个 case 的阶段期望。
- `benchmark-summary`：把 inventory、inventory evaluation 和 executable suite 合并为短摘要，并通过 `scope` 和 `known_limitations` 解释职责边界。

当前结果显示：

- M1 sink candidate pipeline 在现有 candidate M1 cases 上稳定通过。
- M2 taint path candidate 与 reachability `true|false|null` cases 已进入 executable suite，并能通过当前 curated M2 cases。
- inventory evaluator 仍只支持 M1 sink generation，所以会把 M2 cases 作为 `unsupported_stage` gap 记录。
- 完整外部数据集 ingestion 和需要隔离运行环境的真实漏洞 case 仍处于边界记录阶段，不作为当前自动回归失败。

## 命令

当前基线来自以下命令：

```bash
./scripts/benchmark
./scripts/check
```

`./scripts/benchmark` 会依次执行：

```bash
uv run semgrep-llm-vul validate-benchmarks benchmarks/cases
uv run semgrep-llm-vul evaluate-benchmarks benchmarks/cases --artifact-base .
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root . --summary-only
```

## Inventory Baseline

当前 `benchmarks/cases/` 共收录 23 个 case：

| 维度 | 数量 |
| --- | ---: |
| total | 23 |
| candidate | 21 |
| unsupported | 1 |
| blocked | 1 |

按目标阶段：

| 阶段 | 数量 |
| --- | ---: |
| M1 | 12 |
| M2 | 10 |
| M3 | 1 |

按 case 类型：

| 类型 | 数量 |
| --- | ---: |
| curated_minimal | 18 |
| real_vulnerability | 3 |
| synthetic_benchmark | 2 |

按来源：

| 来源 | 数量 |
| --- | ---: |
| project-curated | 18 |
| CVEfixes | 1 |
| NIST SARD / Juliet-style CWE sample | 1 |
| OWASP Benchmark | 1 |
| pypickle CVE-2025-5174 | 1 |
| Vul4J | 1 |

## Inventory Evaluation Baseline

`evaluate-benchmarks` 当前结果：

| outcome | 数量 |
| --- | ---: |
| passed | 11 |
| unsupported | 11 |
| blocked | 1 |
| failed | 0 |
| error | 0 |
| total | 23 |

当前 gaps：

| case | code | 说明 |
| --- | --- | --- |
| `curated-open-redirect-reachability` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-blocked` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-cross-file-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-from-import-alias-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-from-import-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-import-alias-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-multi-layer-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-unknown` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-taint-path` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `cvefixes-dataset-intake-unsupported` | `unsupported_source_ingestion` | 当前不支持直接导入完整 CVEfixes 数据库。 |
| `vul4j-real-java-intake-blocked` | `blocked_runtime` | 需要隔离环境、checkout 或运行边界后才能执行。 |

`evaluate-cases --summary-only` 当前结果：

| 指标 | 数量 |
| --- | ---: |
| total | 21 |
| passed_count | 21 |
| failed_count | 0 |

## 能力边界

当前已经具备：

- M1 known sink、Semgrep finding、diff artifact、vulnerable snippet 和 evidence insufficient 场景的 deterministic sink candidate 回归。
- M1 negative case 回归，包括安全 wrapper、safe API、diff 删除行和证据不足场景。
- M2 taint path candidate、reachability `true|false|null`、Flask route positive、同文件 helper call chain、跨文件 direct helper call chain、module alias attribute call helper call chain、`ImportFrom` module attribute call / alias call helper call chain，以及有界 multi-layer helper call chain 的最小 curated case 回归。
- benchmark inventory、gap 和 executable suite 三层输出。
- benchmark summary 使用 `inventory_evaluation` 和 `executable_suite` 区分 inventory/gap evaluation 与 M1/M2 executable suite，避免把 M2 `unsupported_stage` 误读为 M2 suite 不支持。

当前未覆盖或暂不自动化：

- M2 reachability `true|false|null` 已有最小本地证据模型和 curated 回归，且已能从本地 Flask fixture 源码提取入口证据、同文件 helper call chain 证据、direct import 的跨文件 helper call chain 证据、module alias attribute call 证据、`ImportFrom` module attribute call / alias call 证据，以及最多两层 helper hop 的局部 helper chain 证据。
- 完整 CVEfixes ingestion 尚未实现。
- Vul4J 等需要 checkout、构建、运行或隔离环境的 case 尚未进入自动执行。
- 真实外部项目的大规模 benchmark 下载、缓存和采样流程尚未建立。
- 当前 benchmark 仍偏小，不能解释为整体漏洞分析准确率。

## 下一步

优先扩展能揭示缺陷的 case，而不是只增加 happy path：

- 扩展更多框架入口模型或更真实的调用链证据。
- Semgrep 有候选路径但入口证据不足的 case。
- wrapper、alias、indirect call 造成的误报或漏报边界。
- 名称相似但语义不同的 sink negative case。
- 真实漏洞裁剪 case 的来源、许可证和安全边界记录。

当这些 case 暴露稳定失败模式时，应把失败模式转化为单元测试、fixture 或新的 Insight/ADR。
