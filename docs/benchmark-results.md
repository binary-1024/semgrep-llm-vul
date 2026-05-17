# Benchmark Baseline

本文档记录 benchmark/case harness 的当前基线，用于后续判断能力提升、退化和边界变化。

记录日期：2026-05-17。

## 当前结论

当前 benchmark/case harness 已经可以稳定回答三类问题：

- `validate-benchmarks`：仓库内有哪些 case、来源是什么、处于哪个阶段、当前状态如何。
- `evaluate-benchmarks`：M1 sink generation inventory evaluator 能通过哪些 case，哪些 case 暂时 unsupported 或 blocked。
- `evaluate-cases`：可执行的 M1/M2/M3/M4 case suite 是否满足每个 case 的阶段期望。
- `benchmark-summary`：把 inventory、inventory evaluation 和 executable suite 合并为短摘要，并通过 `scope` 和 `known_limitations` 解释职责边界。

当前结果显示：

- M1 sink candidate pipeline 在现有 candidate M1 cases 上稳定通过。
- M2 taint path candidate 与 reachability `true|false|null` cases 已进入 executable suite，并能通过当前 curated M2 cases。
- M4 differential exp verification cases 已进入 executable suite，并能通过当前 curated M4 cases。
- M4.1 loopback live runner 与 M4.2 managed fixture runtime 已进入 pytest 集成回归。
- M4.3 已新增单独的 opt-in live suite：`benchmarks/live-cases/`；它默认不纳入 `benchmarks/cases` executable suite。
- M4.4 已新增 body-signature effect observation；当前可通过 response body 中的 `meta refresh` 识别 open redirect 差异。
- M4.5 已新增 refresh-header effect observation；当前可通过 response header `Refresh` 识别 open redirect 差异。
- inventory evaluator 仍只支持 M1 sink generation，所以会把 M2/M3/M4 cases 作为 `unsupported_stage` gap 记录。
- 完整外部数据集 ingestion 和需要隔离运行环境的真实漏洞 case 仍处于边界记录阶段，不作为当前自动回归失败。

## 命令

当前基线来自以下命令：

```bash
./scripts/benchmark
./scripts/benchmark-live
./scripts/check
```

`./scripts/benchmark` 会依次执行：

```bash
uv run semgrep-llm-vul validate-benchmarks benchmarks/cases
uv run semgrep-llm-vul evaluate-benchmarks benchmarks/cases --artifact-base .
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root . --summary-only
```

opt-in live suite 由单独命令提供：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/live-cases --repo-root .
```

## Inventory Baseline

当前 `benchmarks/cases/` 共收录 38 个 case：

| 维度 | 数量 |
| --- | ---: |
| total | 38 |
| candidate | 36 |
| unsupported | 1 |
| blocked | 1 |

按目标阶段：

| 阶段 | 数量 |
| --- | ---: |
| M1 | 12 |
| M2 | 17 |
| M3 | 4 |
| M4 | 5 |

按 case 类型：

| 类型 | 数量 |
| --- | ---: |
| curated_minimal | 33 |
| real_vulnerability | 3 |
| synthetic_benchmark | 2 |

按来源：

| 来源 | 数量 |
| --- | ---: |
| project-curated | 33 |
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
| unsupported | 26 |
| blocked | 1 |
| failed | 0 |
| error | 0 |
| total | 38 |

当前 gaps：

| case | code | 说明 |
| --- | --- | --- |
| `curated-open-redirect-poc-plan-blocked` | `unsupported_stage` | inventory evaluator 当前不支持 M3。 |
| `curated-open-redirect-poc-plan-source-control-local-var` | `unsupported_stage` | inventory evaluator 当前不支持 M3。 |
| `curated-open-redirect-poc-plan-unknown` | `unsupported_stage` | inventory evaluator 当前不支持 M3。 |
| `curated-open-redirect-exp-inconclusive` | `unsupported_stage` | inventory evaluator 当前不支持 M4。 |
| `curated-open-redirect-exp-meta-refresh-verified` | `unsupported_stage` | inventory evaluator 当前不支持 M4。 |
| `curated-open-redirect-exp-not-verified` | `unsupported_stage` | inventory evaluator 当前不支持 M4。 |
| `curated-open-redirect-exp-refresh-header-verified` | `unsupported_stage` | inventory evaluator 当前不支持 M4。 |
| `curated-open-redirect-exp-verified` | `unsupported_stage` | inventory evaluator 当前不支持 M4。 |
| `curated-open-redirect-reachability` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-add-url-rule` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-alias-assignment-unknown` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-app-get` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-blocked` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-blueprint-prefix` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-blueprint-unregistered` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-cross-file-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-from-import-alias-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-from-import-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-import-alias-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-multi-layer-helper` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-relative-path-guard` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-source-control-local-var` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-reachability-unknown` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `curated-open-redirect-taint-path` | `unsupported_stage` | inventory evaluator 当前不支持 M2。 |
| `cvefixes-dataset-intake-unsupported` | `unsupported_source_ingestion` | 当前不支持直接导入完整 CVEfixes 数据库。 |
| `vul4j-real-java-intake-blocked` | `blocked_runtime` | 需要隔离环境、checkout 或运行边界后才能执行。 |

`evaluate-cases --summary-only` 当前结果：

| 指标 | 数量 |
| --- | ---: |
| total | 36 |
| passed_count | 36 |
| failed_count | 0 |

`./scripts/benchmark-live` 当前结果：

| 指标 | 数量 |
| --- | ---: |
| total | 3 |
| passed_count | 3 |
| failed_count | 0 |

## 能力边界

当前已经具备：

- M1 known sink、Semgrep finding、diff artifact、vulnerable snippet 和 evidence insufficient 场景的 deterministic sink candidate 回归。
- M1 negative case 回归，包括安全 wrapper、safe API、diff 删除行和证据不足场景。
- M2 taint path candidate、reachability `true|false|null`、Flask decorator route positive、Flask `@*.get(...)` method-specific decorator positive、Blueprint + `register_blueprint(..., url_prefix=...)` positive、未注册 Blueprint 保持 `reachable=null`、模块级 `app.add_url_rule(...)` route positive、同文件 helper call chain、跨文件 direct helper call chain、module alias attribute call helper call chain、`ImportFrom` module attribute call / alias call helper call chain、有界 multi-layer helper call chain、handler-local 相对路径 guard 的 `reachable=false`、基于 `source.location` 的 source controllability 本地 AST 证据，以及 assignment alias 保持 `reachable=null` 的最小 curated case 回归。
- M4 differential verification 已支持 `verified`、`not_verified`、`inconclusive` 三类 curated case，且当前会显式区分 `execution_state`、`effect_state` 与最终 verdict。
- M4.1 已支持 loopback live HTTP replay：对已运行在 `localhost` / `127.0.0.1` / `::1` 上的本地目标发起真实首跳请求，并继续复用现有 observation / verdict contract。
- M4.2 已支持仓库内置 managed fixture runtime：可以由内部 helper 受控地启动 `open_redirect_pair`、`open_redirect_meta_refresh_pair` 与 `open_redirect_refresh_header_pair`，再走现有 live runner / verdict contract。
- M4.3 已支持 opt-in live benchmark case：当前可通过 `benchmarks/live-cases/curated-open-redirect-exp-live-verified`、`benchmarks/live-cases/curated-open-redirect-exp-meta-refresh-live-verified` 与 `benchmarks/live-cases/curated-open-redirect-exp-refresh-header-live-verified` 分别验证 `managed_fixture(open_redirect_pair) -> verified`、`managed_fixture(open_redirect_meta_refresh_pair) -> verified` 与 `managed_fixture(open_redirect_refresh_header_pair) -> verified`。
- M4.4 已支持最小 body-signature effect observation：当前可通过 response body 中的 `meta refresh` 判断 open redirect 是否在 affected / fixed 间表现出差异，并把摘要写入 `response_body_excerpt`。
- M4.5 已支持最小 refresh-header effect observation：当前可通过 response header `Refresh` 判断 open redirect 是否在 affected / fixed 间表现出差异。
- benchmark inventory、gap 和 executable suite 三层输出。
- benchmark summary 使用 `inventory_evaluation` 和 `executable_suite` 区分 inventory/gap evaluation 与 M1/M2/M3/M4 executable suite，避免把 M2/M3/M4 `unsupported_stage` 误读为 suite 不支持。
- exp verification report 当前已提升到 `schema_version=2`，用于稳定承载 response-level evidence 摘要字段。

当前未覆盖或暂不自动化：

- M2 reachability `true|false|null` 已有最小本地证据模型和 curated 回归，且已能从本地 Flask fixture 源码提取 decorator route 证据、`@*.get(...)` 这类 method-specific decorator 证据、Blueprint + `register_blueprint(..., url_prefix=...)` 组合证据、模块级 `app.add_url_rule(...)` registration 证据、同文件 helper call chain 证据、direct import 的跨文件 helper call chain 证据、module alias attribute call 证据、`ImportFrom` module attribute call / alias call 证据、最多两层 helper hop 的局部 helper chain 证据、handler-local 相对路径 guard 的 blocking evidence，以及 `source.location` 对应赋值语句的 source controllability AST 证据；普通 assignment alias、未注册 Blueprint 和更一般的 guard/sanitizer 当前继续保持 `reachable=null`。
- M4 当前虽然已具备 loopback live runner、受控 managed fixture runtime、三条 opt-in live cases，以及最小 response-level observation family，但仍未进入真实项目服务自动启动、容器隔离、会话/鉴权或更广的 runner/effect 类型。
- 当前 response-level observation 仍只覆盖 open redirect 的 `Location`、`Refresh` 与 `meta refresh`；不支持通用 body diff、JS redirect、浏览器渲染或更复杂的 DOM 语义。
- 完整 CVEfixes ingestion 尚未实现。
- Vul4J 等需要 checkout、构建、运行或隔离环境的 case 尚未进入自动执行。
- 真实外部项目的大规模 benchmark 下载、缓存和采样流程尚未建立。
- 当前 benchmark 仍偏小，不能解释为整体漏洞分析准确率。

## 下一步

当前 M4 已经在窄范围内形成可回归闭环，并补上了 loopback live runner、managed fixture runtime、三条 opt-in live cases，以及最小 response-level observation family。后续优先考虑：

- 更明确的 managed fixture family 元数据；
- 更强的 observation contract，例如更多 response-level signature、error signature 或 stdout/stderr；
- 更广的 M4 场景族，而不只是 Flask open redirect；
- 真实漏洞裁剪 case 的来源、许可证和安全边界记录。

当这些 case 暴露稳定失败模式时，应把失败模式转化为单元测试、fixture 或新的 Insight/ADR。
