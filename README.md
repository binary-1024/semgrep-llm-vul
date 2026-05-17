# semgrep-llm-vul

围绕 Semgrep findings 和 LLM 审查工作流构建的 AI 辅助漏洞分析项目。

项目采用证据优先、可反驳、可验证的漏洞分析方法论，目标是把漏洞描述、版本差异、程序分析结果和 agent 推理组织成可审查的分析链路。

## 项目状态

- 阶段和下一步：见 [路线图](docs/roadmap.md)
- 主要规范：`项目开发管理规范.md`
- 技术栈：Python 3.10 系列，使用 `uv` 管理虚拟环境、依赖和构建
- 方法论：见 [漏洞分析方法论](docs/methodology.md)

## 仓库结构

```text
.
├── AGENTS.md
├── README.md
├── docs/
│   ├── Insight/
│   ├── architecture.md
│   ├── development.md
│   ├── git.md
│   ├── glossary.md
│   ├── methodology.md
│   ├── product.md
│   ├── roadmap.md
│   ├── testing.md
│   └── decisions/
├── scripts/
│   ├── build
│   ├── check
│   ├── lint
│   └── test
├── src/
│   └── semgrep_llm_vul/
├── tests/
├── examples/
├── fixtures/
└── .github/
    └── workflows/
```

## 常用命令

```bash
./scripts/check
./scripts/test
./scripts/lint
./scripts/build
./scripts/benchmark
./scripts/benchmark-live
./scripts/benchmark-summary
./scripts/update-semgrep-fixtures
uv run semgrep-llm-vul validate-benchmarks
uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .
```

这些脚本通过 `uv` 执行：

- `./scripts/test` 运行 `pytest`
- `./scripts/lint` 运行 `ruff check .`
- `./scripts/build` 运行 `uv build`
- `./scripts/check` 依次运行 lint、test 和 build
- `./scripts/update-semgrep-fixtures` 从样例项目生成 Semgrep fixture
- `./scripts/benchmark` 校验并执行 benchmark/case harness，覆盖 inventory/gap evaluator 和 M1/M2/M3/M4 case suite
- `./scripts/benchmark-live` 显式执行 opt-in live case suite，覆盖少量需要 managed fixture 的 M4 live cases
- `./scripts/benchmark-summary` 输出 benchmark/case harness 短摘要
- `uv run semgrep-llm-vul validate-benchmarks` 校验 benchmark/case 目录并输出 inventory
- `uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .` 执行 M1 benchmark/case evaluator

## 分析任务输入

分析任务可以用 YAML 或 JSON 描述。示例：

- [known-sink.yaml](examples/analysis/known-sink.yaml)
- [unknown-sink.yaml](examples/analysis/unknown-sink.yaml)
- [known-sink.json](examples/analysis/known-sink.json)

校验输入文件：

```bash
uv run semgrep-llm-vul validate-input examples/analysis/known-sink.yaml
```

生成 sink candidate JSON 报告：

```bash
uv run semgrep-llm-vul generate-sinks \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/basic-result.json
```

执行 benchmark/case harness：

```bash
./scripts/benchmark
./scripts/benchmark-live
./scripts/benchmark-summary
uv run semgrep-llm-vul validate-benchmarks
uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .
```

评估一个 benchmark case 的阶段期望：

```bash
uv run semgrep-llm-vul evaluate-case \
  benchmarks/cases/curated-open-redirect-safe-wrapper \
  --repo-root .
```

批量评估 `benchmarks/cases/` 下的 M1/M2/M3/M4 cases：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root .
```

评估 opt-in live cases：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/live-cases --repo-root .
./scripts/benchmark-live
```

生成 taint path candidate JSON 报告：

```bash
uv run semgrep-llm-vul generate-taint-paths \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-trace.json
```

生成 reachability JSON 报告：

```bash
uv run semgrep-llm-vul confirm-reachability \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-trace.json \
  --reachability-json fixtures/reachability/open-redirect-reachable.json
```

也可以从本地源码 fixture 提取最小 Flask route 入口证据：

```bash
uv run semgrep-llm-vul confirm-reachability \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-trace.json \
  --source-root fixtures/reachability/flask-app
```

日常回归可使用摘要输出：

```bash
./scripts/benchmark-summary
```

生成最小结构化 PoC planning JSON 报告：

```bash
uv run semgrep-llm-vul generate-poc \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-source-control-local-var-trace.json \
  --source-root fixtures/reachability/flask-source-control-local-var-app
```

当前 `generate-poc` 只消费 `reachable=true` 的路径，输出默认 `execution_state=not_run`
的结构化 PoC planning report；`reachable=false` 与 `reachable=null` 不进入 PoC 执行语义。

生成最小结构化 exp verification JSON 报告：

```bash
uv run semgrep-llm-vul verify-exp \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-source-control-local-var-trace.json \
  --source-root fixtures/reachability/flask-source-control-local-var-app \
  --execution-json fixtures/execution/open-redirect-verified.json
```

当前 `verify-exp` 只消费 `PocPlan(execution_state=not_run)` 对应的等价输入，输出带
`execution_state`、`effect_state` 和最终 `verdict` 的结构化 exp verification report；
第一版 runner 仅支持 `http_request_replay`，effect observation 当前仅覆盖 Flask open
redirect 这一类可由 redirect 行为差异表达的场景。

也可以对已经运行在 loopback 上的本地目标发起真实 replay：

```bash
uv run semgrep-llm-vul verify-exp \
  examples/analysis/unknown-sink.yaml \
  --semgrep-json fixtures/semgrep/taint-result-with-source-control-local-var-trace.json \
  --source-root fixtures/reachability/flask-source-control-local-var-app \
  --affected-base-url http://127.0.0.1:5001 \
  --fixed-base-url http://127.0.0.1:5002
```

当前 live runner 只允许 `localhost` / `127.0.0.1` / `::1`，且不能和 `--execution-json`
混用；它只抓首跳响应，不自动启动服务，也不连接公网目标。

## 项目文档

- [Insight 决策流程](docs/Insight/README.md)
- [术语表](docs/glossary.md)
- [漏洞分析方法论](docs/methodology.md)
- [Benchmark 与 Case Harness](docs/benchmark.md)
- [Benchmark Baseline](docs/benchmark-results.md)
- [架构说明](docs/architecture.md)
- [产品目标与需求](docs/product.md)
- [路线图](docs/roadmap.md)
- [开发流程](docs/development.md)
- [Git 管理](docs/git.md)
- [测试策略](docs/testing.md)
- [决策记录](docs/decisions/)

## Python 环境

项目使用 Python 3.10 系列：

```bash
uv sync --dev
uv run python --version
```

`.python-version` 和 `pyproject.toml` 会共同约束项目 Python 版本。

`uv.toml` 已配置国内镜像：

- Python 包索引：清华 PyPI 镜像
- Python 解释器下载：NJU `python-build-standalone` GitHub Release 镜像

## 沟通与文档语言

项目文档、任务说明、交付总结以及 Codex 与用户沟通默认使用中文。

文件名、命令、API 名、日志、第三方输出以及必要技术术语可以保留英文。

## 决策记录

关键设计和架构调整先记录到 `docs/Insight/`，完成多视角讨论和最终决策后，再按需同步到 `docs/decisions/`。

## 路线图

当前阶段、下一步任务和里程碑计划见 [路线图](docs/roadmap.md)。
