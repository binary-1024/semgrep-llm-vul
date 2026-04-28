# Benchmark 与 Case Harness

本文档定义项目如何使用公开 benchmark、真实漏洞 case 和项目自建 curated cases 来验证能力边界。

benchmark/case harness 不替代单元测试。它的职责是持续回答：

- 当前系统能在哪些样例上找到正确 sink？
- 哪些 case 会误报、漏报或无法判断？
- 哪些结论只有 candidate，哪些已经 reachable、triggerable 或 verified？
- 哪些失败应转化为规则、fixture、测试或架构调整？

这个 worktree 的目标是建立一套轻量、可持续的 benchmark/case 收集方式，用知名
benchmark、真实漏洞 case 和 curated minimal case 变相测试当前开发能力、边界和缺陷。
具体来源候选记录在 [`benchmarks/sources.md`](../benchmarks/sources.md)。

当前可复现的 baseline 记录在 [`benchmark-results.md`](benchmark-results.md)。

## 数据来源分层

### synthetic_benchmark

合成或半合成 benchmark，用于验证规则覆盖和误报/漏报。

候选来源：

- NIST SARD / Juliet。
- OWASP Benchmark。

使用原则：

- 仓库只提交抽样 case 的 manifest、最小裁剪样例或引用，不提交完整大数据集。
- benchmark 分数只能作为辅助指标，不能替代证据链质量。
- 对每个抽样 case 标注原始来源、许可、漏洞类别和裁剪方式。

### real_vulnerability

真实漏洞 case，用于验证项目是否能处理真实 repo、版本、patch 和验证环境。

候选来源：

- Vul4J。
- CVEfixes。
- 公开 CVE patch。
- 真实项目安全修复 PR。

使用原则：

- 优先选择有明确 affected version、fixed version、patch 和可复现说明的 case。
- PoC/exp 默认只记录状态和安全边界，未经决策不提交真实攻击脚本。
- 真实 case 必须标注 blocked/unsupported 原因，不能只保留成功样例。

### curated_minimal

项目自建最小 case，用于快速验证某个具体边界，例如：

- `safe_redirect` 不应被误判为 `redirect`。
- diff 中删除行和新增行应保留不同 evidence。
- Semgrep `rule_id` 子串不应单独生成 sink。

使用原则：

- 尽量小、离线、确定性。
- 每个 case 只验证一个核心边界。
- 如果来自真实漏洞简化，需要在 notes 中说明简化内容。

## Case Schema

每个 case 目录包含：

```text
case.yaml
expected.json
notes.md
```

`case.yaml` 描述输入、来源和运行边界。

`expected.json` 描述当前期望输出。它不是永远正确的真理；当项目能力提升或发现期望有误时，应通过 review 更新。

`notes.md` 记录背景、证据链、失败模式和复盘。

## 状态语义

- `candidate`：只验证候选 sink 或候选路径。
- `reachable`：静态或半自动证据支持路径可触达。
- `triggerable`：PoC 已能触发目标行为。
- `verified`：受影响版本和修复版本对照验证通过。
- `unsupported`：当前能力明确不支持。
- `blocked`：缺少环境、版本、依赖或权限。

状态只能向证据充分的方向升级；如果证据被反驳，应降级并记录原因。

## 安全边界

- 不提交真实凭据、私有源码、敏感扫描输出或未授权目标信息。
- 不提交破坏性 payload。
- PoC/exp 进入仓库前必须有明确隔离环境和执行边界。
- 外部 benchmark 或 case 的许可证、来源和裁剪方式必须可追溯。
- 大数据集、下载缓存和生成产物不得进入版本库。

## 当前不足与优化优先级

当前 harness 已能提供日常摘要、baseline 生成和 M1/M2 executable suite，但仍然偏小、偏 curated，不应解释为整体漏洞分析准确率。

已经解决或已有入口的点：

- `./scripts/benchmark-summary` 提供日常短摘要，避免开发者只看完整 JSON 报告。
- `uv run semgrep-llm-vul benchmark-baseline --markdown` 可生成 baseline 计数和 gaps，减少手工更新漂移。
- `benchmark-summary` 输出已使用 `inventory_evaluation` 和 `executable_suite` 区分 inventory/gap evaluation 与可执行 case suite。
- `benchmark-summary` 已带有 `scope` 和 `known_limitations`，用于解释 M2 在 inventory evaluator 中是 `unsupported_stage`、但在 executable suite 中可以通过的情况。

仍需优化的点按优先级排列：

1. 增加能力边界 case，而不是只增加 happy path。
   优先补 wrapper、alias、indirect call、多文件路径、trace 缺失、sanitizer 充分/不充分、source/sink 名称相似但语义不同等 case。
2. 建立 known gap 机制。
   对当前明确做不到、但希望未来打穿的 case，应能记录为已知能力缺口，而不是只能在 `blocked`、`unsupported` 或失败之间选择。该机制会影响 case schema，进入实现前需要先做 Insight/ADR。
3. 强化 fixture provenance。
   外部工具 fixture 应明确标注是 `minimal`、真实输出裁剪、generated output，还是合成近似结构，并说明生成命令、来源和覆盖的失败模式。
4. 增加 report contract 测试。
   sink、taint path、reachability 和后续 PoC/exp report 是 agent 消费的接口，字段结构、三态语义和证据链位置需要稳定性测试。
5. 在 M3/M4 前建立安全执行 harness。
   PoC/exp 进入可执行阶段前，需要隔离、timeout、资源限制、危险动作分类和默认禁止联网/敏感路径写入等边界。

优化 harness 时遵循“主线支撑够用即停”：

- 当前主线仍是 M2 污点路径与可触达确认。
- harness 支线优先补能暴露 M2 缺陷的 case 和契约测试。
- 除非 M3/M4 即将进入实现，否则不提前构建完整 PoC/exp 执行平台。

## 后续实现方向

第一阶段：

- 固化 `benchmarks/` 目录和 case schema。
- 维护 3 到 5 个小型 curated cases。
- 建立 benchmark/case 来源目录，记录来源价值、采样方向和暂不采样原因。

第二阶段：

- 实现 case loader。
- 实现 M1 sink generation evaluator。
- 输出 per-case pass/fail/blocked/unsupported 报告。

当前最小 evaluator 已提供 CLI：

```bash
uv run semgrep-llm-vul validate-benchmarks
uv run semgrep-llm-vul evaluate-benchmarks --artifact-base .
uv run semgrep-llm-vul benchmark-summary --artifact-base . --repo-root .
```

`validate-benchmarks` 只校验 case 目录并输出 inventory；`evaluate-benchmarks`
第一版只支持 M1 sink generation case。它会读取 `benchmarks/cases/<case-id>/case.yaml`
和 `expected.json`，调用本地 deterministic sink pipeline，并比较 `sink_candidates`
与 `must_not_include`。

当前最小 evaluator 已支持评估单个 M1/M2 case：

```bash
uv run semgrep-llm-vul evaluate-case \
  benchmarks/cases/curated-open-redirect-safe-wrapper \
  --repo-root .
```

也可以批量评估当前 `benchmarks/cases/` 下的 M1/M2 cases：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root .
```

日常回归建议使用摘要输出，避免完整阶段报告干扰快速判断：

```bash
./scripts/benchmark-summary
```

更新 baseline 文档时，优先由命令生成当前计数和 gaps，再人工补充能力边界解释：

```bash
uv run semgrep-llm-vul benchmark-baseline --artifact-base . --repo-root . --markdown
```

`benchmark-summary` 的 JSON contract 当前使用 `schema_version=2`：

- `inventory`：case 清单、来源覆盖、声明状态和阶段覆盖。
- `inventory_evaluation`：M1 sink generation inventory/gap evaluation。这里的 M2 `unsupported_stage` 只表示 inventory evaluator 尚未扩展到 M2。
- `executable_suite`：M1/M2 staged executable case checks。M2 pass/fail 以这一层为准。
- `known_limitations`：解释当前 summary 输出中可能被误读的限制。

第三阶段：

- 扩展到 M2 reachability、M3 PoC、M4 exp。
- 支持外部 benchmark 下载缓存，但不提交原始大数据。
