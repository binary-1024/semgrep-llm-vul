# Architecture Insight: Semgrep taint-mode 归一化到 TaintPath/Evidence

## 元信息

- 日期：2026-04-27
- 状态：Accepted
- 关联任务：Semgrep taint-mode 结果建模与归一化
- 关联 ADR：`docs/decisions/0004-normalize-semgrep-taint-as-evidence.md`
- 影响范围：数据模型 | Semgrep 适配层 | 污点路径 | 证据链 | agent 流程

## 背景

项目已经建立语言无关核心模型，并实现了 Semgrep JSON finding 到 `NormalizedFinding` 的最小归一化。

下一步要决定：Semgrep taint-mode 的 source、sink、propagator、sanitizer 和可选 taint trace，应该如何映射到项目内部的 `TaintPath`、`SourceCandidate`、`SinkCandidate`、`TaintStep` 和 `Evidence`。

这个决策会影响后续污点路径生成、可触达确认、PoC 生成和 exp 验证，因此需要先完成 Insight，再进入实现。

## 架构问题

如何在不绑定具体语言、不假设 Semgrep 输出总是完整的前提下，将 Semgrep taint-mode 结果归一化为可追溯、可扩展、可验证的内部污点路径证据？

## 参考资料

- Semgrep taint analysis 官方文档：`https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview`
- Semgrep advanced taint analysis 官方文档：`https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced`
- Semgrep cross-file dataflow traces 官方文档：`https://semgrep.dev/docs/semgrep-code/semgrep-pro-engine-data-flow`
- Semgrep CLI 输出与 JSON schema 官方说明：`https://semgrep.dev/docs/getting-started/cli`
- Semgrep dataflow 去重说明：`https://semgrep.dev/docs/kb/semgrep-code/finding_all_taints`

## 第 1 轮：第一性原理拆解

### 资深 agent 开发架构师

- 根本问题：agent 后续要基于 Semgrep 结果继续推理、补证据和生成 PoC，因此不能只保存扫描器原始 finding，必须形成稳定的内部可交换结构。
- 最小必要能力：把 Semgrep finding 中的 source、sink、trace 节点和 rule metadata 映射到统一证据结构；保留原始字段，允许后续 agent 复核。
- 不可牺牲约束：不能把 Semgrep 的一条 trace 当成完整真相；不能丢失原始证据；不能让 agent 只能读自然语言摘要。
- 最大风险：如果早期模型过度拟合 Semgrep 当前 JSON 结构，后续 Semgrep 版本、Pro/CE 差异或 SARIF/JSON 差异会让模型脆弱。

### 软件工程师

- 根本问题：需要一个可测试、可演进的 adapter 层，把外部工具输出和内部领域模型隔离。
- 最小必要能力：新增 Semgrep taint fixture，覆盖有 trace 和无 trace 两类结果；提供显式错误处理；确保 `./scripts/check` 能验证映射。
- 不可牺牲约束：实现必须保持小范围；不引入重依赖；不在数据模型里硬编码某种语言或某个 Semgrep 版本。
- 最大风险：为了追求完整抽象一次性设计过多字段，导致模型难以维护，测试也无法证明它真的有用。

### 程序分析专家

- 根本问题：污点分析本质上是 source 到 sink 的数据流事实，但 Semgrep 的输出可能只是一条代表路径，不一定包含所有路径。
- 最小必要能力：区分 source、sink、propagator/sanitizer 证据、trace step、路径可达性状态，以及“未确认”状态。
- 不可牺牲约束：不能把静态分析 finding 直接等同于可利用漏洞；必须保留 sanitizer、propagator、路径缺口和语言差异。
- 最大风险：忽略 Semgrep 的分析边界，例如 intra-file/inter-file 能力差异、去重策略和规则质量，导致后续可触达判断过度自信。

### 漏洞安全专家

- 根本问题：安全结论需要证据链，而不是只有 “source reaches sink” 的标签。
- 最小必要能力：每条 taint path 必须能回答：危险输入是什么、危险操作是什么、中间如何传播、是否被净化、为什么仍有风险。
- 不可牺牲约束：PoC/exp 前必须区分“静态可疑路径”和“确认可触达路径”；不能生成破坏性利用代码作为默认行为。
- 最大风险：把误报路径直接推进到 PoC 生成，浪费分析成本，甚至产生不安全输出。

## 第 2 轮：业界做法与备选方案

### 资深 agent 开发架构师

- 业界常见做法：SAST 工具通常输出工具私有 finding，再通过 SARIF、JSON 或内部 schema 进入平台；agent 系统通常需要再做一层 evidence normalization。
- 备选方案：
  - 方案 A：直接把 Semgrep JSON 暴露给后续 agent。
  - 方案 B：强制转换成项目内部 `TaintPath`。
  - 方案 C：双层模型，先归一化为 `NormalizedFinding`，再可选派生 `TaintPath` 和 evidence。
- 优点：方案 C 兼顾工具保真和项目抽象，适合逐步扩展到 CodeQL、Joern 或自研分析器。
- 缺点和失败模式：方案 C 多一层转换，需要维护映射逻辑和 fixture；如果 evidence 太弱，agent 仍可能过度推断。

### 软件工程师

- 业界常见做法：adapter 层通常保留 raw payload 或 raw metadata，内部模型只抽取稳定字段，避免外部 schema 漂移导致核心模型频繁改动。
- 备选方案：
  - 方案 A：把所有 Semgrep 字段完整塞进 `TaintPath`。
  - 方案 B：只抽取 path、line、message 等最小字段。
  - 方案 C：稳定字段结构化，非稳定字段进入 `metadata` 或 `raw_trace`。
- 优点：方案 C 可测试、可回滚、可兼容多版本。
- 缺点和失败模式：调用方需要理解哪些字段是强语义字段，哪些只是 raw evidence。

### 程序分析专家

- 业界常见做法：污点分析通常建模为 source、propagator、sanitizer、sink 和 path；跨过程/跨文件能力通常受引擎和配置限制。
- 备选方案：
  - 方案 A：只使用 Semgrep CE 单函数/单文件 taint 结果。
  - 方案 B：使用 Semgrep Pro 或 Semgrep Code 的 dataflow trace 作为增强证据。
  - 方案 C：把 Semgrep trace 作为一种候选路径证据，再用后续调用图/agent/动态验证确认。
- 优点：方案 C 不把某个工具当作唯一真相，适合本项目“多阶段证据链”目标。
- 缺点和失败模式：需要额外阶段确认 reachability；短期内不能宣称完整路径覆盖。

### 漏洞安全专家

- 业界常见做法：安全平台通常把 SAST finding 分成“检测结果”和“验证结果”，后者需要 reachability、环境、版本和 exploitability 证据支持。
- 备选方案：
  - 方案 A：Semgrep 命中即视为漏洞。
  - 方案 B：Semgrep 命中只作为候选，后续确认路径可达性。
  - 方案 C：要求受影响版本和修复版本对照验证后才进入 exp 结论。
- 优点：方案 B/C 能降低误报，并自然连接 PoC/exp 阶段。
- 缺点和失败模式：分析链路变长，需要明确阶段状态，避免用户误读中间结果。

## 第 3 轮：交叉质询与收敛

### 资深 agent 开发架构师

- 对其他方案的质询：如果只做 `TaintPath`，无 trace 的 Semgrep finding 如何参与后续 agent 推理？如果只做 raw JSON，agent 如何稳定消费？
- 需要验证的假设：Semgrep JSON 中 taint trace 字段可能随版本和输出格式变化；模型必须容忍 trace 缺失。
- 当前最小可行架构：`NormalizedFinding` 保持扫描器 finding；新增 `TaintTrace` 或扩展 `TaintPath` 归一化函数，把可识别 trace 转成 path，不能识别的部分进入 evidence metadata。
- 验证 harness：fixture 至少覆盖有 trace、无 trace、畸形 trace 三类输入。

### 软件工程师

- 对其他方案的质询：一次性设计过多模型会拖慢项目；是否可以先做 parser contract，再逐步丰富字段？
- 需要验证的假设：当前 `TaintPath` 模型是否足够表达 Semgrep trace 的 source、intermediate vars、sink；如果不够，应小幅扩展而不是重写。
- 当前最小可行架构：新增 Semgrep taint normalization 函数，不修改现有公共 API 的语义；必要时新增 `TaintRole` 和 `TraceStepKind` enum。
- 验证 harness：测试断言输出中的 source、sink、steps、evidence、confidence 和 raw metadata。

### 程序分析专家

- 对其他方案的质询：Semgrep 官方说明会对 taint findings 做去重，并可能只报告一条代表 trace；如果我们把它命名为“完整污点路径”，会误导后续阶段。
- 需要验证的假设：trace 中的 intermediate steps 能否稳定映射为 ordered steps；不同版本输出的字段名需要通过 fixture 扩展确认。
- 当前最小可行架构：内部命名采用“observed trace”或“reported path”，可达性默认 `reachable=None`，直到后续确认阶段再置为 `True/False`。
- 验证 harness：fixture 中显式标注“Semgrep reported one trace, not all possible traces”。

### 漏洞安全专家

- 对其他方案的质询：如果 evidence 没有阶段状态，用户会把静态 finding 当作 exp 结论；必须在模型中保留风险级别和未确认项。
- 需要验证的假设：Semgrep rule metadata 中的 cwe、category、confidence、likelihood 等字段可以作为安全语义补充，但不能替代验证结论。
- 当前最小可行架构：每条由 Semgrep 派生的 `TaintPath` evidence 都应写明“静态分析候选路径，尚未确认可触达或可利用”。
- 验证 harness：测试 evidence.open_questions 包含可达性、sanitizer、版本对照等未确认项。

## 最终架构决策

采用“双层归一化”：

1. Semgrep 原始结果先归一化为 `NormalizedFinding`。
2. 如果 finding 中存在可识别 taint trace，则进一步派生为内部 `TaintPath`。
3. 如果 trace 缺失或不完整，仍保留为 `NormalizedFinding`，并生成 evidence 说明“仅有 finding，无完整 trace”。
4. `TaintPath.reachable` 默认保持 `None`，表示尚未完成可触达确认。
5. 所有 Semgrep 派生的路径都必须保留 raw metadata 或 raw trace 摘要，作为后续复核依据。

## 架构边界

- Semgrep adapter 只负责解析和归一化，不负责判断漏洞是否真实可利用。
- `TaintPath` 表示“报告路径”或“候选路径”，不是最终可达漏洞结论。
- 可触达确认、PoC 生成和 exp 验证属于后续里程碑。
- Semgrep CE、Semgrep Pro、SARIF、JSON 的输出差异通过 fixture 和 adapter 兼容，不污染核心模型。

## 模块职责

- `semgrep_llm_vul.semgrep`：解析 Semgrep JSON，生成 `NormalizedFinding`，并在下一步实现 taint trace 到 `TaintPath` 的派生。
- `semgrep_llm_vul.models`：提供语言无关核心模型，必要时小幅新增 trace role / step kind。
- `fixtures/semgrep/`：保存 Semgrep 输出样例，包括 taint-mode、有 trace、无 trace 和异常结构。
- `tests/`：锁定解析 contract 和 evidence 语义。

## 数据流

```text
Semgrep JSON
  ↓
NormalizedFinding
  ↓
可选：Semgrep taint trace parser
  ↓
TaintPath(reachable=None)
  ↓
后续阶段：可触达确认
  ↓
PoC / exp
```

## 失败处理

- 缺少 `results`：抛出解析错误。
- finding 缺少必要字段：抛出解析错误。
- trace 字段存在但无法识别：不丢弃 finding，生成 `NormalizedFinding`，并在 evidence 中记录 trace 未解析。
- trace 只有 sink 没有 source：生成 finding evidence，不生成完整 `TaintPath`。
- 多条可能路径：保留 Semgrep 报告路径，并明确不是完整路径枚举。

## 可观测性

每条由 Semgrep 派生的 evidence 至少包含：

- Semgrep rule id。
- 文件路径和行列位置。
- source/sink/step 的角色。
- 原始 trace 或 trace 摘要。
- 重现命令，例如 `semgrep scan --json`，有 dataflow 输出时记录相应参数。
- 未确认项：可达性、sanitizer 充分性、版本对照、运行环境。

## 验证方式

下一步实现时至少添加：

- `fixtures/semgrep/taint-result-with-trace.json`
- `fixtures/semgrep/taint-result-without-trace.json`
- `tests/test_semgrep_taint.py`

测试覆盖：

- Semgrep taint finding 能生成 `NormalizedFinding`。
- 可识别 trace 能生成 `TaintPath`。
- `TaintPath.reachable is None`。
- source、sink、intermediate step 都有 evidence。
- trace 缺失时不生成误导性的完整 path。

## 重新评估条件

以下情况需要重新评估本决策：

- Semgrep JSON schema 对 dataflow trace 结构发生明显变化。
- 项目开始同时接入 SARIF、CodeQL、Joern 或自研分析器。
- `TaintPath` 需要表达多条分支路径、条件路径或跨服务路径。
- PoC/exp 阶段发现当前 evidence 不足以支撑验证。

## 后续动作

- [x] 同步新增 `docs/decisions/0004-normalize-semgrep-taint-as-evidence.md`
- [x] 实现 Semgrep taint trace fixture
- [x] 实现 Semgrep taint trace 到 `TaintPath` 的归一化函数
- [x] 增加 `tests/test_semgrep_taint.py`
- [x] 根据实现结果更新 `docs/architecture.md`
