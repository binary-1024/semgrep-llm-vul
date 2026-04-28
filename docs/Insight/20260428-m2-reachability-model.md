# Insight: M2 可触达确认最小模型

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：M2 污点路径生成与可触达确认
- 关联 ADR：`docs/decisions/0010-use-local-reachability-evidence-model.md`
- 决策类型：分析策略 | 数据模型 | 安全边界

## 背景

项目已经具备最小 taint path candidate generation：可以把 M1 sink candidate 与 Semgrep taint-mode trace 对齐，生成 `TaintPath(reachable=None)`。这说明系统能提出“候选路径”，但还不能回答这条路径是否能从真实入口到达。

如果不先定义 reachable 的证据标准，后续 PoC 生成会把 candidate path 当成可触发事实，导致误报被放大。因此 M2 下一步必须先定义本地、确定性、可审查的 reachability 最小模型，再进入实现。

## 决策问题

M2 第一版应如何在不实现完整跨语言调用图、不联网、不调用真实 LLM 的前提下，把 `reachable=None` 的候选路径升级为 `reachable=true/false` 或保持 unknown？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：taint path 只证明数据流候选存在，reachability 需要证明 source 所在上下文能从程序入口被调用到。
- 最小必要能力：入口模型、路径所在函数或文件的锚点、入口到路径节点的局部可达证据、阻断证据。
- 不可牺牲约束：不能把 Semgrep trace 直接等同于可触达；不能因为找不到入口就断言不可达。
- 最大风险：早期实现过度追求完整调用图，导致语言绑定过重、性能不可控、验证困难。

### 工程化专家

- 根本问题：reachable 需要稳定 schema 和可回归 harness，否则每次新增框架支持都会破坏已有判断。
- 最小必要能力：结构化 reachability report、可解释 evidence、unknowns、fixture 化的 positive/negative/unknown case。
- 不可牺牲约束：本地确定性、无外部服务依赖、失败可复现。
- 最大风险：把框架路由、调用图、版本对照和 sanitizer 判断一次性揉在一起，造成不可测试的大模块。

### 漏洞安全专家

- 根本问题：漏洞验证链路需要区分 candidate、reachable、triggerable、verified；reachable 只是“入口可到达路径”，不是漏洞可利用。
- 最小必要能力：入口类型、source 可控性、sink 路径可达性、sanitizer/guard 的初步阻断记录。
- 不可牺牲约束：`reachable=true` 不能自动进入 PoC/exp 成功结论；必须保留残余 unknowns。
- 最大风险：把“有路由”误认为“攻击者可控”，或者把“有 sanitizer 名称”误认为“安全”。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：静态分析通常把数据流图、调用图、taint tracking 和 path query 分层处理。CodeQL 文档区分 local data flow 与 global data flow，并指出全局数据流更昂贵；Semgrep taint-mode 用 sources、sinks、sanitizers、propagators 描述污点语义，并提供跨函数/跨文件相关选项。
- 备选方案：
  - A. 完整跨语言调用图和跨文件数据流。
  - B. 仅使用 Semgrep trace，认为存在 trace 即 reachable。
  - C. 本地最小 reachability evidence model：先证明入口锚点和路径上下文之间的可达证据，再分阶段扩展。
- 优点：C 能保持语言无关核心，只把语言和框架知识放进 adapter 或 fixture；可以快速进入 M2 验证。
- 缺点和失败模式：C 的第一版覆盖率有限，需要诚实输出 unknown；如果 evidence schema 太弱，会难以升级到 M3。

### 工程化专家

- 业界常见做法：成熟 SAST/CodeQL 类工具会通过可配置 query、模型库和 path report 管理复杂度；工程上通常先做可回归的最小样例，再扩展语言和框架模型。
- 备选方案：
  - A. 直接接入 CodeQL/Joern 等外部工具生成 reachability。
  - B. 自研完整分析引擎。
  - C. 先定义统一 report 和 evidence schema，第一版用本地 heuristic/fixture 驱动。
- 优点：C 能复用现有 `TaintPathGenerationReport`、benchmark/case harness 和 `./scripts/check`。
- 缺点和失败模式：C 需要明确“不支持”与“unknown”的差异，否则会被误解为能力不足或误判。

### 漏洞安全专家

- 业界常见做法：漏洞 triage 会把静态命中、入口可达、攻击者可控、sanitizer 充分、版本对照和运行验证逐步升级；任何一步缺证据都应保持 inconclusive，而不是强行确认。
- 备选方案：
  - A. 只要 source 到 sink 有 taint path 就生成 PoC。
  - B. 只有动态验证成功才承认 reachable。
  - C. reachable 作为 M2 中间结论，只表示从入口到路径的静态可达性，triggerable/verified 留给 M3/M4。
- 优点：C 能阻止 PoC 过早建立在弱证据上，同时不会要求 M2 承担动态运行环境。
- 缺点和失败模式：C 仍可能遗漏运行时路由条件、鉴权、配置开关和环境依赖，必须保留 residual unknowns。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：完整调用图在当前阶段会把项目拉向语言专用分析器；仅依赖 Semgrep trace 又无法证明入口可达。
- 需要验证的假设：少量入口模型和局部调用证据足以支撑第一批 M2 case。
- 当前最小可行决策：建立 `ReachabilityAssessment` 概念，输出 `reachable=true|false|null`、entrypoint、call_chain、blocking_factors、unknowns 和 evidence。
- 验证 harness：至少覆盖 Flask route 到 sink 的 positive、未注册函数的 unknown、显式 guard/sanitizer 的 blocked 或 unknown。

### 工程化专家

- 对其他方案的质询：如果不先定 schema，实现会不断改报告结构，导致 CLI、benchmark 和后续 PoC 都跟着震荡。
- 需要验证的假设：M2 第一版可以只支持本地文件和 fixture，不需要真实 repo clone。
- 当前最小可行决策：新增 reachability report 的序列化约定，但第一版实现可以只在现有 `TaintPath` 外包装 assessment，不改 Semgrep adapter。
- 验证 harness：新增 M2 reachability curated cases；`./scripts/check` 和 `./scripts/benchmark` 保持通过。

### 漏洞安全专家

- 对其他方案的质询：`reachable=false` 比 `reachable=true` 更危险，因为静态分析很容易漏掉动态调度；第一版必须谨慎使用 false。
- 需要验证的假设：只有存在强阻断证据时才输出 false；缺入口、缺框架模型、缺调用边都保持 null。
- 当前最小可行决策：reachable 的状态语义为：true 表示静态证据支持入口可到达；false 表示有明确阻断证据；null 表示候选路径存在但可达性未确认。
- 验证 harness：每个 true/false/null case 都必须记录为什么不是另外两个状态。

## 最终决策

M2 采用本地、确定性、证据优先的 reachability evidence model。

第一版只做静态可触达确认，不做 PoC 触发确认，也不做 exp 验证。`reachable` 的语义如下：

- `true`：存在本地静态证据支持入口到候选路径上下文可达，例如框架路由、公开 handler、明确调用链或测试入口到 sink 所在函数的链路。
- `false`：存在明确阻断证据，例如函数未注册且仅死代码可见、路径被确定性 guard 阻断、版本对照显示路径不在受影响版本中。第一版应谨慎输出 false。
- `null`：候选路径存在，但入口、调用链、source 可控性、sanitizer/guard 或版本证据不足。

第一版 reachability assessment 至少包含：

- `path_id` 或可追溯到候选 `TaintPath` 的引用。
- `reachable`。
- `entrypoint`：入口类型、名称、位置、证据。
- `call_chain`：入口到 source/sink 上下文的函数或文件链；没有则为空。
- `source_control`：source 是否可能由外部输入控制；不足则 unknown。
- `blocking_factors`：sanitizer、guard、版本差异、不可达分支等阻断证据。
- `evidence`：每条判断的来源、位置、置信度、推理说明。
- `unknowns`：阻止升级为更强结论的问题。

## 为什么现在这样做

- M2 已经具备 candidate path，但还不能支撑 M3 PoC。
- reachability 是 candidate path 到 PoC 的关键门槛，必须先定义清楚。
- 本项目核心目标是证据链，而不是单一静态命中数量。
- 本地最小模型能快速落入 harness，避免一开始陷入完整跨语言调用图。

## 不采用的方案

- 直接把 Semgrep taint trace 当作 reachable：不采用。Semgrep trace 是候选数据流证据，不证明入口可达或攻击者可控。
- 直接实现完整跨语言调用图：不采用。当前阶段成本高、语言绑定重、难以用小 harness 稳定验证。
- 只有动态运行成功才输出 reachable：不采用。动态验证属于 M3/M4；M2 需要静态可触达中间结论。
- 缺少入口就输出 unreachable：不采用。缺证据应保持 `null`，避免静态漏报被伪装成否定结论。

## 验证方式

- 新增 M2 reachability fixture/case：
  - positive：框架入口或测试入口明确调用到 taint path。
  - unknown：存在 taint path，但缺入口模型或调用链证据。
  - blocked：存在明确 guard/sanitizer/版本阻断证据。
- 单元测试验证 `true/false/null` 状态语义、evidence、unknowns 和 blocking factors。
- benchmark/case harness 增加 M2 reachability case，防止后续把 candidate 误升级。
- `./scripts/check` 必须通过。

## 参考资料

- CodeQL: About data flow analysis, https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/
- Semgrep: Advanced taint analysis techniques, https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/advanced
- Semgrep: Rule structure syntax, https://semgrep.dev/docs/writing-rules/rule-syntax

## 重新评估条件

- 第一批 reachability case 中，`null` 过多导致无法支撑 M3 PoC。
- 需要支持的框架入口模型明显超过本地 heuristic 可维护范围。
- 引入 CodeQL、Joern、SARIF path 或真实 repo clone 后，现有 schema 无法承载外部证据。
- 安全边界进入动态运行或 exp 自动化阶段。

## 后续动作

- [x] 同步新增或更新 `docs/decisions/`
- [x] 更新 `docs/architecture.md`
- [ ] 更新 `docs/product.md`
- [ ] 更新测试或 fixture
