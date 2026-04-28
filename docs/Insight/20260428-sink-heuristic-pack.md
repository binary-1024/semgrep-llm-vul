# Insight: sink heuristic pack

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：M1 sink 函数生成
- 关联 ADR：`docs/decisions/0008-use-local-sink-heuristic-pack.md`
- 决策类型：分析策略 | 数据模型 | 工程流程

## 背景

M1 已经具备最小 sink generation pipeline，可以从 known sink、Semgrep finding、diff artifact 和漏洞片段中提取候选 sink。当前实现仍使用内置的危险函数名元组，例如 `redirect`、`exec`、`eval`、`system`。

这个做法足以验证 pipeline，但不适合继续扩展：不同语言、框架和漏洞类型的 sink 命名差异很大；如果继续把规则写死在代码常量里，后续会难以审查、难以测试，也容易把规则语义和 pipeline 控制流混在一起。

## 决策问题

M1 下一步应如何把写死的危险调用名扩展成可维护、可测试、语言相对无关的 sink heuristic pack？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：sink 识别不是简单字符串匹配，而是在代码调用表达式中识别“危险行为类别”和“具体 API”之间的候选映射。
- 最小必要能力：规则需要能表达 `name`、`category`、可选 `languages`、`confidence` 和说明，并能在 diff、snippet、Semgrep finding 中复用。
- 不可牺牲约束：规则只能产生 candidate evidence，不能把命中直接升级成 reachable、triggerable 或 verified。
- 最大风险：规则过宽会造成高噪声，尤其是把 `safe_redirect`、`is_safe_redirect` 这类安全封装误判为 `redirect`。

### 工程化专家

- 根本问题：规则需要可审查、可回归，而不是散落在多个函数里的硬编码条件。
- 最小必要能力：先用本地内置数据结构集中定义规则，并通过 fixture 测试覆盖 positive、negative 和 malformed 场景。
- 不可牺牲约束：第一版不能引入动态加载、远程规则源或复杂插件体系，否则 harness 边界会变大。
- 最大风险：过早抽象 provider 接口会让简单规则配置变成框架工程，拖慢 M1 验证。

### 漏洞安全专家

- 根本问题：sink 规则应该服务于漏洞验证路径，不是罗列所有危险 API。规则必须保留证据链和不确定性。
- 最小必要能力：每条规则要能说明为什么这个调用可能是 sink，以及后续需要验证什么。
- 不可牺牲约束：命中规则后仍需后续污点路径和 PoC/exp 验证；不能因为规则名称带有 “critical” 等字样就提高到确认结论。
- 最大风险：规则 pack 如果缺少反例测试，会让后续 taint path 从错误 sink 出发，放大误报成本。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：Semgrep、CodeQL、ESLint security rules 等通常以规则包组织 sink/source/sanitizer 模式，并把规则命中作为静态证据。
- 备选方案：
  - A. 继续硬编码函数名。
  - B. 本地内置 heuristic pack。
  - C. 外部 YAML/JSON 规则文件。
  - D. 直接复用 Semgrep rule metadata。
- 优点：A 最简单；B 可测试且边界小；C 易扩展；D 能借助现有生态。
- 缺点和失败模式：A 难维护；C 需要 schema、加载和错误处理；D 依赖外部规则质量，且 metadata 不一定表达 sink 调用本身。

### 工程化专家

- 业界常见做法：成熟工具通常把规则定义、规则执行和报告输出分层；早期项目常先用内置规则集打通 schema，再考虑外部配置。
- 备选方案：
  - A. 用 tuple/list 继续维护。
  - B. 用 dataclass 定义本地规则对象。
  - C. 引入插件式 provider。
  - D. 引入规则 DSL。
- 优点：B 对当前阶段足够明确，能给后续外部配置留出 schema 形状；C/D 扩展性强。
- 缺点和失败模式：C/D 需要更多错误边界和文档，当前没有足够真实规则来证明必要性。

### 漏洞安全专家

- 业界常见做法：安全扫描规则一般按漏洞类别维护，例如 command injection、open redirect、deserialization，并把 confidence/severity 与证据来源分开。
- 备选方案：
  - A. 仅按函数名匹配。
  - B. 按漏洞类别组织函数名和说明。
  - C. 将 sanitizer/source/sink 全部放入同一个 pack。
- 优点：B 能让报告解释更清晰，也方便后续从 sink 扩展到 source/sanitizer。
- 缺点和失败模式：C 容易把 M1 和 M2 的边界混在一起；当前应只覆盖 sink heuristic。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果只用函数名，如何区分 `redirect` 和 `safe_redirect`？
- 需要验证的假设：现有调用表达式解析已经按完整调用名的末段精确匹配，规则 pack 可以继续复用这个边界。
- 当前最小可行决策：引入本地内置 `SinkHeuristic` 规则对象，先表达危险调用名、类别、语言、置信度和说明。
- 验证 harness：保留已有 `safe_redirect` negative fixture，并新增规则 pack 的正向和反向单元测试。

### 工程化专家

- 对其他方案的质询：现在是否应该读取外部 YAML 规则？
- 需要验证的假设：在没有足够真实用户规则之前，外部加载会增加无关复杂度；内置 dataclass 可以先稳定 schema。
- 当前最小可行决策：第一版只做代码内内置 pack，不做动态加载，不做 CLI 参数。
- 验证 harness：`./scripts/check` 必须覆盖规则对象、匹配函数、sink generation pipeline 输出。

### 漏洞安全专家

- 对其他方案的质询：规则 confidence 是否会被误解为漏洞确认概率？
- 需要验证的假设：报告中继续使用 candidate/evidence 语义，并在 rule reasoning 中明确“需要后续路径和触发验证”。
- 当前最小可行决策：规则 confidence 只作为候选排序初值或证据 confidence，不代表可触达或可利用。
- 验证 harness：测试断言命中规则后仍输出 `SinkCandidate`，不输出 verified 状态。

## 最终决策

M1 下一步引入本地内置 sink heuristic pack，用集中定义的规则对象替代散落的硬编码危险函数名。

第一版规则对象至少包含：

- `name`：规则标识。
- `call_names`：精确匹配的危险调用末段或全名。
- `category`：漏洞或危险行为类别，例如 `open_redirect`、`command_execution`、`deserialization`。
- `languages`：可选语言范围；为空表示语言无关启发式。
- `confidence`：候选证据置信度初值。
- `description`：规则命中的安全含义。

规则 pack 的职责：

- 为 diff、snippet、Semgrep finding 提供统一的危险调用匹配来源。
- 为证据链提供规则名、类别和说明。
- 继续保持本地、确定性、可测试。

规则 pack 不负责：

- 动态下载或加载外部规则。
- 直接确认 sink 可触达或漏洞可利用。
- 表达 source、sanitizer 或完整 taint 规则。
- 替代 Semgrep/CodeQL 等专业分析工具。

## 为什么现在这样做

- M1 已经通过最小 pipeline 验证了证据优先数据流，可以开始增强候选提取能力。
- 现有硬编码函数名已经暴露维护压力，继续堆常量会降低可审查性。
- 本地内置 pack 能在不扩大运行环境和安全边界的情况下，提高多语言/多漏洞类别扩展能力。
- 这个抽象为后续外部 YAML/JSON 规则文件、Semgrep metadata 对齐、LLM 辅助规则建议留下演进空间。

## 不采用的方案

- 继续硬编码 `DANGEROUS_CALL_NAMES`：不采用。短期简单，但后续难以承载类别、说明、置信度和语言范围。
- 第一版直接读取外部 YAML/JSON 规则：暂不采用。需要新增 schema、加载错误、路径安全和文档边界，当前收益不足。
- 第一版引入插件式 provider：暂不采用。现阶段只有一个本地 heuristic source，插件化过早。
- 依赖 Semgrep rule_id 推断 sink：不采用。已有 negative fixture 证明规则名子串会造成无代码调用证据的误判。

## 验证方式

后续 feature 分支至少验证：

- rule pack 中的调用名能生成与现有行为一致的 sink candidate。
- evidence metadata 包含 rule 名称和类别。
- `safe_redirect`、`is_safe_redirect` 等安全封装仍不会被子串误判。
- diff、snippet、Semgrep finding 继续共享同一匹配逻辑。
- `./scripts/check` 通过。

## 重新评估条件

以下情况出现时重新评估本决策：

- 需要用户自定义规则或项目级规则。
- 需要读取 Semgrep/CodeQL/SARIF 的规则 metadata 并映射到内部规则。
- 需要表达 source、sanitizer、propagator 或完整 taint spec。
- 内置规则数量超过人工审查舒适范围。
- LLM agent 开始参与规则建议或规则生成。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
