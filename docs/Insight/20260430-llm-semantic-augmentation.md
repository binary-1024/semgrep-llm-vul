# Insight: 将 LLM 用作 source/sink/sanitizer 的证据约束语义增强层

## 元信息

- 日期：2026-04-30
- 状态：Accepted
- 关联任务：方法论扩展，讨论 LLM 是否应辅助判断 unfamiliar library API 的 source/sink/sanitizer 语义
- 关联 ADR：0012
- 决策类型：分析策略

## 背景

传统程序分析依赖规则、知识库和人工建模来判断 source、sink、sanitizer 与 propagator。
这条路线有很强的可重复性和可审计性，但也有稳定短板：对长尾库、项目自定义 wrapper、
版本差异和跨生态 API 的知识覆盖并不完整。结果往往是：

- source/sink 识别覆盖不全，recall 受限。
- sanitizer 语义判断过于依赖名字，容易误报或漏报。
- 规则作者必须持续补库，维护成本高且迁移慢。

LLM 具备更强的语义理解和广覆盖知识，且可以结合文档检索、源码检索或 MCP 工具补足上下文。
因此需要决定：在本项目中，LLM 是否应承担 unfamiliar API 的 source/sink/sanitizer 判断职责；
如果承担，应放在什么层、受哪些约束、做到什么程度就停止。

## 决策问题

在 `semgrep-llm-vul` 中，LLM 是否应该替代手写规则来判断 source/sink/sanitizer，还是只作为证据约束的语义增强层？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：程序分析的困难不只是“路径怎么找”，还包括“路径上的节点到底是什么语义”。source/sink/sanitizer 的知识不完备，会直接限制分析覆盖率。
- 最小必要能力：把 unfamiliar API 从“完全未知”提升为“带证据的候选语义判断”，至少能说明它更像 source、sink、sanitizer 还是 unknown。
- 不可牺牲约束：不能让模型的自然语言猜测污染核心数据流骨架；任何语义判断都必须可追溯、可反驳。
- 最大风险：把 LLM 的高 recall 误当成高正确率，尤其在 sanitizer 判断上生成过强结论。

### 工程化专家

- 根本问题：知识覆盖率不足本质上是“静态规则扩展速度慢”，但工程系统还要求稳定性、可重放和可回归。
- 最小必要能力：将 LLM 判断收敛为结构化输出，而不是自由文本；输出必须能被 fixture、benchmark 和 schema 测试锁住。
- 不可牺牲约束：最终主流程仍要可离线验证、可复现、可回退，不能把不稳定外部依赖直接嵌进主判断链。
- 最大风险：版本漂移、检索漂移、模型漂移叠加，导致同一 API 在不同时间得到不一致结论。

### 漏洞安全专家

- 根本问题：source/sink/sanitizer 误判会直接影响漏洞结论，尤其 sanitizer 误判会把本该保守的 unknown 过早升级为 safe。
- 最小必要能力：让系统区分“支持风险成立的证据”和“支持风险被充分消除的证据”，并允许 unknown 持续存在。
- 不可牺牲约束：sanitizer 必须与威胁模型、上下文和版本绑定，不能只凭函数名或文档宣传语判断。
- 最大风险：模型把“看起来像校验/编码”的逻辑错误地当成有效 sanitizer，导致危险的 false negative。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：成熟 SAST/taint 引擎通常以规则 pack、标准库模型、框架模型和人工维护的知识库来表达 source/sink/sanitizer；LLM 更多用于 triage、解释和辅助建模，而不是直接替代数据流规则。
- 备选方案：
  - A. 继续纯手写规则和知识库。
  - B. 让 LLM + 检索在运行时直接判断所有 unfamiliar API。
  - C. 让 LLM 只输出带证据的候选语义，再由规则/harness 决定是否吸收。
- 优点：
  - A 稳定、可重复。
  - B 覆盖广、对长尾库和 wrapper 适应快。
  - C 在覆盖率和可控性之间更平衡。
- 缺点和失败模式：
  - A 扩展慢，对长尾库覆盖差。
  - B 容易把 hallucination、版本误配和上下文误读直接放进主结论。
  - C 仍然需要设计 schema、验证 harness 和知识沉淀流程。

### 工程化专家

- 业界常见做法：大多数工程系统把不稳定智能能力放在“建议层”或“编译层”，而把稳定规则放在“执行层”。
- 备选方案：
  - A. 在线调用 LLM，实时返回 source/sink/sanitizer 判断。
  - B. 离线使用 LLM 生成候选知识，再人工或 harness 审核后编译进本地 pack。
  - C. 两层并存：在线只生成 hypothesis，离线才允许升级为稳定知识。
- 优点：
  - A 集成快，探索效率高。
  - B 最易审计和回归。
  - C 兼顾探索速度与系统稳定性。
- 缺点和失败模式：
  - A 很难复现，供应商、模型和检索结果一变就可能漂。
  - B 吞吐慢，人工或 harness 审核成本更高。
  - C 设计复杂，需要更严格的 contract 和 stop rule。

### 漏洞安全专家

- 业界常见做法：安全研究与漏洞 triage 通常接受“模型帮助发现可疑点”，但不会把“模型说这个 sanitizer 有效”直接当成最终结论。
- 备选方案：
  - A. 让 LLM 辅助识别 source/sink，但不参与 sanitizer 判断。
  - B. 让 LLM 参与 sanitizer 判断，但只能输出 `unknown` 或 `candidate_sanitizer`，不能直接输出 safe。
  - C. 让 LLM 同时判断 source/sink/sanitizer，并直接影响 reachability/PoC 结论。
- 优点：
  - A 风险最低。
  - B 能覆盖更多真实项目中的 wrapper/validator 场景。
  - C 自动化程度最高。
- 缺点和失败模式：
  - A 会保留 sanitizer 建模的长尾盲区。
  - B 仍需要 threat-model-aware schema 和更强 benchmark。
  - C 最容易产生危险的 false negative 与过度自信结论。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果把 LLM 放到主执行层，谁来保证不同模型版本、不同检索结果、不同文档版本之间的等价性？
- 需要验证的假设：LLM 在 unfamiliar API 的 source/sink 候选召回上是否显著优于纯规则；在 sanitizer 判断上是否会系统性过度乐观。
- 当前最小可行决策：允许 LLM 作为语义增强层输出带证据的候选分类，但不允许直接替代规则和程序分析骨架。
- 验证 harness：
  - unfamiliar API 的 source/sink 正例。
  - 名字像 sanitizer、但实际不足以阻断风险的反例。
  - 文档缺失、版本不明或实现缺失时必须输出 unknown。

### 工程化专家

- 对其他方案的质询：如果实时引入 LLM/MCP，如何把结果稳定复现到 CI、fixture 和 benchmark 中？
- 需要验证的假设：结构化输出 schema 是否足以承载“主张 / 证据 / 适用版本 / 失败模式 / unknowns”。
- 当前最小可行决策：先设计方法论和输出 contract，再做离线或 mock 驱动的最小 harness，不立即把在线 LLM 接进主流程。
- 验证 harness：
  - 固定输入下的 schema/snapshot 测试。
  - 检索缺失、源码缺失、版本不匹配时的 degraded behavior。
  - benchmark 中显式记录 `candidate`、`unknown` 与拒绝升级的原因。

### 漏洞安全专家

- 对其他方案的质询：如果模型把某个 validator 误判为 sanitizer，系统是否还能阻止 reachability 从 unknown 被错误降成 false 或 safe？
- 需要验证的假设：在安全相关 negative judgment 上，LLM 是否显著弱于 positive hypothesis generation。
- 当前最小可行决策：LLM 对 sanitizer 的判断只能作为“待验证的安全假设”，默认不能单独输出最终 safe 结论。
- 验证 harness：
  - sanitizer false-positive 专项 case。
  - threat-class-specific case，例如同一编码函数在不同 sink/context 下是否仍有效。
  - 版本差异 case，验证不同版本库语义变化时模型是否会过度泛化。

## 最终决策

项目采用以下原则：

1. **LLM 不替代 source/sink/sanitizer 规则层，也不替代程序分析骨架。**
2. **LLM 可以作为证据约束的语义增强层，专门补 unfamiliar API、长尾库、wrapper 和跨生态知识覆盖。**
3. **LLM 的输出必须是结构化、可反驳、可回放的候选语义判断，而不是自由文本结论。**
4. **sanitizer 判断默认最保守：LLM 不能单独给出最终 safe 结论，只能输出 `candidate_sanitizer` 或 `unknown`。**
5. **当前 M1/M2 阶段先落方法论、contract 和 benchmark，不把在线 LLM/MCP 直接接入主执行路径。**

## 为什么现在这样做

- 它正面回应了“规则知识覆盖不全”的真实痛点。
- 它避免把系统过早改造成“运行时依赖模型拍板”的不可控结构。
- 它与我们现有方法论一致：候选结论可以增加，但最终结论必须受证据链和 harness 约束。
- 它给未来的 LLM 接入留出了清晰落点：不是替代，而是增强。

## 不采用的方案

- 纯规则长期维持不变：不采用，因为对长尾库和自定义 wrapper 的覆盖率会持续受限。
- 让 LLM 直接替代 source/sink/sanitizer 规则：不采用，因为不可重复、不可审计，且 sanitizer 误判风险过高。
- 在当前阶段立即接入在线 LLM/MCP 并影响主流程：不采用，因为当前还没有对应的 schema、fixture、benchmark 和 fail-safe 约束。

## 验证方式

- 方法论层：在 `docs/methodology.md` 明确语义增强层的职责、边界和 sanitizer 保守原则。
- harness 层：后续引入一组专门 benchmark/case，覆盖：
  - unfamiliar library source/sink 正例；
  - sanitizer false-positive 反例；
  - 版本变化导致的语义漂移；
  - 检索缺失或源码缺失时的 unknown；
  - wrapper/helper 语义判断场景。
- 工程层：如果未来实现该能力，输出必须进入结构化 report，并经过 schema、snapshot 和 benchmark 回归。

## 重新评估条件

- 我们决定在主流程中接入真实 LLM provider 或文档检索 MCP。
- 需要让 LLM 直接影响 `reachable=false`、safe 或 PoC/exp 结论。
- benchmark 显示 LLM 在 sanitizer negative judgment 上稳定失真。
- 已经积累出足够多的稳定语义判断，适合编译回本地知识库或规则 pack。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [ ] 是否需要更新测试或 fixture
