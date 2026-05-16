# Insight: 为 M3 引入最小结构化 PoC planning 闭环

## 元信息

- 日期：2026-05-16
- 状态：Accepted
- 关联任务：M3 主线启动；将 M2 `reachable=true` 输出推进为最小 PoC planning 能力
- 关联 ADR：`docs/decisions/0014-use-structured-poc-planning-first.md`
- 决策类型：分析策略

## 背景

当前仓库已经完成 M2 第一版最小闭环，具备：

- candidate taint path；
- `reachable=true|false|null` 三态；
- 本地 Flask 入口证据；
- 有界局部 helper call chain；
- source controllability AST 证据；
- 本地 guard/blocking evidence。

路线图和方法论文档都已经明确，下一步不再继续无止境补 M2 语法角落，而是要把已经确认 `reachable=true` 的路径推进到 M3：PoC 生成。

但这里有一个关键选择：M3 第一版到底是应该直接生成可执行 payload/脚本，还是先生成结构化、未执行的 PoC plan/report？

## 决策问题

M3 第一版是否应先实现“结构化 PoC planning/report”，而不是直接进入可执行 PoC 或 exploit 脚本生成？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：M2 证明的是“静态可触达”，不是“运行时已触发”。
- 最小必要能力：把 `reachable=true` 的路径转换成最小触发输入、请求形态和预期效果。
- 不可牺牲约束：不能把静态证据自动升级成“已验证利用”。
- 最大风险：把 `reachable=true` 误当成“必然可执行”，导致阶段语义漂移。

### 工程化专家

- 根本问题：当前仓库擅长本地、确定性、可回归；真实执行会立刻引入环境耦合与副作用治理。
- 最小必要能力：定义稳定的 PoC report schema、CLI、fixture 和 benchmark/case 回归。
- 不可牺牲约束：M3 第一版必须可在本地离线 harness 中稳定验证。
- 最大风险：过早进入执行层，导致测试噪音大、失败归因不清、主线失焦。

### 漏洞安全专家

- 根本问题：PoC 阶段既要推进结论，也要收紧安全边界。
- 最小必要能力：优先生成安全验证型 PoC 规划，明确前提、预期效果和未验证项。
- 不可牺牲约束：默认不产出破坏性 payload，不把 `unknown` 推进成可利用结论。
- 最大风险：脚本一旦可执行，就需要额外处理副作用、隔离、鉴权与误用风险。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：静态分析或漏洞 triage 系统一般先输出 trigger hypothesis、attack surface 和 reproduction notes，再进入可执行验证。
- 备选方案：
  - A. 直接生成可执行 payload/脚本；
  - B. 先生成结构化 PoC plan/report；
  - C. 保持只到 M2，不做 M3。
- 优点：B 能最大化复用当前 `reachable=true|false|null` 三态，不破坏阶段边界。
- 缺点和失败模式：B 仍然依赖 M2 证据质量；如果 plan 过于抽象，会变成“看起来像输出，实际上不能执行”的空壳。

### 工程化专家

- 业界常见做法：先把“计划层 contract”做稳定，再引入运行环境、沙箱执行和观察契约。
- 备选方案：
  - A. 一步到位做脚本生成和执行；
  - B. 先做 report-first 的 PoC planning；
  - C. 用自由文本描述 PoC，不建结构化 contract。
- 优点：B 最符合现有 harness 结构，可以做 schema test、CLI test、benchmark case。
- 缺点和失败模式：如果 request 参数或环境前提恢复不足，report 可能不够可操作。

### 漏洞安全专家

- 业界常见做法：把 PoC 和 exp 分层，PoC 偏最小触发验证，exp 偏自动化利用与对照验证。
- 备选方案：
  - A. 让 M3 直接产出 exploit 风格脚本；
  - B. 让 M3 只产出安全验证型 plan/report；
  - C. 让 LLM 自由生成攻击请求，再人工筛选。
- 优点：B 更容易控制误用风险，也更适合作为后续 M4 的输入。
- 缺点和失败模式：B 不能替代真实执行验证，必须清楚标记 `not_run` 和 unknowns。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果直接生成脚本，谁来保证 `reachable=true` 与“运行时可复现”之间的差距被表达出来？
- 需要验证的假设：当前 M2 的入口、source control 和 blocking evidence 足以支撑最小 request 形态恢复。
- 当前最小可行决策：只对 `reachable=true` 路径生成结构化 PoC plan/report。
- 验证 harness：正例必须生成 plan；`reachable=false` 与 `reachable=null` 必须停在 planning 之外。

### 工程化专家

- 对其他方案的质询：如果没有先定义 report contract，后续 benchmark 与 CLI 如何稳定回归？
- 需要验证的假设：可以在不引入真实执行环境的前提下，恢复 method/path/参数键名等最小触发信息。
- 当前最小可行决策：先做 report-first 的 PoC planning CLI，不进入脚本执行。
- 验证 harness：模型/序列化测试、CLI 测试、benchmark/case、`./scripts/check`、`./scripts/benchmark`。

### 漏洞安全专家

- 对其他方案的质询：如果让 M3 直接产出可执行 payload，现阶段谁来兜住副作用和误用边界？
- 需要验证的假设：当前阶段产出的 plan 足够具体，能为后续 M4 提供真实价值，而不是空洞建议。
- 当前最小可行决策：M3 第一版只支持“安全验证型、默认 `not_run`、带证据链”的 PoC planning。
- 验证 harness：计划中必须包含前提、预期效果、unknowns 和 limitations；不得冒充 `verified`。

## 最终决策

M3 第一版采用**结构化、证据承载的 PoC planning/report**，不直接进入可执行 payload 或 exploit 脚本生成。

第一版边界：

- 只消费 `reachable=true` 的路径进入 M3。
- `reachable=false` 与 `reachable=null` 继续保留为证据，不进入 PoC 执行语义。
- 默认执行状态必须是 `not_run`。
- 输出必须结构化，至少包含：入口、最小触发输入、请求形态、预期效果、前提条件、evidence、unknowns、limitations。
- 当前优先支持本地 Flask open redirect 这一类已被 M2 source-root fixture 稳定覆盖的场景。

## 为什么现在这样做

- M2 已经足以回答“哪条路径值得尝试触发”，现在应该把这份答案变成可消费的 PoC plan，而不是继续扩同类入口小变体。
- report-first 的 M3 能最大化复用现有 harness 思路：结构化输出、fixture、CLI、benchmark/case、schema test。
- 这一步能把“我们知道该怎么触发”与“我们已经验证成功”明确分层，为后续 M4 执行验证保留清晰边界。

## 不采用的方案

- 直接生成可执行 payload/脚本：不采用，因为现阶段还没有成熟的运行环境建模、隔离执行和 success/failure observation contract。
- 只输出自由文本 PoC 描述：不采用，因为不可稳定回归，也不利于后续 agent 和 benchmark 消费。
- 继续停留在 M2，不进入 M3：不采用，因为主线已经具备推进 M3 的最小前提。

## 验证方式

- 引入最小 `PoCPlan` / `PoCGenerationReport` 数据模型与 JSON contract。
- 新增 CLI 入口，消费 M2 report 或等价输入，输出结构化 PoC planning JSON。
- 新增至少一个 `reachable=true` 的 M3 正例 case。
- 新增 `reachable=false` 与 `reachable=null` 不得生成 executable-oriented plan 的负例。
- 运行 `./scripts/check` 与 `./scripts/benchmark`。

## 重新评估条件

- 需要支持真实执行、容器运行、对照版本验证或自动化脚本生成。
- 需要覆盖比当前 Flask open redirect 更广的运行方式。
- 当前 plan 无法稳定恢复最小请求形态，导致 M4 无法消费。
- 需要引入明确的 execution state 机、隔离环境和副作用治理。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [ ] 是否需要更新测试或 fixture
