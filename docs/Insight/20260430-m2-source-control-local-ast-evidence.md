# Insight: M2 source_control 的本地 AST 证据扩展

## 元信息

- 日期：2026-04-30
- 状态：Accepted
- 关联任务：M2 污点路径生成与可触达确认
- 关联 ADR：`docs/decisions/0010-use-local-reachability-evidence-model.md`
- 决策类型：分析策略 | 证据链

## 背景

当前 `confirm-reachability --source-root` 已经能从本地 Flask fixture 源码中提取 entrypoint
与 call chain 证据，并把 `reachable` 稳定区分为 `true|false|null`。

但 `source_control` 仍然偏弱：当前实现主要依赖 `taint_path.source.name` 是否包含
`request.` 来判断 source 是否来自 Flask request 对象。这意味着一旦 Semgrep trace 中的
source 名称只是局部变量名，例如 `next_url`，即使其 source location 对应的赋值右侧是
`request.args.get("next")`，系统也无法从本地证据确认其外部可控性。

在继续扩大 import/alias 边界之前，更符合主线的问题是：如何让 `source_control`
从“字符串猜测”升级为“基于 source location 的本地可审查证据”。

## 决策问题

M2 当前是否应该优先把 `source_control` 扩展为基于 source location 的本地 AST 证据，
而不是继续扩更多 import/alias 变体？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：reachability 不只需要 entrypoint 和 call chain，还需要回答 source 是否真的可由外部输入控制。
- 最小必要能力：当 `source.name` 不够用时，能回到本地源码定位该 source 所在语句，并判断它是否来自 `request.*`。
- 不可牺牲约束：不能因为 source 位于 route function 内就默认 controlled；不能把普通局部变量名自动升级为外部可控。
- 最大风险：如果继续只看名称，后续 M2 会在更真实的 trace 上频繁把“可控但名字不显式”的 source 退回 unknown。

### 工程化专家

- 根本问题：当前 `source_control` 的判定逻辑过于脆弱，随着 fixture 真实性提高会不断抖动。
- 最小必要能力：局部、确定性、无外部依赖的源码检查；输出结构保持不变，只增强证据质量。
- 不可牺牲约束：不引入完整数据流引擎；不把 assignment/points-to/type inference 混进来。
- 最大风险：如果一次性做成泛化 taint 跟踪，会和现有 M2 最小模型边界冲突，测试成本飙升。

### 漏洞安全专家

- 根本问题：`source_control` 是 reachable 与后续 PoC 之间的重要门槛；过弱会导致可信度不足，过强会放大误报。
- 最小必要能力：能明确说明“为什么这个 source 看起来来自攻击者可控输入”。
- 不可牺牲约束：`controlled=true` 仍然只是静态可控性，不等于漏洞可触发或已验证。
- 最大风险：把任意局部变量都当成 request-derived，等于把 source controllability 退化成名字游戏。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：静态分析通常把 source 建模和入口建模分开；source 既可以由 API 名称判定，也可以由 AST/IR 上的赋值来源判定。
- 备选方案：
  - A. 继续只看 `source.name` 中是否出现 `request.`。
  - B. 基于 source location 的本地 AST 语句检查，只识别有限的 Flask request access 模式。
  - C. 直接做更一般的局部数据流或 points-to 传播。
- 优点：B 能明显提升真实 trace 兼容性，同时仍保持本地、确定性、低复杂度。
- 缺点和失败模式：B 仍然只覆盖有限模式，遇到 assignment alias、helper 封装或更复杂表达式仍需保持 unknown。

### 工程化专家

- 业界常见做法：先用最小 pattern matcher 提升证据质量，再由更重的分析器补复杂情况。
- 备选方案：
  - A. 继续补 import/alias 边界，把 call chain 做得更细。
  - B. 在现有 report schema 内增强 `source_control` 证据来源。
  - C. 重写 M2 让 source_control 与 call_chain 共用统一局部追踪器。
- 优点：B 改动集中在 `reachability.py`，不会震动报告 schema，也容易加 fixture 回归。
- 缺点和失败模式：如果没有明确非目标，B 很容易滑向“顺手支持 assignment alias / object attribute / helper wrapper”。

### 漏洞安全专家

- 业界常见做法：把 source controllability 当作独立结论，并允许“路径可达但 source 可控性不明”的 inconclusive 状态。
- 备选方案：
  - A. 只要 route 可到 sink 就认为 source controlled。
  - B. source_control 只在存在明确 request-derived 证据时输出 true，否则保持 false 或 unknown。
  - C. 暂不碰 source_control，继续扩 route/call chain。
- 优点：B 更贴近证据优先的方法论，能直接服务后续 PoC 输入构造。
- 缺点和失败模式：如果 false 与 unknown 边界不清，会把“证据不足”误说成“不可控”。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：继续扩 import/alias 只会让 call chain 更完整，但 source controllability 仍是短板。
- 需要验证的假设：只基于 source location 所在语句检查 request-derived 模式，就足以覆盖第一批更真实的 source case。
- 当前最小可行决策：支持从 source location 所在赋值语句识别 Flask request access，例如 `request.args[...]`、`request.args.get(...)`、`request.form[...]`、`request.values.get(...)`。
- 验证 harness：新增一个 `source.name` 只是局部变量、但 source location 对应 request-derived 赋值的 positive case。

### 工程化专家

- 对其他方案的质询：如果把 assignment alias、helper wrapper 一并支持，当前 M2 的简单边界会再次模糊。
- 需要验证的假设：只检查 source location 所在语句，而不做跨语句传播，就能保持实现小而稳。
- 当前最小可行决策：第一版只做 source location 对应语句的 AST 匹配；不追踪二次赋值，不做局部 worklist。
- 验证 harness：新增最小 source-root fixture、Semgrep trace fixture、CLI/benchmark 回归；保持 `./scripts/check` 和 `./scripts/benchmark` 通过。

### 漏洞安全专家

- 对其他方案的质询：如果 `controlled=false` 被用来表达“没找到 request 证据”，会把 unknown 误写成否定结论。
- 需要验证的假设：在现有模型里，只要本地 AST 看到明确 request-derived 赋值就输出 controlled=true；否则继续保守。
- 当前最小可行决策：只增强 `controlled=true` 的证据，不扩大 `controlled=false` 的使用范围。
- 验证 harness：新增正例，并确保已有 unknown / negative case 不回退。

## 最终决策

优先推进 M2 的 `source_control` 主线：把当前仅靠 `source.name` 的最小判断，扩展为
**基于 source location 的本地 AST 证据**。

第一版边界：

- 当 `source.name` 已明确包含 `request.` 时，保持现有行为。
- 当 `source.name` 不足以判断，但 `source.location` 指向的本地源码语句能静态识别为
  Flask request-derived 赋值时，输出 `source_control.controlled=true`。
- 识别模式仅限少量本地、可枚举的 Flask request access。
- 不做跨语句传播，不做 assignment alias，不做 helper wrapper，不做对象属性或 points-to。

## 为什么现在这样做

- 这一步直接增强 reachability 的核心证据质量，比继续补 import/alias 边界更贴近主线。
- 它不改变 report schema，也不要求引入新的外部分析器。
- 它能把“真实 trace 里 source 只剩局部变量名”的常见情况纳入可验证范围。

## 不采用的方案

- 继续只看 `source.name`：不采用。对更真实的 trace 太脆弱。
- 直接做更一般的局部数据流追踪：不采用。当前阶段复杂度过高，容易和 M2 最小模型边界冲突。
- 把任何 route 内局部变量都视为外部可控：不采用。证据质量过低，误报风险高。

## 验证方式

- 新增一个最小 positive case：
  - `source.name` 只是局部变量；
  - `source.location` 指向 `request.*` 赋值语句；
  - 期望 `reachable=true` 且 `source_control.controlled=true`。
- 保持已有 unknown / blocked / alias boundary case 不回退。
- `./scripts/check`、`./scripts/benchmark`、Markdown 相对链接检查通过。

## 重新评估条件

- 需要支持跨语句赋值、helper wrapper、assignment alias 或对象属性 owner 时。
- 现有 AST 语句匹配对真实 trace 覆盖不足，导致 `source_control` 仍频繁退回 unknown。
- 需要把 source_control 与更一般的局部数据流统一时。

## 后续动作

- [ ] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
