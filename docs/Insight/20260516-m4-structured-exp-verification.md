# Insight: 为 M4 引入最小结构化 exp verification 闭环

## 元信息

- 日期：2026-05-16
- 状态：Accepted
- 关联任务：M4 主线启动；将 M3 `PocPlan(execution_state=not_run)` 推进为最小 exp verification 能力
- 关联 ADR：`docs/decisions/0015-use-structured-exp-verification-first.md`
- 决策类型：分析策略

## 背景

当前仓库已经完成 M3 第一版最小闭环，具备：

- `reachable=true|false|null` 三态；
- 结构化 `PocPlan` / `PocGenerationReport`；
- 默认 `execution_state=not_run` 的安全验证型 PoC planning；
- 本地、离线、可回归的 fixture / CLI / benchmark / report contract。

路线图和方法论文档都已经明确，下一步进入 M4：exp 验证与生成。

但这里有一个关键选择：M4 第一版到底是应该直接进入“自由命令执行 + 通用 exploit 生成”，还是先建立一个**带生成产物的、差分 verification harness**，只支持很窄、可审计的执行与观察语义？

## 决策问题

M4 第一版是否应先实现“结构化 exp verification/report + 窄 runner”，而不是直接进入通用 exploit 执行器？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：M3 证明的是“知道如何触发”，不是“已经在 affected/fixed 对照中观察到差异”。
- 最小必要能力：把 `PocPlan(not_run)` 推进成受影响版本与修复版本可比较的验证结论。
- 不可牺牲约束：不能把单版本运行结果或生成出来的脚本直接升级成 `verified`。
- 最大风险：把执行状态、观察结果和最终 verdict 混在一起，导致阶段语义塌缩。

### 工程化专家

- 根本问题：当前仓库的优势是本地、确定性、可回归；通用执行器会立刻引入环境耦合、隔离治理和不可重复噪音。
- 最小必要能力：定义稳定的 M4 report schema、execution evidence fixture、CLI、benchmark/case 和 contract test。
- 不可牺牲约束：M4 第一版必须仍能在离线 harness 中稳定回归。
- 最大风险：为了跑通第一条 exp，过早引入通用 shell/code 执行，把主线拖进平台工程。

### 漏洞安全专家

- 根本问题：M4 是第一个会显式碰“执行结果”的阶段，必须同时推进证据和安全边界。
- 最小必要能力：把“执行是否完成”“效果是否观察到”“对照后是否 verified”分成三个层次。
- 不可牺牲约束：不得对真实公网目标发请求，不得处理 secrets，不得生成破坏性 payload。
- 最大风险：把“能发请求”误当成“exp 已完成”，或者把“一边跑通”误当成 `verified`。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：PoC 与 exp 分层；exp 更强调 affected/fixed 对照、观察规则和最终结论，而不是单次触发。
- 备选方案：
  - A. 直接做通用 exploit 生成与执行；
  - B. 先做结构化、差分式 exp verification/report；
  - C. 继续停留在 M3，不进入 M4。
- 优点：B 能最大化复用当前阶段化证据模型，且最容易保持 `verified / not_verified / inconclusive` 的保守语义。
- 缺点和失败模式：B 仍然依赖 M3 plan 足够具体；如果 plan 太抽象，M4 会大量落到 `inconclusive`。

### 工程化专家

- 业界常见做法：先定义执行工件、观察工件和 verdict contract，再逐步扩 runner 类型。
- 备选方案：
  - A. 通用 shell/code executor；
  - B. report-first verification harness + typed runner；
  - C. 只写自由文本验证说明。
- 优点：B 最符合当前仓库的 harness 结构，可以直接落 schema test、CLI test、fixture、benchmark case。
- 缺点和失败模式：如果 typed runner 设计不够窄，很容易重新滑回“半通用执行平台”。

### 漏洞安全专家

- 业界常见做法：先从安全验证型 replay / harness 开始，只支持窄类型请求与观察，再根据隔离能力扩展。
- 备选方案：
  - A. 生成任意 exploit 脚本并执行；
  - B. 生成可重放 request artifact，并结合本地 execution evidence 做对照验证；
  - C. 把执行全留给人工，不做结构化验证。
- 优点：B 能把“exp 生成”和“exp 验证”放进同一个可审计 contract，又不直接越过安全边界。
- 缺点和失败模式：B 不是完整通用 exp 平台，当前覆盖面必须保持很窄。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 affected / fixed 不作为一等输入，M4 和 M3 的本质区别到底是什么？
- 需要验证的假设：当前 `PocPlan` 已经足够恢复 method/path/参数形态，能驱动最小 replay artifact。
- 当前最小可行决策：M4 第一版采用 `PocPlan(not_run) -> ExpVerificationReport`，并显式区分执行态、效果态和最终 verdict。
- 验证 harness：必须覆盖 `verified`、`not_verified` 与 `inconclusive` 三类结果。

### 工程化专家

- 对其他方案的质询：如果没有先定义 execution evidence schema，CLI、benchmark 和回归如何稳定消费？
- 需要验证的假设：可以用本地 fixture 承载执行观察，而不是先搭一个真实在线执行平台。
- 当前最小可行决策：先做 report-first 的差分 verification harness，并且 runner 当前只支持窄类型的 `http_request_replay`。
- 验证 harness：模型/序列化测试、CLI 测试、benchmark/case、`./scripts/check`、`./scripts/benchmark`。

### 漏洞安全专家

- 对其他方案的质询：如果一开始就放开通用命令执行，谁来兜住 secrets、网络、副作用和误用风险？
- 需要验证的假设：对于当前 Flask open redirect 主线，只用 HTTP request replay + redirect observation 就足够表达最小 exp 语义。
- 当前最小可行决策：M4 第一版只支持“结构化 request artifact + 本地 execution evidence + 保守 verdict”的 exp verification。
- 验证 harness：`verified` 必须要求 affected 观察到效果且 fixed 未观察到效果；其他模糊情况一律降级为 `not_verified` 或 `inconclusive`。

## 最终决策

M4 第一版采用**结构化、证据承载的 exp verification/report**，并只引入一个窄类型、可审计的 runner 语义，不直接进入通用 exploit 执行器。

第一版边界：

- 只消费 `PocPlan(execution_state=not_run)` 进入 M4。
- M4 report 必须显式区分：
  - `execution_state`：有没有完成执行观察；
  - `effect_state`：预期效果是否被观察到；
  - `verification_verdict`：affected / fixed 对照后的最终结论。
- 当前 verdict 只允许 `verified`、`not_verified`、`inconclusive`。
- 当前 runner 只支持窄类型 `http_request_replay`。
- 当前观察规则只支持 Flask open redirect 这一类可由 `Location` header / redirect target 差异表达的效果。
- 默认使用本地 execution evidence fixture，不依赖真实公网目标，不处理 secrets，不执行破坏性 payload。

## 为什么现在这样做

- M3 已经足以回答“该发什么请求、期望观察什么效果”，现在应该把这份 plan 推进成可对照、可审计的验证结论。
- report-first 的 M4 能最大化复用现有 harness：结构化输出、fixture、CLI、benchmark/case、schema test。
- 把执行态、效果态和最终 verdict 分开，能显著降低“脚本生成了”“一边跑通了”“看起来像成功”这类假阳性升级。

## 不采用的方案

- 直接做通用 exploit 生成与执行：不采用，因为当前没有成熟的隔离、secret、网络和副作用治理。
- 只输出自由文本验证说明：不采用，因为不可稳定回归，也不利于后续 benchmark/agent 消费。
- 继续停留在 M3，不进入 M4：不采用，因为主线已经具备推进 M4 最小闭环的前提。

## 验证方式

- 引入最小 `ExpVerificationReport` 数据模型与 JSON contract。
- 新增 CLI 入口，消费 M3 plan 所需等价输入和本地 execution evidence，输出结构化 exp verification JSON。
- 至少新增一个 `verified`、一个 `not_verified`、一个 `inconclusive` 的 M4 curated case。
- 运行 `./scripts/check` 与 `./scripts/benchmark`。

## 重新评估条件

- 需要支持真实本地服务启动、容器运行、跨请求会话或鉴权流程。
- 需要支持比当前 Flask open redirect 更广的 runner / effect 语义。
- 当前 `PocPlan` 无法稳定恢复 request artifact，导致大多数 M4 case 落入 `inconclusive`。
- 为跑通第一个场景就不得不引入通用 shell/code 执行。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [ ] 是否需要更新测试或 fixture
