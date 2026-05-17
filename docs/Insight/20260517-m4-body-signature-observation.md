# Insight: 为 M4.4 引入 body-signature effect observation

## 元信息

- 日期：2026-05-17
- 状态：Accepted
- 关联任务：M4.4 主线；扩 M4 的 effect coverage，而不是扩 runner 权限或回到 M2/M3 语法角落
- 关联 ADR：`docs/decisions/0019-use-body-signature-observation-for-m4.md`
- 决策类型：数据模型 / 安全边界

## 背景

当前 M4 已经具备：

- 结构化 `ExpVerificationReport`；
- loopback live HTTP replay runner；
- 仓库内置 managed fixture runtime；
- opt-in live benchmark cases；
- dedicated full-chain CLI E2E smoke。

但当前 `effect observation` 仍然只覆盖一类非常窄的规则：`30x + Location` 风格的 Flask
open redirect。只要目标效果不是由响应头表达，而是落在响应 body 里，当前 runner 即使已经拿到了真实
响应，也只能停在 `effect_unknown` 或保守地判成 `effect_not_observed`。

## 决策问题

M4 是否应该在保持当前本地、受控、差分 verification contract 不变的前提下，为 open redirect
增加一类基于 response body signature 的 effect observation？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：执行层已经能拿到真实 HTTP 响应，但 observation 规则过窄，导致能力上限低于采样能力。
- 最小必要能力：让 response body 中可结构化识别的 redirect 语义进入 effect 观察，而不是只看 header。
- 不可牺牲约束：不能把“看起来像字符串包含 URL”直接升级成效果观察；必须有明确语义模式。
- 最大风险：把 body 观察做成泛化模糊匹配，导致误报明显上升。

### 工程化专家

- 根本问题：当前 runner、fixture、case、report 都已具备扩 observation 的承载能力，缺的是一个窄而稳定的新规则族。
- 最小必要能力：扩 `ExecutionEvidenceRecord` / `ExpObservation` 的 body 载荷承载能力，并给出一条新的最小规则。
- 不可牺牲约束：不改 `verified` / `not_verified` / `inconclusive` 语义；不改 loopback / managed fixture 安全边界。
- 最大风险：把一个小扩展做成通用 body diff 平台，导致 contract 和测试爆炸。

### 漏洞安全专家

- 根本问题：有些 open redirect 或近似跳转效果不会出现在 `Location` header，而是出现在 HTML body 中。
- 最小必要能力：支持受控、可解释、可回归的 body signature，比如 `meta refresh` 这类明确跳转语义。
- 不可牺牲约束：不执行浏览器、不跑 JS、不连接公网、不把“任意 body 内容”解释成效果。
- 最大风险：把带外部 URL 的普通 HTML 文本误判成漏洞效果。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：先定义少量高置信度 observation pattern，再逐步扩类型，而不是一开始做宽泛语义匹配。
- 备选方案：
  - A. 保持只支持 header redirect；
  - B. 直接做通用 body diff / signature 平台；
  - C. 先引入 `meta refresh` 这类明确 body redirect signature。
- 优点：C 能最小代价扩大 coverage，同时保持高解释性。
- 缺点和失败模式：C 仍只覆盖很小一类 body redirect，不是通用 body analysis。

### 工程化专家

- 业界常见做法：在已有 request replay / response normalization 上增量加入新 observation family，并用新的 fixture/case 锁定。
- 备选方案：
  - A. 只在 live runner 中支持 body；
  - B. 同时让 execution evidence JSON 和 live runner 都支持 body；
  - C. 先不改 schema，只在内部临时字符串匹配。
- 优点：B 最一致，fixture、CLI、benchmark 和 live harness 都能复用。
- 缺点和失败模式：B 需要调整 execution evidence schema 和 report contract。

### 漏洞安全专家

- 业界常见做法：优先识别有清晰安全语义的 HTML/HTTP 信号，如 `meta refresh`、固定错误签名、显式异常 banner。
- 备选方案：
  - A. 任意 body 包含外部 URL 即视为效果；
  - B. 只接受显式 `meta refresh` 跳转；
  - C. 立即支持 JS redirect、DOM 片段、body diff 等更广模式。
- 优点：B 最容易解释，也最容易避免误判。
- 缺点和失败模式：B 覆盖率低，但与当前阶段匹配。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果只做字符串包含外部 URL，怎么区分“页面上显示了一段 URL 文本”和“页面真的会跳转”？
- 需要验证的假设：`meta refresh` 作为 HTML body pattern，足以表达一条新的、可回归的 observation family。
- 当前最小可行决策：只为 open redirect 增加 `meta refresh` body signature 观察。
- 验证 harness：离线 execution evidence fixture + live managed fixture + benchmark/live case。

### 工程化专家

- 对其他方案的质询：如果 body 观察只在 live runner 可用，那 execution fixture 和 case suite 就无法表达这个能力提升。
- 需要验证的假设：execution evidence JSON 增加可选 `response.body` 字段后，旧 fixture 不会受影响。
- 当前最小可行决策：同时扩 execution evidence loader、live runner、reporting 和 benchmark case。
- 验证 harness：单元测试、CLI 回归、benchmark case、live case、`./scripts/check`。

### 漏洞安全专家

- 对其他方案的质询：如果直接支持 JS redirect 或更广 body diff，会不会把 M4 从“可审查闭环”推成“模糊内容匹配器”？
- 需要验证的假设：`meta refresh` 的语义足够清晰，可在不运行浏览器的前提下判断为 redirect 效果。
- 当前最小可行决策：只支持 `meta refresh`，不支持任意 JS 或通用 body diff。
- 验证 harness：affected 响应为外部 `meta refresh`，fixed 响应为站内或普通 HTML，最终只在前者观察到效果。

## 最终决策

M4.4 引入 **body-signature effect observation**，第一版只支持 open redirect 下的
`meta refresh` 模式。

第一版边界：

- 继续保留 `verified` / `not_verified` / `inconclusive` 三态 verdict。
- 继续保留 `execution_state`、`effect_state`、最终 verdict 三层分离。
- `ExecutionEvidenceRecord` 和 `ExpObservation` 允许承载响应 body 片段。
- execution evidence JSON 与 live runner 都允许提供 response body。
- 第一版只增加 `meta refresh` 这一类 body redirect signature。
- 不支持通用 body diff，不支持 JS 执行，不支持浏览器渲染，不支持任意字符串模糊匹配。

## 为什么现在这样做

- 它正好命中当前主线 blocker：runner 已经能拿到响应，但 observation coverage 还太窄。
- 它不要求 M2/M3 返工，因为仍然服务当前 open redirect 主线。
- 它把能力提升落在 evidence-bearing contract 上，而不是落在隐式实现细节里。

## 不采用的方案

- 继续只支持 header-based redirect：当前不采用，因为会让 M4 的 coverage 长期受限。
- 直接做通用 body diff / error signature 平台：当前不采用，因为范围过大。
- 直接支持 JS redirect、DOM 解析或浏览器执行：当前不采用，因为会显著扩大执行边界。

## 验证方式

- 新增离线 execution evidence fixture：`meta refresh` 风格的 `verified` 正例。
- 新增 M4 curated case。
- 新增 managed fixture family 和 opt-in live case。
- 新增单元测试、CLI 回归和 live runner 回归。

## 重新评估条件

- 需要支持除 open redirect 外的 body-based observation family。
- 需要支持 JS redirect、错误签名或更通用的 body diff。
- 需要引入真实浏览器或渲染行为才能判断效果。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
