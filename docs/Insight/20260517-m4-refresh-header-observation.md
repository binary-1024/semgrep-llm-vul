# Insight: 为 M4.5 引入 refresh-header effect observation

## 元信息

- 日期：2026-05-17
- 状态：Accepted
- 关联任务：M4.5 主线；继续扩 M4 的 response-level observation coverage，而不是扩大 runner 权限
- 关联 ADR：`docs/decisions/0020-use-refresh-header-observation-for-m4.md`
- 决策类型：观测规则 / 安全边界

## 背景

当前 M4.4 已经具备：

- 结构化 `ExpVerificationReport`；
- loopback live HTTP replay runner；
- 仓库内置 managed fixture runtime；
- opt-in live benchmark cases；
- `meta refresh` body signature 这一类 response-level observation。

但 open redirect 的显式跳转效果除了 `Location` header 和 body `meta refresh` 外，还经常通过
`Refresh: 0; url=...` 这类 response header 表达。当前 runner 已经能拿到真实响应头，却还不能把这类
高语义密度的 header redirect 纳入 effect observation。

## 决策问题

M4 是否应该在保持当前本地、受控、差分 verification contract 不变的前提下，为 open redirect
增加一类基于 `Refresh` response header 的 effect observation？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：M4 已经具备 HTTP 观测能力，但 effect 规则仍然漏掉一类明确的跳转表达。
- 最小必要能力：识别 `Refresh` header 中的外跳目标，并把它纳入与 `Location` / `meta refresh` 同层的 effect 判断。
- 不可牺牲约束：不能把任意 header 文本误判成效果；必须要求它具备明确 redirect 语义。
- 最大风险：把更一般的 header 解析扩成模糊字符串匹配器。

### 工程化专家

- 根本问题：这是一个同构扩展，不应要求新的 runner、schema 或新的执行边界。
- 最小必要能力：在现有 response headers 归一化上增加 `Refresh` 解析 helper，并补 execution fixture / managed fixture / case / test。
- 不可牺牲约束：不提升 schema 版本，不改 `verified` / `not_verified` / `inconclusive` contract。
- 最大风险：把单个新 signal 做成宽泛的 header semantic framework，导致实现和文档膨胀。

### 漏洞安全专家

- 根本问题：`Refresh` response header 仍然属于明确的跳转语义，只是表达位置不同。
- 最小必要能力：只接受 `Refresh` 中的 `url=` 形式，且仍然要求目标为外部 URL。
- 不可牺牲约束：不执行浏览器，不做 JS/DOM 推理，不因页面包含外部字符串就判为效果。
- 最大风险：把没有 `url=` 的刷新提示、或内部跳转，误升级成 open redirect 观察结果。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：把高置信度的 HTTP/HTML redirect pattern 逐条纳入 observation family，而不是一步做全量内容语义。
- 备选方案：
  - A. 保持只支持 `Location` 与 `meta refresh`
  - B. 新增 `Refresh` response header
  - C. 直接上通用 response header/body diff
- 优点：B 与当前 contract 最同构，收益直接。
- 缺点和失败模式：B 仍然只覆盖很小一类 response-level signal。

### 工程化专家

- 业界常见做法：沿现有 fixture/case harness 做增量能力回归，而不是只在实现层“隐式支持”。
- 备选方案：
  - A. 只在离线 execution fixture 里支持
  - B. 同时在 execution fixture、managed fixture、benchmark/live case 里都支持
  - C. 只写代码，不补新的 case
- 优点：B 最稳定，长期维护成本最低。
- 缺点和失败模式：需要同步 baseline 计数和多处文档。

### 漏洞安全专家

- 业界常见做法：优先吸收“语义明确、无需浏览器执行”的跳转信号，例如 `Location`、`Refresh`、`meta refresh`。
- 备选方案：
  - A. 只要 body/header 里出现外部 URL 就判效果
  - B. 只接受带 `url=` 的 `Refresh` header
  - C. 立即扩到 JS redirect、DOM 片段和更一般的 body diff
- 优点：B 容易解释，误报面最小。
- 缺点和失败模式：覆盖率仍然受限。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 `Refresh` header 只是内部 URL 或没有 `url=`，凭什么把它算成 open redirect 效果？
- 需要验证的假设：`Refresh: ... url=<external>` 足以表达一条新的、高置信度 redirect observation。
- 当前最小可行决策：新增 `Refresh` header 观察，但仅支持带 `url=` 的外部跳转。
- 验证 harness：离线 execution fixture + managed fixture + opt-in live case + CLI/benchmark 回归。

### 工程化专家

- 对其他方案的质询：如果这一步不补 case，只在实现层悄悄支持，后续很容易退化。
- 需要验证的假设：现有 report schema 已能承载该能力，不需要再升 `schema_version`。
- 当前最小可行决策：不改 schema，只增 observation helper、fixture style 和回归层。
- 验证 harness：`./scripts/check`、`./scripts/benchmark`、`./scripts/benchmark-live`。

### 漏洞安全专家

- 对其他方案的质询：如果现在直接把更广的 error signature / body diff 一起做进来，会不会又把主线带偏？
- 需要验证的假设：`Refresh` header 是一个足够独立、不会扩大执行边界的 observation family。
- 当前最小可行决策：只扩 `Refresh` response header，不扩更一般 header semantic parsing。
- 验证 harness：affected 用外部 `Refresh`，fixed 用普通本地 HTML 或无外跳 header，最终只在前者观察到效果。

## 最终决策

M4.5 引入 **refresh-header effect observation**，第一版只支持 open redirect 下的
`Refresh: ... url=...` response header。

第一版边界：

- 继续保留 `verified` / `not_verified` / `inconclusive` 三态 verdict。
- 继续保留 `execution_state`、`effect_state`、最终 verdict 三层分离。
- 不变更 exp verification report schema。
- execution evidence JSON 与 live runner 都允许通过现有 response headers 承载该能力。
- 只支持带 `url=` 的 `Refresh` header，不支持任意 header 文本模糊匹配。
- 不支持通用 body diff，不支持 JS 执行，不支持浏览器渲染。

## 为什么现在这样做

- 它与现有 `Location` / `meta refresh` 是同一类 observation family，推进成本低但收益直接。
- 它继续服务当前 open redirect 主线，不需要 M2/M3 返工。
- 它扩大的是 observation coverage，不是 runner 权限或环境边界。

## 不采用的方案

- 保持只支持 `Location` 与 `meta refresh`：当前不采用，因为会留下明显可识别的 redirect signal 空缺。
- 一次性做通用 response diff / error signature 平台：当前不采用，因为范围过大。
- 直接支持 JS redirect 或浏览器执行：当前不采用，因为会显著扩大执行边界。

## 验证方式

- 新增离线 execution evidence fixture：`Refresh` header 风格的 `verified` 正例。
- 新增 M4 curated case。
- 新增 managed fixture family 和 opt-in live case。
- 新增单元测试、CLI 回归和 benchmark/live 回归。

## 重新评估条件

- 需要支持更广的 response-level observation family，例如 error signature 或 body diff。
- 需要支持更复杂的 header/body 语义组合判断。
- 需要引入浏览器或渲染行为才能确认效果。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
