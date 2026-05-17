# Insight: 当前窄范围下将 M4 收口为完成状态

## 元信息

- 日期：2026-05-17
- 状态：Accepted
- 关联任务：M4 goal 收口；判断当前路线图下 M4 是否已经达到完成线
- 关联 ADR：`docs/decisions/0021-close-bounded-m4-as-complete.md`
- 决策类型：工程流程 / 里程碑边界

## 背景

当前仓库已经具备：

- 结构化 `ExpVerificationReport`；
- `verified` / `not_verified` / `inconclusive` 三态 verdict；
- loopback live HTTP replay runner；
- 仓库内置 managed fixture runtime；
- opt-in live benchmark cases；
- full-chain CLI E2E smoke tests；
- open redirect 场景下的 `Location` header、`Refresh` response header 和 body `meta refresh`
  三类最小 response-level observation。

与此同时，路线图仍把默认主线停留在 `M4`，容易让后续所有“更多 observation family”“更多漏洞族”
“更强运行环境”都被误解为“M4 还没完成”，从而让 goal 模式无限延长。

## 决策问题

在保持当前证据优先、窄边界和本地隔离约束不变的前提下，当前路线图下的 M4 是否已经可以收口为完成状态？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：里程碑完成的判断，应看该阶段是否已经形成可验证闭环，而不是看能力覆盖是否已经足够广。
- 最小必要能力：M4 需要具备结构化 exp verification、受影响/修复版本对照、明确 verdict 语义，以及可复现证据。
- 不可牺牲约束：不能把“还有很多未来可扩展点”误当成“当前闭环还没成立”。
- 最大风险：把 open redirect 这一条主线的最小验证闭环做成永远不会结束的 observation 清单。

### 工程化专家

- 根本问题：goal 模式需要一个清晰的 stop rule，否则会把“主线完成”拖成“无限加点”。
- 最小必要能力：实现、fixture、benchmark、live suite、E2E、文档语义都要对齐，说明当前版本已经可交付。
- 不可牺牲约束：收口不能只靠聊天判断，必须写回 roadmap 和决策文档。
- 最大风险：没有收口边界，后续每个增量都继续挂在 M4 名下，导致路线图失真。

### 漏洞安全专家

- 根本问题：M4 的目标是“受控地验证判断是否正确”，不是“做成通用 exploit 平台”。
- 最小必要能力：本地隔离、窄 runner、差分验证、显式未知和可复现实验链路。
- 不可牺牲约束：不能为了宣称完成而放松公网、鉴权、浏览器执行或任意 payload 边界。
- 最大风险：把更强执行能力当成完成标准，反而扩大安全暴露面。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：先把一个明确场景做成“可复现、可回归、可解释”的最小闭环，再扩族而不是持续扩大单一里程碑定义。
- 备选方案：
  - A. 继续把所有 response-level 扩展都算作 M4 未完成
  - B. 把当前 open redirect 主线的最小验证闭环视为 M4 已完成
  - C. 只有支持真实项目自动启动、容器和更多漏洞族后才算完成
- 优点：B 能真实反映当前系统已具备的可验证闭环。
- 缺点和失败模式：B 需要同步调整路线图话术，避免看起来像“提前宣布胜利”。

### 工程化专家

- 业界常见做法：里程碑关闭依赖 acceptance criteria，而不是功能想象空间。
- 备选方案：
  - A. 保持 roadmap 继续写“当前主线仍停留在 M4”
  - B. 正式把 M4 标为当前窄范围版本完成，并把后续工作改写为横向扩展
  - C. 新开 M5
- 优点：B 改动最小，且不需要凭空定义一个还没有产品边界的 M5。
- 缺点和失败模式：如果 roadmap 写得不清楚，后续读者可能不明白“完成的是哪一版 M4”。

### 漏洞安全专家

- 业界常见做法：安全验证系统先固定一个受控能力包，再逐步扩执行面和场景族。
- 备选方案：
  - A. 继续扩更多 observation signal 后再关 M4
  - B. 以当前本地隔离 + 三类 observation + live harness 作为 M4 完成线
  - C. 只有支持更强 exploit / browser / auth 流程才算完成
- 优点：B 更符合“先把安全边界站稳”的工程节奏。
- 缺点和失败模式：未来扩展必须清楚标注为“后 M4 扩展”，不能又被混回未完成项。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 affected/fixed 差分、live runner、managed fixture、E2E 和 observation family 都已经闭环，为什么还不能算完成？
- 需要验证的假设：当前 M4 已经满足路线图里“生成并执行 exp 验证、输出结构化验证报告、对照 affected/fixed”的最小定义。
- 当前最小可行决策：把当前 open redirect 主线下的 M4 收口为完成状态。
- 验证 harness：`./scripts/check`、`./scripts/benchmark`、`./scripts/benchmark-live`、`./scripts/e2e-smoke`。

### 工程化专家

- 对其他方案的质询：如果继续把所有后续扩展挂在 M4 上，goal 模式的完成条件要怎样定义才不会无限延长？
- 需要验证的假设：路线图和 benchmark 文档可以清楚地区分“当前窄范围完成”与“后续横向扩展方向”。
- 当前最小可行决策：新增一个里程碑边界 ADR，并同步更新 roadmap、architecture、benchmark baseline。
- 验证 harness：文档对齐 + 全量回归通过。

### 漏洞安全专家

- 对其他方案的质询：如果把浏览器执行、真实项目环境编排、公网目标等都当成当前完成标准，会不会直接推翻现在的安全边界？
- 需要验证的假设：在不放松本地隔离和窄 runner 约束的前提下，当前 M4 已经是一个可交付的最小安全验证系统。
- 当前最小可行决策：关闭当前窄范围 M4，并把更强执行面改写为后续扩展，不再视为 M4 blocker。
- 验证 harness：确认当前 live suite 和 full-chain E2E 已能覆盖真实使用链路。

## 最终决策

将 **当前窄范围定义下的 M4 收口为完成状态**。

这里的“完成”指：

- 已形成从结构化 PoC planning 到结构化 exp verification 的最小差分验证闭环；
- 已有离线 evidence、loopback live runner、managed fixture runtime、opt-in live cases 和 full-chain E2E；
- 已有 open redirect 场景下的最小 response-level observation family；
- 已满足当前路线图对 M4 的最小 acceptance criteria。

这里的“完成”不指：

- 已支持真实项目自动启动或容器环境；
- 已支持更多漏洞族；
- 已支持浏览器执行、鉴权、secrets 或通用 exploit 平台能力；
- 已覆盖所有 response signature。

## 为什么现在这样做

- 当前系统已经具备可验证、可回归、可解释的 M4 闭环。
- 继续把所有横向扩展都挂在 M4 名下，会让主线完成条件失真。
- 先收口，再把后续工作改写为扩展方向，更符合 harness-first 的项目管理方式。

## 不采用的方案

- 继续把更多 observation signal 当作 M4 未完成项：当前不采用，因为会让完成线无限后移。
- 立即新开 M5：当前不采用，因为还没有稳定的下一阶段产品边界。
- 以真实项目环境编排或浏览器执行作为 M4 完成条件：当前不采用，因为会显著扩大安全边界。

## 验证方式

- `./scripts/check`
- `./scripts/benchmark`
- `./scripts/benchmark-live`
- `./scripts/e2e-smoke`
- 路线图、架构文档和 benchmark baseline 对 M4 状态的语义更新

## 重新评估条件

- 项目决定把真实项目环境编排纳入默认主线；
- 项目决定把更多漏洞族的 exp verification 作为当前产品承诺；
- 项目决定引入浏览器执行、鉴权或更强 runner 类型。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
