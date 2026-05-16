# Insight: 为 M2 引入最小本地 guard/blocking evidence

## 元信息

- 日期：2026-05-16
- 状态：Accepted
- 关联任务：M2 reachability 主线校准；将 `reachable=false` 从手写 JSON 推进到本地确定性 AST 证据
- 关联 ADR：`docs/decisions/0013-use-local-guard-blocking-evidence.md`
- 决策类型：分析策略

## 背景

当前 M2 已经具备：

- Semgrep taint path candidate 对齐；
- `reachable=true|false|null` 三态；
- 本地 Flask 入口模型、局部 helper chain 和 source controllability AST 证据；
- 基于手写 reachability JSON 的 blocked case。

但现在的 `reachable=false` 仍然主要依赖手写 JSON。入口模型已经越来越完整，再继续只补 route 变体，边际收益开始下降。真正缺的主线能力，是把“明确 guard / blocking factor”也变成可以从本地源码中提取的确定性证据。

## 决策问题

M2 下一步是否应该把重点从继续扩入口模型，转向最小本地 guard/blocking evidence？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：reachability 不是只有“有没有入口”，还包括“路径是否被明确阻断”。
- 最小必要能力：能从本地 AST 中识别少量、明确、可回归的 guard 模式。
- 不可牺牲约束：`reachable=false` 必须只在证据非常明确时输出。
- 最大风险：把弱 guard、名字像 sanitizer 的逻辑，误当成真实阻断。

### 工程化专家

- 根本问题：现在 blocked case 只能靠手写 JSON，主执行链与真实源码脱节。
- 最小必要能力：一条很窄的 AST heuristic，能补正例/负例 fixture 和 benchmark。
- 不可牺牲约束：不能把 guard 分析一下子做成大而泛的 symbolic engine。
- 最大风险：为了追求“更聪明”而牺牲可测试性和可解释性。

### 漏洞安全专家

- 根本问题：仅有入口可达并不等于漏洞可达；guard/sanitizer 会改变漏洞判断。
- 最小必要能力：先识别最常见、最明确、最不含糊的阻断模式。
- 不可牺牲约束：不能因为 guard 名字“看起来安全”就输出 false。
- 最大风险：把仍然可控但被部分约束的数据，错误降成不可达，形成 false negative。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：CodeQL、Semgrep 等通常把 sanitizer/guard 单独建模，而不是混进入口分析。
- 备选方案：
  - A. 继续只扩入口模型；
  - B. 引入最小本地 guard heuristic；
  - C. 直接做更泛化的数据流/条件约束分析。
- 优点：B 能最小成本补齐 `reachable=false` 的本地证据来源。
- 缺点和失败模式：B 覆盖很窄，必须接受大量场景继续保持 `null`。

### 工程化专家

- 业界常见做法：先把最常见模式固化成 deterministic heuristic，再看是否值得做通用分析。
- 备选方案：
  - A. 继续手写 blocked JSON；
  - B. 只支持少量 handler-local guard；
  - C. 一步到位支持跨函数 guard/sanitizer。
- 优点：B 能直接进入现有 harness，不引入新运行时依赖。
- 缺点和失败模式：如果模式定义不窄，很容易让测试变脆。

### 漏洞安全专家

- 业界常见做法：漏洞 triage 会把“明确 guard 存在”与“仍然不确定”分开；默认宁可 unknown，也不轻易 false。
- 备选方案：
  - A. 保持 blocked 只来自人工证据；
  - B. 只支持明确的相对路径 guard 一类模式；
  - C. 让 LLM 直接判断 guard 是否有效。
- 优点：B 风险最可控，而且能和当前 open redirect fixtures 直接对齐。
- 缺点和失败模式：只适合很具体的漏洞族，不能被误当成通用 sanitizer 引擎。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果继续只做入口模型，M2 的 `false` 会不会长期停留在手写 JSON 层？
- 需要验证的假设：handler-local 的相对路径 guard 能否稳定用 AST 抽出来。
- 当前最小可行决策：支持一类显式、窄边界的本地 guard pattern。
- 验证 harness：positive blocked case、unknown fallback case、existing true cases 不回退。

### 工程化专家

- 对其他方案的质询：如果上来做跨函数/跨模块 guard，会不会直接把 reachability 模块做重？
- 需要验证的假设：实现可以限制在 Flask handler 本地，不改动核心数据模型结构。
- 当前最小可行决策：先做 handler-local guard，blocking factor 仍复用现有结构。
- 验证 harness：unit test、CLI、benchmark case、`./scripts/check`、`./scripts/benchmark`。

### 漏洞安全专家

- 对其他方案的质询：如果让 LLM 或宽松 heuristic 直接输出 false，谁来兜住 false negative 风险？
- 需要验证的假设：被识别的 guard 模式确实对应“当前漏洞语义被阻断”，而不是仅仅“路径仍可到 sink”。
- 当前最小可行决策：只支持 open redirect 下非常明确的“相对路径约束”阻断模式。
- 验证 harness：blocked case 必须给出明确 `blocking_factor_kind`；其他 guard/sanitizer 继续保持 `null`。

## 最终决策

在当前阶段，M2 下一步从“继续扩入口模型”切换到“引入最小本地 guard/blocking evidence”。

第一版只支持：

- Flask handler-local 的显式 guard；
- 与当前 open redirect 语义直接对应的、非常窄的相对路径约束模式；
- 仍通过现有 `blocking_factors` 结构表达 `reachable=false`。

超出该边界的 guard、wrapper、跨函数 sanitizer、第三方库校验逻辑，一律继续保持 `reachable=null`。

## 为什么现在这样做

- 入口模型已经覆盖了 route decorator、method-specific decorator、Blueprint 注册和 `add_url_rule(...)`，继续扩同类变体的收益正在下降。
- M2 的 blocked 语义如果长期停留在手写 JSON，就无法形成真正“从源码到结论”的闭环。
- 这一步正好补上 `true / false / null` 三态里最薄弱的一环。

## 不采用的方案

- 继续只补 Flask 入口变体：不采用，因为主线收益开始下降。
- 一步到位做通用 sanitizer/guard 引擎：不采用，因为过重、难验证。
- 让 LLM 直接判断 guard 是否有效：不采用，因为当前阶段应先坚持本地确定性证据。

## 验证方式

- 新增本地源码 fixture 和 Semgrep trace fixture。
- 新增至少一个 `reachable=false` 的 source-root blocked case。
- 保持现有 `reachable=true` 和 `reachable=null` curated cases 全部通过。
- 运行 `./scripts/benchmark` 和 `./scripts/check`。

## 重新评估条件

- 需要支持跨函数、跨模块 guard/sanitizer。
- 需要覆盖比 open redirect 更广的漏洞语义。
- 当前最小 heuristic 在 benchmark 中出现系统性误判。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [ ] 是否需要更新测试或 fixture
