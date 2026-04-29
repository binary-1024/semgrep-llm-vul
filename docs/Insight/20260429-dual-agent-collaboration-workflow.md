# Insight: 实现 agent 与研究型 agent 的双轨协作工作模式

## 元信息

- 日期：2026-04-29
- 状态：Accepted
- 关联任务：固定项目级 agent 协作模式
- 关联 ADR：`docs/decisions/0011-use-dual-track-agent-collaboration.md`
- 影响范围：agent 流程 | 开发流程 | 决策流程

## 背景

`semgrep-llm-vul` 同时具有两个特征：一是它是一个需要持续交付代码、fixture、benchmark 和 CLI 的工程项目；二是它的方法论和能力边界又强依赖程序分析、漏洞研究和算法取舍。

如果只做实现，很容易陷入“局部功能越做越深，但理论边界、失败模式和替代方案没有被系统梳理”的问题；如果只做研究，又会把项目拖进长时间文献调研，迟迟不能回到可验证的 harness 和主线交付。

因此需要把“理论支撑”和“工程落地”拆成稳定但闭环的两个轨道，并把这套协作方式写成长期规范。

## 架构问题

对于一个以程序分析与漏洞验证为核心的 agent 项目，如何建立一种既能持续获得理论支撑、又不会阻塞主线实现和验证的固定协作模式？

## 第 1 轮：第一性原理拆解

### 资深 agent 开发架构师

- 根本问题：单一 agent 同时承担研究、实现、验证和项目节奏管理时，容易在深度研究与主线交付之间来回切换，导致上下文抖动和决策漂移。
- 最小必要能力：一个负责主线实现与交付的核心 agent，一个负责理论、论文、算法比较和方案收敛的研究型 agent，以及两者之间稳定的信息回流机制。
- 不可牺牲约束：最终代码、测试、harness 和交付责任必须归于单一主实现 agent；研究输出不能绕过 Insight/ADR 直接变成长期规则。
- 最大风险：把研究型 agent 变成新的上下文噪声源，或者把它的建议当成未经验证的“权威答案”。

### 软件工程师

- 根本问题：项目需要可验证、可回归、可维护的节奏，不能因为研究任务而让实现分支长期悬空。
- 最小必要能力：清晰的角色边界、明确的输入输出格式，以及“做到什么程度就停”的停止条件。
- 不可牺牲约束：不增加无意义流程负担；不能为了“多 agent”而让每个小任务都必须开子任务。
- 最大风险：职责不清导致重复劳动，或者研究结论没有沉淀到文档，最后仍然只能依赖聊天记忆。

### 程序分析专家

- 根本问题：调用图、污点传播、框架入口、版本差异、sanitizer 有效性等问题具有明显理论背景；如果没有专门的理论轨道，工程实现会过早固化为局部 heuristic。
- 最小必要能力：研究型 agent 能持续输出算法候选、适用边界、失败模式和验证建议。
- 不可牺牲约束：理论结论必须和当前项目阶段匹配，不能直接把完整 CHA、RTA、points-to 或跨语言调用图路线塞进当前 M2。
- 最大风险：研究型 agent 按“学术上最完整”而不是“当前阶段最可落地”来给建议，反而把主线拖偏。

### 漏洞安全专家

- 根本问题：漏洞分析中的很多错误，不是代码写错，而是结论越级，例如把 candidate 当 reachable，把 reachable 当 verified。
- 最小必要能力：研究型 agent 帮助识别安全语义边界，主实现 agent 把这些边界落实到 schema、测试和 harness 里。
- 不可牺牲约束：研究输出不能替代证据；安全结论仍然要靠本地证据链、fixture 和验证命令来闭环。
- 最大风险：研究 agent 给出听起来合理但无法在当前仓库复现的建议，导致安全边界变得口头化。

## 第 2 轮：业界做法与备选方案

### 资深 agent 开发架构师

- 业界常见做法：复杂系统设计常把“研究/架构评审”和“实现/验证”分层处理，通过 RFC、ADR、design review 或 researcher-engineer pairing 形成闭环。
- 备选方案：
  - A. 单 agent 串行完成研究与实现。
  - B. 主实现 agent + 按需研究型 agent 的双轨协作。
  - C. 多个平行 agent 同时承担研究、实现、review。
- 优点：B 在上下文成本、理论支撑和工程可控性之间更平衡；主实现 agent 持有仓库全局责任，研究型 agent 提供聚焦的理论增量。
- 缺点和失败模式：如果边界没写清，B 会退化成“两个 agent 都在提建议，但没人真正收敛”；如果过度扩张，又会滑向 C 的协调成本。

### 软件工程师

- 业界常见做法：团队通常把探索性研究限制在明确问题范围内，并要求研究结果转化为设计文档、测试计划或实验清单，而不是停留在讨论里。
- 备选方案：
  - A. 研究只在遇到明显 blocker 时临时触发。
  - B. 对算法、架构、方法论和能力边界相关任务，默认启用研究型 agent。
  - C. 对所有任务都固定启用研究型 agent。
- 优点：B 既能保证关键决策有理论支撑，也不会给纯实现或小修任务增加固定负担。
- 缺点和失败模式：B 需要定义清楚触发条件；如果定义过宽，仍会增加流程噪声；定义过窄，又会回到“研究总是补做”的被动模式。

### 程序分析专家

- 业界常见做法：程序分析工具落地往往采用“理论候选 -> 小规模原型 -> 基准回归 -> 扩展支持”的路线，而不是直接实现完整分析器。
- 备选方案：
  - A. 研究型 agent 聚焦论文和经典算法，主实现 agent 自己决定落地。
  - B. 研究型 agent 除理论外，还需给出适配当前项目阶段的缩减版本、失败模式和实验建议。
- 优点：B 更符合本项目“证据优先、harness-first”的节奏，研究输出可以直接进入 Insight 和 benchmark 设计。
- 缺点和失败模式：如果没有停止条件，B 可能变成无休止的文献调研。

### 漏洞安全专家

- 业界常见做法：安全研究与工程验证通常分离，但最终风险判断要靠统一的证据链和复现步骤收敛。
- 备选方案：
  - A. 研究型 agent 只负责列论文和术语。
  - B. 研究型 agent 负责把安全语义边界、误报漏报风险、验证层级和失败模式一起梳理清楚。
- 优点：B 能直接服务 `candidate -> reachable -> triggerable -> verified` 的阶段边界。
- 缺点和失败模式：如果输出不落到当前任务，容易变成“知识很多，但对 PR 没帮助”。

## 第 3 轮：交叉质询与收敛

### 资深 agent 开发架构师

- 对其他方案的质询：如果不把主实现 agent 设为唯一集成者，多个 agent 的观点会直接竞争仓库状态，最终没人对结果负责。
- 需要验证的假设：关键决策任务里，引入研究型 agent 是否能减少返工，而不是只增加文档量。
- 当前最小可行架构：固定采用“主实现 agent + 研究型 agent”的双轨模式，但仅对算法、架构、方法论、证据链和能力边界类任务默认启用。
- 验证 harness：观察后续若干 PR 中，研究输出是否稳定转化为 Insight、ADR、测试或 benchmark，而不是停留在聊天里。

### 软件工程师

- 对其他方案的质询：如果所有任务都要求研究参与，会让简单修复也走重流程，拖慢主线。
- 需要验证的假设：触发条件和停止条件写清楚后，这套模式不会造成明显的流程阻塞。
- 当前最小可行架构：研究型 agent 只产出理论支持、方案比较、风险清单和验证建议；主实现 agent 负责代码、文档、测试、回归、提交和最终总结。
- 验证 harness：检查长期规则是否已写入 `AGENTS.md`、`docs/development.md`、`docs/git.md` 和 ADR；后续任务总结中是否能明确说明“双轨输入如何转化为仓库结果”。

### 程序分析专家

- 对其他方案的质询：如果研究型 agent 只做文献罗列，不对当前阶段给出“够用即停”的建议，就无法真正服务主线。
- 需要验证的假设：对于调用图、reachability、sink heuristic、PoC/exp 策略等问题，研究型 agent 的输出能否帮助我们更早识别非目标。
- 当前最小可行架构：研究型 agent 默认回答四件事：为什么可行、有哪些备选、失败模式是什么、当前阶段应做到哪里停。
- 验证 harness：把这些输出落到 Insight 的三轮讨论和最终决策，再由实现 agent 通过 fixture、case 和 `./scripts/check` 检验。

### 漏洞安全专家

- 对其他方案的质询：如果研究输出不能进入证据链语义和安全边界，就无法降低越级结论的风险。
- 需要验证的假设：双轨模式是否能让 `unknowns`、`blocking factors`、阶段结论语义这些关键边界更稳定。
- 当前最小可行架构：研究型 agent 为安全语义和失败模式提供支撑，主实现 agent 把这些边界转化为报告字段、测试断言和 benchmark case。
- 验证 harness：未来涉及 reachability、PoC、exp 的任务，检查是否把“理论边界”同步成结构化输出和回归项。

## 最终架构决策

项目采用固定的双轨协作工作模式：

- 主实现 agent：负责主线实现、仓库修改、测试、benchmark、CLI、验证、提交和最终交付。
- 研究型 agent：负责理论、算法、论文、行业做法、备选方案、失败模式和阶段性建议的梳理。
- 决策收敛：由主实现 agent 汇总研究输出与本地实现/验证反馈，形成下一步 Insight、ADR、任务方案或实现边界。

默认触发场景：

- 架构调整或 agent 流程变化。
- 程序分析算法选择，例如调用图、污点传播、入口模型、版本对照策略。
- 方法论文档、证据链语义、阶段结论语义调整。
- 需要权衡多条技术路线且后续会影响多个里程碑的任务。

默认不必触发的场景：

- 小范围文档修正。
- 已有决策下的直接实现。
- 局部 bug fix、测试补充、fixture 更新。
- 不涉及能力边界变化的日常维护任务。

## 为什么现在这样做

- 项目正在进入程序分析能力逐步扩展的阶段，算法和架构判断会越来越频繁。
- 用户已经明确接受“理论支撑 + 工程落地”双轨模式，并希望把它当成固定工作方式。
- 现在把规则写清楚，能避免后续每次都重新约定一次“要不要开研究 agent、研究完落到哪里”。

## 不采用的方案

- 单 agent 串行研究加实现：不采用。它容易把深度研究和主线交付混在一起，缺少稳定的理论反馈面。
- 对所有任务都强制多 agent：不采用。流程成本过高，会让简单任务失去节奏感。
- 让研究型 agent 直接主导主线实现：不采用。最终仓库集成、验证和责任边界需要保持单一归口。
- 让研究结论只停留在聊天：不采用。长期有效规则必须进入 Insight、ADR 或规范文档。

## 架构边界

- 研究型 agent 默认不直接拥有主线实现责任。
- 研究型 agent 的建议应尽量以“主张 / 适用前提 / 预期收益 / 失败模式 / 最小实验 / kill criterion”组织，避免只给方向不给停止条件。
- 主实现 agent 的总结应尽量以“实现变更 / 验证结果 / 残余 unknowns”组织，避免只报告成功不报告边界。
- 研究型 agent 可以参与讨论、产出方案比较和实验建议，但长期规则仍需由主实现 agent 收敛并写入仓库文档。
- 双轨模式服务主线，不得让研究支线无限膨胀。

## 模块职责

- `AGENTS.md`：记录默认协作规则、触发条件和职责边界。
- `docs/development.md`：记录任务执行流程中的双轨协作步骤。
- `docs/git.md`：记录双轨协作与 docs/feature 分支分离的关系。
- `docs/decisions/`：记录最终确定的长期协作决策。
- `docs/Insight/`：记录具体任务中理论与工程如何收敛。

## 数据流

```text
任务问题
  ↓
主实现 agent 界定主线目标 / 非目标
  ↓
研究型 agent 输出理论依据 / 方案比较 / 风险 / 停止条件
  ↓
主实现 agent 结合仓库现状做最小实现或验证
  ↓
Insight / ADR / 任务计划收敛
  ↓
代码、测试、benchmark、文档变更
```

## 失败处理

- 如果研究输出偏离当前阶段，主实现 agent 应主动缩小为“当前最小可行决策”。
- 如果研究结论无法转化为仓库内证据、测试或文档，应降级为待验证假设，而不是长期规则。
- 如果研究任务开始阻塞主线，应先以现有证据推进最小实现，并把剩余问题记录进 Insight 或 roadmap。

## 可观测性

- 关键任务总结中应说明：是否使用研究型 agent、研究输出如何影响本次决策、哪些内容被转化为文档/测试/benchmark。
- 重要研究结论应能在 `docs/Insight/`、`docs/decisions/` 或相关规范中定位，而不是只存在于聊天记录。

## 参考资料

- CodeQL: About data flow analysis, https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/
- CodeQL: Analyzing data flow in Python, https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/
- Semgrep: Taint analysis overview, https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview
- Dean, Grove, Chambers 1995: Static Class Hierarchy Analysis, https://web.cs.ucla.edu/~palsberg/tba/papers/dean-grove-chambers-ecoop95.pdf
- Bacon and Sweeney 1996: Fast Static Analysis of C++ Virtual Function Calls, https://research.google/pubs/fast-static-analysis-of-c-virtual-function-calls/
- Steensgaard 1996: Points-to Analysis in Almost Linear Time, https://www.microsoft.com/en-us/research/publication/points-to-analysis-in-almost-linear-time/
- PyCG: Practical Call Graph Generation in Python, https://www.spinellis.gr/pubs/conf/2021-ICSE-pycg/html/journal.pdf

## 验证方式

- 本次决策通过以下方式验证：
  - 增加 Insight 与 ADR，形成可查阅的长期规则。
  - 更新 `AGENTS.md`、`docs/development.md`、`docs/git.md` 和术语表，确保规则可执行、可检索。
  - 继续在后续算法/架构任务中使用该模式，并观察是否减少返工或主线偏移。

## 重新评估条件

- 研究型 agent 的输出长期无法转化为仓库内工件。
- 多 agent 协作开始显著增加等待、重复劳动或上下文噪声。
- 项目进入更大规模并行开发，需要从“双轨”升级到更明确的多角色编排。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [x] 是否需要更新 `AGENTS.md`
- [x] 是否需要更新测试或 fixture
