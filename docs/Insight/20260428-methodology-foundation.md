# Insight: 漏洞分析方法论基础

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：方法论强化
- 关联 ADR：`docs/decisions/0007-use-falsifiable-evidence-first-methodology.md`
- 决策类型：分析策略 | 安全边界 | 工程流程

## 背景

项目已经有 `docs/methodology.md` 的第一版，但它更像原则纲要。随着项目进入 M1 sink generation，方法论必须能够支撑后续实现、测试、review 和安全边界，而不只是描述“证据优先”。

方法论需要回答：

- 为什么这条分析链路从理论上可行？
- 每一步产出的结论如何被验证或反驳？
- 程序分析、LLM agent、人工审查和动态验证分别承担什么职责？
- 行业内常见做法如何映射到本项目的 harness？

## 决策问题

项目应采用怎样的核心方法论，才能让漏洞分析从线索到 exp 验证具备理论依据、工程可行性和可验证性？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：漏洞分析本质上是在程序中寻找“危险语义是否能被外部可控输入触达”。这可以拆成 source、propagator、sanitizer、sink、entrypoint 和 runtime behavior。
- 最小必要能力：每一阶段必须把自然语言线索落到程序实体、代码位置或运行行为。
- 不可牺牲约束：静态分析只能产生候选和约束，不能直接等同于漏洞可利用。
- 最大风险：把单一工具结果当成事实，忽略路径不可达、sanitizer、配置、版本和运行条件。

### 工程化专家

- 根本问题：方法论必须转化为可测试 pipeline，否则只能停留在报告写作。
- 最小必要能力：为每一阶段定义输入、输出、可验证断言、失败状态和 fixture。
- 不可牺牲约束：第一版必须离线、确定性、可回归；外部服务和 LLM 只能作为可替换增强。
- 最大风险：方法论过大、过抽象，导致无法落实到 `./scripts/check`、fixture 和 CLI 行为。

### 漏洞安全专家

- 根本问题：漏洞结论不是“工具报了 finding”，而是“攻击前置条件、数据流、危险操作和实际触发效果是否同时成立”。
- 最小必要能力：结论必须分级：candidate、reachable、triggerable、verified，而不是一步到 final vulnerability。
- 不可牺牲约束：PoC/exp 需要隔离环境和安全边界；不能默认生成破坏性 payload。
- 最大风险：LLM 生成过度自信结论，或 exp 验证缺少受影响版本与修复版本对照。

## 第 2 轮：理论依据、行业做法与备选方案

### 程序分析专家

- 理论依据：静态分析通过抽象程序行为得到保守近似；taint analysis 将风险建模为 source 到 sink 的传播关系；data-flow analysis 可用于回答数据是否可能从一个程序点流向另一个程序点。
- 行业做法：Semgrep taint-mode、CodeQL data flow/taint tracking、SARIF 结果归一化、patch diff review 都采用“候选证据 + 人工或后续验证”的方式。
- 备选方案：单工具主导、LLM 主导、多证据融合。
- 优点：多证据融合更适合跨语言、跨框架和不完整输入。
- 缺点和失败模式：多证据融合需要更严格的证据 schema 和冲突处理。

### 工程化专家

- 理论依据：可测试系统必须具备可观察输入、确定性中间产物和可断言输出；否则无法回归。
- 行业做法：成熟安全工具链通常把扫描、triage、验证、报告分离，用 CI、fixture、规则库和基准样例维护质量。
- 备选方案：报告优先、pipeline 优先、benchmark 优先。
- 优点：pipeline 优先最适合当前阶段，因为它能先约束行为再逐步提高智能程度。
- 缺点和失败模式：如果没有最小可执行切片，方法论会变成大而空的文档。

### 漏洞安全专家

- 理论依据：漏洞可利用性需要满足前置条件、输入控制、传播路径、危险操作和可观察效果。任何单点证据都不足以推出最终结论。
- 行业做法：OWASP WSTG 强调基于测试的验证；NIST SSDF 强调验证、可追踪和降低漏洞风险；漏洞研究常用受影响版本与修复版本对照来验证判断。
- 备选方案：只做静态判断、只做动态验证、静态候选 + 动态验证闭环。
- 优点：静态候选 + 动态验证闭环能兼顾覆盖率和可信度。
- 缺点和失败模式：动态验证成本高，环境不可复现时必须保留 unknown 状态。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果动态验证成本高，是否会让早期阶段无法推进？
- 需要验证的假设：静态阶段可以输出候选和不确定性，动态验证只在 PoC/exp 阶段成为最终确认条件。
- 当前最小可行决策：方法论采用“分阶段可反驳结论”，每个阶段只声明自己能证明的内容。
- 验证 harness：每个阶段都必须有 positive、negative、insufficient、malformed fixture 或测试断言。

### 工程化专家

- 对其他方案的质询：多来源证据会不会让 schema 过早复杂？
- 需要验证的假设：可以先用统一 `Evidence` + `SourceReference` + confidence/unknowns 表达证据，不急于引入复杂知识图谱。
- 当前最小可行决策：方法论要求 evidence-first 和 falsifiable-by-design，但实现按里程碑逐步落地。
- 验证 harness：每个 pipeline 输出必须能被 snapshot-free 的结构化断言验证。

### 漏洞安全专家

- 对其他方案的质询：如何避免 PoC/exp 生成越界？
- 需要验证的假设：把 PoC 定义为最小安全验证样例，把 exp 定义为隔离环境中的对照验证，可以降低风险。
- 当前最小可行决策：方法论明确 safety gate：敏感数据不默认外传、破坏性 payload 不默认生成、exp 需要隔离环境和版本对照。
- 验证 harness：PoC/exp 阶段的输出必须包含环境、命令、日志、退出码或响应证据。

## 最终决策

项目采用 falsifiable evidence-first vulnerability analysis 方法论：

1. 从第一性原理拆解漏洞：external control、entrypoint、source、propagation、sanitizer、sink、reachability、trigger effect。
2. 用程序分析工具生成候选证据，不把工具 finding 当成最终结论。
3. 用 LLM agent 做语义理解、证据归纳和排序辅助，但不允许绕过证据链。
4. 用分阶段结论控制语义：candidate、reachable、triggerable、verified。
5. 用受影响版本与修复版本对照、PoC/exp 和日志证据完成最终验证。
6. 用 harness 把每个失败模式转化为 fixture、测试断言或明确的人工验证步骤。

## 为什么现在这样做

- M1 即将实现 sink candidate pipeline，必须先明确方法论边界。
- 现有 `docs/methodology.md` 还缺少理论依据、行业洞察和可验证标准。
- 如果方法论不够严格，后续 LLM agent 很容易产出无法审计的漏洞结论。

## 不采用的方案

- LLM-first 方法论：不采用，因为不可复现、难测试、容易过度自信。
- SAST-only 方法论：不采用，因为静态 finding 不能证明可触达或可利用。
- Exploit-first 方法论：不采用，因为安全风险高，也无法解释和回归中间分析过程。
- 一次性 final report 方法论：不采用，因为无法把失败模式沉淀到 harness。

## 验证方式

本次文档更新需要：

- 扩展 `docs/methodology.md`，加入第一性原理、理论依据、技术可行性、行业洞察和可反驳验证标准。
- 同步 ADR 记录最终方法论。
- `./scripts/check` 通过。

后续实现需要：

- 每个里程碑都提供 candidate、negative、insufficient、malformed 相关测试。
- 输出结构中显式保留 evidence、confidence、unknowns 和 reproduction。
- PoC/exp 阶段必须包含隔离环境和对照验证证据。

## 重新评估条件

- 接入真实 LLM provider。
- 接入真实 GitHub repo clone 和 diff 获取。
- 引入 CodeQL、Joern、SARIF 或其他程序分析工具。
- 开始自动生成 PoC/exp。
- 出现无法用现有 evidence/confidence/unknowns 表达的重要案例。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/methodology.md`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
