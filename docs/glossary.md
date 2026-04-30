# 术语表

本文档定义项目内长期使用的核心术语。它用于统一 Codex、文档、测试和后续实现中的表达，避免同一个词在不同阶段被误用。

## 使用原则

- 术语表记录稳定含义，不记录临时任务说明。
- 新增长期有效术语时，优先更新本文档，而不是只写在对话里。
- 术语含义发生变化时，应同步检查 `docs/methodology.md`、`docs/architecture.md`、`docs/roadmap.md` 和相关 ADR。
- 英文术语可以保留原文；中文解释用于明确项目内语义边界。

## 阶段与结论

### clue

漏洞线索。可以来自漏洞描述、PR 列表、commit、issue、CVE 描述、用户输入、扫描结果或人工观察。

clue 只能启动分析，不能直接等同于漏洞结论。

### candidate

候选结论。表示当前证据支持进一步分析，但尚未达到确认标准。

项目中常见候选包括 `SinkCandidate`、candidate taint path 和 candidate PoC idea。

### recommended

推荐结论。表示系统在多个候选中基于证据和置信度排序后给出的首选结果。

recommended 仍然不是最终漏洞确认；它必须可被后续证据降级。

### reachable

可触达。表示存在本地静态证据支持入口到候选路径上下文可达。

项目使用三态语义：

- `true`：有入口到路径上下文的静态可达证据。
- `false`：有明确阻断证据。
- `null`：候选路径存在，但证据不足，无法确认可达或不可达。

`reachable=true` 不表示 PoC 已触发，也不表示漏洞已验证。

### triggerable

可触发。表示已经有具体输入、请求或运行步骤，理论上能触发目标行为。

triggerable 属于 M3 PoC 阶段，不应在 M2 可触达确认中提前声明。

### verified

已验证。表示在隔离环境中通过执行证据确认受影响版本与修复版本存在符合预期的行为差异。

verified 属于 M4 exp 验证阶段。

### unknown

未知。表示证据不足、模型不支持、输入缺失或结果无法可靠判断。

unknown 不是失败，而是避免伪造确定性的安全状态。

## 漏洞分析对象

### source

污染源。表示外部可控或潜在不可信数据进入程序分析模型的位置。

示例包括 HTTP 参数、请求体、header、cookie、环境变量、文件内容、消息队列输入等。

### sink

安全敏感操作或危险 API。表示数据到达后可能产生安全影响的位置。

示例包括命令执行、SQL 查询、模板渲染、重定向、反序列化、文件写入、路径解析、代码执行等。

### sanitizer

清洗、校验、编码、权限检查或隔离逻辑。它可能阻断 source 到 sink 的风险传播。

sanitizer 不能只凭函数名确认有效，必须结合上下文、数据类型和漏洞类型判断。

### propagator

传播器。表示数据从一个表达式、变量、对象、字段或容器传播到另一个位置的规则或代码行为。

例如集合写入、对象字段赋值、字符串拼接、函数返回值和回调传参。

### taint

污染状态。表示某个值、对象或表达式可能受不可信输入影响。

taint 是程序分析抽象，不等同于真实攻击可控。

### taint path

污点路径。表示 source 到 sink 的候选传播路径。

在本项目中，`TaintPath` 默认是候选证据；只有经过可触达确认后，才能成为 reachable taint path。

### entrypoint

程序入口。表示外部输入进入应用或某段代码被调用的入口位置。

示例包括 Web route、controller、CLI command、RPC handler、message consumer、test entry 和公开 API。

### call chain

调用链。表示从入口到目标函数、source、sink 或路径上下文的函数调用或近似调用序列。

第一版可以是近似链，但必须带证据和 unknowns。

### blocking factor

阻断因素。表示支持 `reachable=false` 或阻止升级为 `reachable=true` 的证据。

示例包括明确 guard、有效 sanitizer、不可满足配置、版本差异、不可达分支、未注册 handler。

## 证据与报告

### evidence

证据。支持某个候选或结论的可复核材料。

证据可以来自代码位置、diff、Semgrep finding、taint trace、运行日志、人工输入、commit、PR 或文档。

### evidence chain

证据链。将多个 evidence 按判断逻辑组织起来，说明为什么当前结论成立、还缺什么、如何复现或反驳。

### unknowns

未确认项。表示阻止结论升级的问题清单。

unknowns 应具体、可行动，避免写成泛泛的“不确定”。

### confidence

置信度。表示当前结论被证据支持的程度。

confidence 必须来自证据质量、证据数量、冲突情况和可复现程度，不能作为装饰字段。

### reproducible steps

复现步骤。表示重新获得证据或验证判断所需的命令、输入、路径、版本和环境说明。

## 协作与流程

### 主实现 agent

项目中负责主线实现、仓库修改、测试、benchmark、验证、提交和最终交付的核心 agent。

主实现 agent 对最终结果负责，并负责把理论建议收敛为文档、代码和可验证工件。

### 研究型 agent

项目中负责理论、算法、论文、行业做法、方案比较和失败模式梳理的辅助 agent。

研究型 agent 默认不直接承担主线实现责任；它的输出应服务当前阶段决策，并沉淀为 Insight、ADR、测试思路或 benchmark 约束。

### 双轨协作

“主实现 agent + 研究型 agent”的固定协作模式。

它用于把理论支撑与工程落地组织成闭环：研究型 agent 提供方案比较和边界判断，主实现 agent 负责最小实现、验证和最终收敛。

### 语义增强层

指位于确定性规则层和最终安全结论之间的辅助能力层。

在本项目中，语义增强层主要指 LLM 基于文档、源码或检索结果，对 unfamiliar API、长尾库函数或
wrapper 的 source/sink/sanitizer 语义做带证据的候选判断。

语义增强层可以补知识覆盖，但不能直接替代规则层，也不能单独给出最终 safe 结论。

## 工具与中间表示

### Semgrep finding

Semgrep 规则命中的结构化结果。它是候选证据，不等同于漏洞确认。

项目中 Semgrep finding 会被归一化为 `NormalizedFinding`。

### Semgrep taint trace

Semgrep taint-mode 输出中的 source、intermediate 和 sink 路径信息。

trace 存在表示候选传播关系；trace 缺失不表示漏洞不存在。

### NormalizedFinding

项目内部的 finding 归一化表示，用于屏蔽外部工具 JSON 格式差异。

### TaintPath

项目内部的候选污点路径模型。它可以来自 Semgrep taint trace，也可以来自后续其他程序分析工具。

`TaintPath.reachable` 默认保持 `None`，直到 M2 reachability assessment 提供证据。

### ReachabilityAssessment

M2 可触达评估结果。用于说明候选 `TaintPath` 是否有静态证据支持入口可达、是否有明确阻断证据，或为什么仍保持 unknown。

### SinkCandidate

M1 sink 生成阶段输出的候选 sink。

它可以来自用户已知 sink、漏洞描述、diff artifact、Semgrep finding 或本地 heuristic pack。

## 里程碑

### M0

基础 harness。目标是建立可开发、可验证、可回滚的工程环境。

### M1

sink 函数生成。目标是根据输入线索生成或确认漏洞 sink 函数候选。

### M2

污点路径生成与可触达确认。目标是生成 candidate taint path，并确认哪些路径可触达。

### M3

PoC 生成。目标是基于 reachable taint path 生成最小触发样例或步骤。

### M4

exp 验证与生成。目标是在隔离环境中自动验证受影响版本和修复版本的行为差异。

## 安全产物

### PoC

Proof of Concept。用于证明触发条件和最小输入的验证样例。

PoC 应尽量安全、最小、可复现，并明确未运行或未验证风险。

### exp

Exploit 或验证脚本。在本项目中，exp 默认指用于验证漏洞判断的自动化脚本，不默认指破坏性利用代码。

exp 必须在隔离环境中运行，并输出日志、退出码、请求响应或行为差异。
