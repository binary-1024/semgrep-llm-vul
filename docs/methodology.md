# 方法论

本文档定义 `semgrep-llm-vul` 的漏洞分析方法论。它回答“我们如何从漏洞线索走到可验证结论”，不同于 `docs/development.md` 的工程开发流程。

本方法论不是一次性报告模板，而是一套可反驳、可测试、可回归的分析 harness。它要求每个候选结论都能被证据支持，也能被后续证据推翻或降级。

## 总纲

项目采用 falsifiable evidence-first vulnerability analysis：

> 先收集可复核证据，再生成候选结论；先标记不确定性，再推进验证；任何 agent 推理都必须回到代码、diff、finding、日志或人工输入。

核心目标：

- 全面：覆盖 sink、source、propagation、sanitizer、reachability、PoC、exp 和最终判断。
- 缜密：区分候选、可触达、可触发、已验证，不把任一中间证据当成最终漏洞。
- 可验证：每个阶段都有输入、输出、证据、失败状态和测试/复现方式。
- 理论上可行：建立在程序分析、taint analysis、patch diff analysis 和动态验证的组合上。
- 工程上可落地：先用本地、确定性、离线 harness 实现最小闭环，再逐步引入 LLM、GitHub API 和更多分析器。

## 第一性原理

漏洞分析的根本问题是：

> 外部可控输入，是否能在具体版本、配置和执行条件下，到达安全敏感操作，并产生可观察的安全影响？

这可以拆成八个基本要素：

1. external control：攻击者或外部输入是否可控。
2. entrypoint：输入从哪里进入程序。
3. source：程序分析意义上的污染源。
4. propagation：数据如何在函数、对象、字段、回调或协议边界中传播。
5. sanitizer：是否存在有效校验、编码、权限检查或隔离。
6. sink：安全敏感操作或危险 API。
7. reachability：source 到 sink 的路径是否从实际入口可达。
8. trigger effect：触发后是否能观察到安全影响或版本差异。

任何漏洞结论都至少需要解释这些要素中的相关部分。缺失要素必须进入 `unknowns`，不能被 LLM 推理静默补全。

## 理论依据

### 程序分析

程序分析通过抽象程序行为来回答“某种性质是否可能成立”。本项目使用程序分析时遵循两个原则：

- 静态分析提供候选和约束，不直接提供最终可利用结论。
- 动态验证提供具体执行证据，但覆盖范围受输入和环境限制。

因此，静态和动态不是互相替代，而是形成闭环：

```text
static candidates
  ↓
human/agent triage
  ↓
targeted PoC
  ↓
controlled exp verification
```

### Data-flow 与 taint analysis

taint analysis 将风险建模为 source 到 sink 的传播关系，并考虑 sanitizer 是否阻断传播。Semgrep taint-mode 和 CodeQL data flow/taint tracking 都采用类似抽象：定义 source、sink、sanitizer，并分析数据是否可能沿路径传播。

本项目采用这一理论，但不假设工具输出完备：

- path 存在表示“候选传播关系”，不是“可触达漏洞”。
- path 缺失不代表“没有漏洞”，可能是规则、语言建模或工具能力不足。
- sanitizer 需要结合上下文判断，不能只看名称。

### Patch diff analysis

修复 diff 是漏洞分析的重要证据，因为它揭示维护者认为需要改变的行为。diff 可用于发现：

- 新增校验、编码、权限检查或边界检查。
- 删除或替换危险调用。
- 改变数据流、控制流或默认配置。
- 新增测试用例或错误处理。

diff 只能说明“修复意图或行为变化”，不能单独证明漏洞可利用。它应与代码位置、Semgrep finding、路径分析或动态验证交叉确认。

### 动态验证

PoC 和 exp 用于把候选判断推进到可观察行为：

- PoC 证明触发条件和最小输入。
- exp 在隔离环境中自动验证受影响版本与修复版本的行为差异。

动态验证的理论边界是覆盖性：一个 exp 失败不必然证明漏洞不存在，可能是环境、配置、输入或路径未覆盖。失败必须记录为 evidence，而不是简单丢弃。

## 行业洞察

本项目的方法论吸收但不盲从行业实践：

- SAST 工具擅长快速发现候选代码位置，但误报和漏报都不可避免。
- CodeQL、Semgrep、SARIF、Joern 等工具输出应进入统一证据模型，而不是直接驱动最终结论。
- OWASP WSTG 代表的测试方法强调用可复现测试验证安全风险。
- NIST SSDF 代表的软件安全实践强调验证、可追踪和降低漏洞风险。
- 实际漏洞研究通常结合 CVE 描述、patch diff、commit message、测试变化、SAST finding、人工代码审计和运行验证。

因此，本项目不采用单工具、单 agent、单报告的路线，而采用多证据、分阶段、可回归的路线。

## 分析对象

一次漏洞分析任务围绕以下对象展开：

- `VulnerabilityInput`：用户提交的任务事实，包括 repo、版本、漏洞描述、sink 信息、候选 PR 和 artifacts。
- `Evidence`：支持某个判断的证据，包括描述、代码位置、diff、Semgrep finding、运行日志等。
- `SourceReference`：证据或候选对应的文件、行号、函数、URL、commit 或 artifact 位置。
- `SinkCandidate`：候选或推荐 sink，不等同于最终漏洞确认。
- `TaintPath`：候选污点路径，不等同于可触达路径。
- PoC：用于证明触发条件的最小验证样例。
- exp：在隔离环境中自动验证受影响版本与修复版本行为差异的脚本。

## 分阶段结论

项目避免“一步到位”的漏洞结论，而是把结论分阶段推进：

```text
clue
  ↓
sink candidate
  ↓
candidate taint path
  ↓
reachable taint path
  ↓
PoC
  ↓
exp verification
  ↓
final vulnerability judgment
```

每一阶段只能声明本阶段已经验证的内容：

- sink generation：输出候选或推荐 sink，不声明漏洞可利用。
- taint path generation：输出候选路径，不声明入口可触达。
- reachability confirmation：声明路径可触达、不可达或 unknown。
- PoC generation：说明触发方式、前置条件和预期效果。
- exp verification：通过执行日志、退出码、请求响应或行为差异给出最终判断。

阶段结论必须允许降级：

- `recommended` 可以降级为 `candidate`。
- `reachable` 可以降级为 `unknown` 或 `not_reachable`。
- PoC 可以标记为 `not_run`、`failed_to_trigger` 或 `environment_missing`。
- exp 可以标记为 `verified`、`not_verified`、`inconclusive`。

## 证据链原则

每个候选和结论都必须携带证据链。

证据链至少包含：

- 来源：漏洞描述、PR、commit、diff、代码位置、Semgrep 结果、运行日志、人工输入等。
- 内容：支持当前判断的关键片段或摘要。
- 推理：为什么该证据支持当前判断。
- 置信度：当前判断的可信程度。
- 未确认项：还缺什么信息，哪些判断仍存在不确定性。
- 复现方式：如何重新得到该证据，例如命令、文件路径、commit hash 或测试步骤。

没有证据锚点时，系统应输出“无法推荐”或低置信候选，而不是伪造高置信结论。

证据之间可能冲突。冲突时不做静默覆盖，必须记录：

- 冲突双方是什么。
- 哪一方更可信，为什么。
- 是否需要额外测试或人工确认。
- 当前结论是否需要降级。

## 可反驳性标准

方法论要求每个重要判断都能被反驳。一个结论如果无法说明“什么证据会推翻它”，就不能进入高置信输出。

示例：

- sink candidate 可被反驳：代码位置并非危险操作，或修复 diff 与该函数无关。
- taint path 可被反驳：路径中存在有效 sanitizer，或调用链在目标版本不可达。
- reachable path 可被反驳：入口需要不可满足的权限、配置或状态。
- PoC 可被反驳：输入无法触发预期行为。
- exp verified 可被反驳：修复版本仍可触发，或受影响版本在相同环境无法触发。

## 程序分析与 LLM 分工

程序分析工具负责提供可结构化证据：

- Semgrep finding：规则命中的代码位置和模式证据。
- Semgrep taint-mode trace：候选 source 到 sink 的静态路径证据。
- 后续可扩展 CodeQL、SARIF、Joern、调用图和语言 AST。

LLM agent 负责处理难以完全规则化的部分：

- 从漏洞描述中归纳风险语义。
- 总结 diff 意图和修复模式。
- 辅助合并多来源证据。
- 给出候选排序理由和下一步分析建议。
- 生成待验证假设和缺失证据清单。

LLM agent 不应直接产生不可追溯的最终结论。凡是 LLM 输出的候选，都必须能追溯到输入证据或明确标记为待验证假设。

### LLM 语义增强层

项目接受这样一种受约束用法：当 source/sink/sanitizer 的规则知识覆盖不全时，LLM 可以作为
**语义增强层**，辅助判断 unfamiliar library API、长尾库函数和项目自定义 wrapper 的语义。

但这层能力必须满足以下约束：

- 它增强的是知识覆盖率，不替代程序分析骨架。
- 它输出的是带证据的候选语义判断，不是直接可执行的最终结论。
- 它必须绑定适用版本、适用上下文、失败模式和 unknowns。
- 它不能单独把 unknown 升级为 safe。
- 对 sanitizer 的判断默认最保守，因为 sanitizer 是否有效高度依赖威胁模型、数据类型、sink 上下文和版本实现。

因此，在本项目里更合理的分工是：

- 规则和程序分析：负责稳定、确定性、可回归的 source/sink/sanitizer 基线。
- LLM + 检索：负责补 unfamiliar API 的候选语义、给出证据摘要、指出版本和上下文前提。
- harness：负责决定哪些候选可以升级为稳定知识，哪些必须继续保持 `candidate` 或 `unknown`。

当前 M1/M2 阶段先建立这套方法论和验证边界，不急于把在线 LLM/MCP 直接接入主执行路径。

## Semgrep 的角色

Semgrep 是跨语言分析入口之一，不是唯一事实来源。

本项目对 Semgrep 输出采用双层语义：

- `NormalizedFinding`：Semgrep 规则命中的 finding，是候选证据。
- `TaintPath(reachable=None)`：当 Semgrep 输出可识别 trace 时派生的候选路径，尚未完成可触达确认。

因此：

- Semgrep finding 不能直接等同于漏洞。
- taint trace 不能直接等同于可触达路径。
- trace 缺失时不强行生成路径，但 finding 仍可作为证据保留。

## 已知 sink 与未知 sink

### 已知 sink

用户提供 sink signature 时，系统应：

- 将用户输入作为高优先级候选。
- 标准化函数签名和代码位置。
- 补充漏洞片段、artifact、Semgrep finding 或描述证据。
- 输出候选或推荐 sink，不直接声明漏洞已确认。

### 未知 sink

用户没有提供 sink 时，系统应：

- 从漏洞描述中提取危险行为。
- 从修复 diff 或候选 PR 中寻找行为变化、校验新增、危险调用替换或删除。
- 从 Semgrep finding 中提取危险调用和位置证据。
- 合并候选并稳定排序。
- 明确记录无法推荐的原因和下一步需要的证据。

## 置信度语义

置信度不是装饰字段，必须来自证据质量。

第一版可以使用确定性规则计算置信度。排序依据应优先考虑：

1. 用户显式提供的 sink，并有代码位置或片段支持。
2. 同时被 diff 和 Semgrep 支持的候选。
3. 有明确函数签名、文件和行号的候选。
4. 只有自然语言描述支持的候选。
5. 没有证据锚点的假设。

置信度必须能够解释：

- 支持它的证据有哪些。
- 反对或冲突证据有哪些。
- 哪些 unknowns 阻止它升级。
- 下一步如何提升或降低置信度。

## 技术可行性路径

方法论按能力逐步落地：

### M1：sink generation

- 输入：`VulnerabilityInput`、漏洞描述、已知 sink、diff artifact、Semgrep finding。
- 输出：`SinkCandidate` 列表、推荐 candidate、evidence、confidence、unknowns。
- 验证：known sink、unknown with diff、unknown with Semgrep、insufficient evidence、malformed evidence fixture。

### M2：taint path 与 reachability

- 输入：sink candidate、source 线索、Semgrep taint trace、调用关系或框架入口。
- 输出：candidate path、reachable path、not reachable、unknown。
- 验证：小型 fixture 项目、sanitizer 反例、不可达入口、缺失 trace。

### M3：PoC

- 输入：reachable path、入口参数、运行方式、版本信息。
- 输出：最小触发输入、请求样例或脚本、预期效果、未运行原因。
- 验证：隔离环境、可重复命令、失败状态。

### M4：exp

- 输入：PoC、受影响版本、修复版本、运行环境。
- 输出：自动化验证脚本、日志、退出码、响应差异、最终判断。
- 验证：受影响版本触发，修复版本不触发；无法验证时输出 inconclusive。

## 安全边界

漏洞分析天然涉及敏感代码和潜在利用能力。默认边界如下：

- 不默认上传源码、漏洞数据、扫描结果或运行日志到外部服务。
- PoC 优先生成安全验证样例，避免破坏性 payload。
- exp 必须在隔离环境中执行。
- 受影响版本和修复版本应尽量成对验证。
- 无法运行验证时，必须说明缺失环境和未验证风险。

## Harness 要求

每个阶段都要有对应 harness：

- 输入 harness：YAML/JSON analysis input 和校验错误。
- adapter harness：minimal、realistic、malformed fixture。
- pipeline harness：候选生成、排序、证据链和失败模式测试。
- CLI harness：exit code、stdout、stderr。
- regression harness：发现过的问题必须沉淀为测试或 fixture。
- CI harness：`./scripts/check` 必须通过。

每个重要 pipeline 至少覆盖：

- positive：证据充分时输出候选或结论。
- negative：存在反证时不输出错误结论。
- insufficient：证据不足时输出 unknown 或无法推荐。
- malformed：输入结构错误时给出可理解错误。
- regression：曾经出错的真实或 realistic 样例。

Insight 中列出的失败模式，应转化为 fixture 或测试断言；无法自动化时，必须写明人工验证步骤。

## 参考依据

本方法论参考以下一手或官方材料：

- [Semgrep taint analysis documentation](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview)
- [CodeQL data flow analysis documentation](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
- [CodeQL flow labels and sanitizer modeling](https://codeql.github.com/docs/codeql-language-guides/using-flow-labels-for-precise-data-flow-analysis/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)

这些材料提供的是分析和验证思路，不直接决定本项目实现。本项目仍以本仓库的数据模型、fixture、Insight、ADR 和 `./scripts/check` 作为工程事实来源。

## 与其他文档的关系

- `docs/product.md` 定义项目要解决什么问题。
- `docs/methodology.md` 定义如何分析和形成结论。
- `docs/architecture.md` 定义当前系统结构和数据流。
- `docs/roadmap.md` 定义阶段计划和下一步。
- `docs/development.md` 定义开发过程如何执行。
- `docs/Insight/` 记录关键决策如何形成。
- `docs/decisions/` 记录最终决策。
