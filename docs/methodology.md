# 方法论

本文档定义 `semgrep-llm-vul` 的漏洞分析方法论。它回答“我们如何从漏洞线索走到可验证结论”，不同于 `docs/development.md` 的工程开发流程。

## 核心立场

项目采用 evidence-first vulnerability analysis：

> 先收集可复核证据，再生成候选结论；先标记不确定性，再推进验证；任何 agent 推理都必须回到代码、diff、finding、日志或人工输入。

这意味着：

- LLM agent 负责辅助理解、归纳、排序和提出下一步假设。
- Semgrep、diff、代码片段、运行日志和人工输入负责提供证据锚点。
- 内部模型负责把证据、候选、置信度和未确认项结构化。
- harness 负责让每一步可测试、可复现、可回归。

## 分析对象

一次漏洞分析任务围绕以下对象展开：

- `VulnerabilityInput`：用户提交的任务事实，包括 repo、版本、漏洞描述、sink 信息、候选 PR 和 artifacts。
- `Evidence`：支持某个判断的证据，包括描述、代码位置、diff、Semgrep finding、运行日志等。
- `SinkCandidate`：候选或推荐 sink，不等同于最终漏洞确认。
- `TaintPath`：候选污点路径，不等同于可触达路径。
- PoC：用于证明触发条件的最小验证样例。
- exp：在隔离环境中自动验证受影响版本与修复版本行为差异的脚本。

## 分阶段结论

项目避免“一步到位”的漏洞结论，而是把结论分阶段推进：

```text
线索
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

- sink generation 阶段只输出候选或推荐 sink，不声明漏洞可利用。
- taint path 阶段只输出候选路径，不声明入口可触达。
- reachable path 阶段才声明路径可触达、不可达或未知。
- PoC 阶段说明触发方式和预期效果。
- exp 阶段通过执行日志、退出码、请求响应或行为差异给出最终判断。

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

LLM agent 不应直接产生不可追溯的最终结论。凡是 LLM 输出的候选，都必须能追溯到输入证据或明确标记为待验证假设。

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

优先级大致如下：

1. 用户显式提供的 sink，并有代码位置或片段支持。
2. 同时被 diff 和 Semgrep 支持的候选。
3. 有明确函数签名、文件和行号的候选。
4. 只有自然语言描述支持的候选。
5. 没有证据锚点的假设。

第一版实现可以使用简单、确定性的规则计算置信度；后续接入 LLM ranker 时，也必须解释排序依据。

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

Insight 中列出的失败模式，应转化为 fixture 或测试断言；无法自动化时，必须写明人工验证步骤。

## 与其他文档的关系

- `docs/product.md` 定义项目要解决什么问题。
- `docs/methodology.md` 定义如何分析和形成结论。
- `docs/architecture.md` 定义当前系统结构和数据流。
- `docs/roadmap.md` 定义阶段计划和下一步。
- `docs/development.md` 定义开发过程如何执行。
- `docs/Insight/` 记录关键决策如何形成。
- `docs/decisions/` 记录最终决策。
