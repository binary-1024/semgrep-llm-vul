# Decision: 使用可反驳的证据优先漏洞分析方法论

## 背景

项目需要一套全面、缜密、可验证、理论上可行的方法论，支撑从漏洞线索到 sink、污点路径、PoC 和 exp 验证的完整链路。

已有 `docs/methodology.md` 提出了 evidence-first vulnerability analysis，但仍需要补足第一性原理、理论依据、行业实践和验证标准，使后续实现、测试和 review 能围绕同一套方法执行。

## 决策

项目采用 falsifiable evidence-first vulnerability analysis 方法论。

核心原则：

- 从第一性原理拆解漏洞：external control、entrypoint、source、propagation、sanitizer、sink、reachability、trigger effect。
- 用程序分析工具生成候选证据，不把 Semgrep、CodeQL、SARIF 等 finding 直接当成漏洞结论。
- 用 LLM agent 做语义理解、证据归纳和排序辅助，但不允许绕过证据链。
- 用分阶段结论控制语义：candidate、reachable、triggerable、verified。
- 用受影响版本与修复版本对照、PoC/exp 和日志证据完成最终验证。
- 用 harness 把每个失败模式转化为 fixture、测试断言或明确的人工验证步骤。

## 影响

- sink generation 阶段只能输出候选或推荐 sink，不声明漏洞可利用。
- taint path 阶段只能输出候选路径，不声明入口可触达。
- reachable path 阶段才声明路径可触达、不可达或 unknown。
- PoC 阶段说明触发条件和预期效果。
- exp 阶段通过隔离环境中的对照执行证据给出最终判断。
- LLM provider、GitHub API、真实 repo clone 和动态执行环境都必须作为可替换 provider 接入，不能破坏可验证 harness。

## 备选方案

- LLM-first 方法论：不采用，因为不可复现、难测试、容易过度自信。
- SAST-only 方法论：不采用，因为静态 finding 不能证明可触达或可利用。
- Exploit-first 方法论：不采用，因为安全风险高，也无法解释和回归中间分析过程。
- 一次性 final report 方法论：不采用，因为无法把失败模式沉淀到 harness。

## 验证方式

文档层面：

- `docs/methodology.md` 必须包含第一性原理、理论依据、技术可行性、行业洞察、可反驳验证标准和安全边界。
- `docs/methodology.md` 必须说明它与 product、architecture、roadmap、development、Insight、ADR 的关系。

实现层面：

- 每个里程碑都必须设计 positive、negative、insufficient、malformed 相关测试或 fixture。
- 输出结构必须显式保留 evidence、confidence、unknowns 和 reproduction。
- PoC/exp 阶段必须包含隔离环境、受影响版本与修复版本对照、日志或响应证据。
- `./scripts/check` 必须通过。

## 参考依据

- Semgrep taint-mode 使用 source、sink、sanitizer 等概念表达 taint tracking。
- CodeQL data flow 和 taint tracking 文档将路径查询、source、sink、sanitizer 建模为程序分析问题。
- OWASP WSTG 强调基于测试的安全验证。
- NIST SSDF 强调软件安全实践中的验证、可追踪和降低漏洞风险。
