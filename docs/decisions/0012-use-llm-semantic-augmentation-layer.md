# Decision: 使用证据约束的 LLM 语义增强层，而不是替代规则层

## 背景

项目在 source/sink/sanitizer 建模上会持续遇到知识覆盖率问题：长尾库、版本差异、自定义 wrapper、
跨生态 API 和项目局部惯用法都很难完全依靠手写规则维护。与此同时，直接让 LLM 替代规则层又会引入
不可重复、不可审计和 sanitizer 误判风险。

因此需要确定：LLM 在项目里的正确位置是什么。

## 决策

项目采用“证据约束的 LLM 语义增强层”原则：

- LLM 不替代程序分析骨架，也不替代确定性 source/sink/sanitizer 规则。
- LLM 可以辅助判断 unfamiliar API、长尾库和 wrapper 的语义，但输出必须是结构化候选判断。
- LLM 输出必须绑定证据、适用版本、前提条件、unknowns 和失败模式，不能只给自由文本结论。
- 对 sanitizer 的判断保持最保守策略：LLM 不能单独给出最终 safe 结论，只能给出 `candidate_sanitizer` 或 `unknown`。
- 当前 M1/M2 阶段先建设方法论、schema 和 benchmark，不将在线 LLM/MCP 直接接入主执行链。

## 影响

- 项目未来可以系统性扩展对 unfamiliar library API 的语义覆盖。
- 主流程仍然保持本地、确定性、可验证的基线，不会被模型输出直接污染。
- 后续若实现该能力，必须同步建设结构化 report、schema 测试和 benchmark/fixture。
- sanitizer 建模会继续保持保守，优先防止危险的 false negative。

## 备选方案

- 继续只依赖纯规则：不采用，因为知识覆盖扩展太慢。
- 让 LLM 直接替代规则层：不采用，因为不可复现且安全风险过高。
- 立即把在线 LLM/MCP 接入当前 M1/M2 主流程：不采用，因为缺少足够的 harness 约束。

## 验证方式

- 方法论文档是否明确了 LLM 语义增强层的职责和边界。
- benchmark 是否覆盖 unfamiliar API、sanitizer false-positive、版本漂移和 unknown 降级场景。
- 未来实现时，结构化输出是否能通过 schema、snapshot 和 benchmark 回归。

## 关联 Insight

- [将 LLM 用作 source/sink/sanitizer 的证据约束语义增强层](../Insight/20260430-llm-semantic-augmentation.md)
