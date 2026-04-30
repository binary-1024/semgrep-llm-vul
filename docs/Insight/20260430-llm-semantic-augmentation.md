# Insight: LLM 是否应辅助判断 source/sink/sanitizer

## 元信息

- 日期：2026-04-30
- 状态：Accepted
- 关联任务：LLM 语义增益边界研究
- 关联 ADR：待定
- 决策类型：分析策略 | 证据链 | 安全边界

## 研究结论

### 主张

在 `semgrep-llm-vul` 里，**应该让 LLM（可带 Context7/文档检索）辅助判断 source/sink/sanitizer，但只能作为“语义增益层”和“待验证假设生成器”，不能替代手写规则、程序分析和本地证据链**。

更具体地说：

- `sink`：可以让 LLM 辅助补充候选类别、框架语义、排序理由和缺失证据清单。
- `source`：可以让 LLM 辅助补充“哪些输入点通常是 user-controlled”的框架知识，但最终仍要落回代码位置、AST、调用链或 trace 证据。
- `sanitizer`：**最保守**。LLM 可以提示“疑似 sanitizer / guard / validation pattern”，但不应直接判定“有效 sanitizer 成立”。

### 适用前提

- 已经有本地结构化证据作为锚点，例如：
  - `NormalizedFinding`
  - `TaintPath`
  - diff/snippet
  - 本地 AST / reachability evidence
- LLM 输出必须绑定输入证据、文档片段或框架 API 说明，不能裸给结论。
- LLM 输出默认是 `candidate`、`hint`、`unknowns` 或 `next checks`，不是 final verdict。

### 预期收益

1. 解决的知识覆盖局限

- 手写规则对**长尾框架语义**覆盖差，例如某个库的 redirect helper、template render、deserializer、ORM raw query、command wrapper。
- 规则对**跨语言/跨框架同义表达**覆盖差，例如“危险行为相同，但 API 名字完全不同”。
- 程序分析工具通常告诉我们“这里有 path / finding”，但不擅长解释：
  - 这个调用在框架里通常扮演什么角色
  - 这个 patch 为什么像是在补某类 sanitizer
  - 某个 helper 更像 source/sink/validator 还是普通业务函数
- Context7/文档检索能补的，不是“执行真相”，而是**API 语义背景和行业常识覆盖**。

2. 对当前项目的直接价值

- M1：比纯 heuristic 更容易覆盖长尾 sink 候选，但又不需要立刻把所有框架知识写死进规则包。
- M2：比纯字符串/局部模式更容易补 source/sanitizer 的语义解释，但仍把最终判断留给本地证据。

### 失败模式

1. 为什么不能直接替代规则和程序分析

- LLM 擅长语义归纳，不擅长保证**位置精确性、路径精确性、负结论精确性**。
- 它无法稳定替代：
  - AST / call chain / taint trace 的结构化定位
  - `reachable=true|false|null` 的保守状态机
  - benchmark / fixture / regression 的确定性回归
- 如果直接让 LLM 判 source/sink/sanitizer，最容易出现：
  - 结论可读，但没有代码锚点
  - 同一输入重复运行结论飘动
  - 把“像是”误写成“就是”

2. sanitizer 判断为什么尤其危险

- `sanitizer` 不是“名字像 safe/validate/escape”就成立。
- 它高度依赖：
  - 漏洞类型
  - 调用位置
  - 输入输出编码域
  - 是否覆盖所有攻击面
  - 版本与配置
- 同一个函数在不同上下文里，可能是：
  - 有效 sanitizer
  - 不充分 sanitizer
  - 只做格式化而不做安全约束
  - 仅对部分 sink 有效
- 因此 LLM 在 sanitizer 上最容易犯的错是：
  - **名称欺骗**：`safe_redirect`、`sanitize_url`、`escape` 看起来安全，但语义可能不够
  - **过度概括**：文档说“validates input”，就被误提升为“阻断漏洞”
  - **忽略漏洞类型差异**：HTML escape 不等于 URL redirect validation，不等于 command injection sanitization

### 最小实验

当前 M1/M2 最合适的落点，不是“让 LLM 直接给结论”，而是做一个**离线、可回放、只产出建议不产出 verdict** 的最小实验：

1. M1 sink 实验

- 输入：现有 `VulnerabilityInput` + diff/snippet + `NormalizedFinding`
- 输出：`llm_hints`
  - 候选 sink 类别
  - 候选 API / helper 名称
  - 排序理由
  - 需要哪些本地证据才能升级
- 要求：最终 `SinkCandidate` 仍由现有规则/证据链生成；LLM 只影响补充候选和排序解释。

2. M2 source 实验

- 输入：现有 `TaintPath` + `source.location` + 局部源码片段
- 输出：`llm_hints`
  - 该 source 是否“看起来像 request-controlled”
  - 为什么
  - 还缺哪些 AST / framework 证据
- 要求：`source_control.controlled=true` 仍必须由本地 AST / 规则证据确认；LLM 只能把 case 从“无想法”推进到“待验证假设”。

3. M2 sanitizer 实验

- 输入：候选 sanitizer 调用点 + 上下文片段 + 文档检索片段
- 输出只允许：
  - `possible_sanitizer`
  - `possible_guard`
  - `insufficient_to_confirm`
- 要求：**禁止** LLM 直接输出“有效 sanitizer=true”作为结构化结论。

### kill criterion

满足以下任一条件，就不应继续加深这条路线，至少不应在当前阶段升级为主线能力：

- LLM 输出不能稳定绑定到本地证据、文档片段或代码位置。
- 两轮最小实验后，新增收益主要只是“解释更好听”，而不是带来新的可验证候选。
- 它显著增加 review 成本，却不能转化为 fixture、benchmark 或 deterministic 规则。
- sanitizer 实验中，LLM 经常把“疑似有效”说成“已阻断”，且无法用简单 guardrail 压住。
- 主实现开始依赖 LLM 才能通过当前 M1/M2 case，这说明它已经越过“增益层”边界。

## 对当前阶段的落点建议

- **M1**：最适合先落在 `sink hint / ranking rationale / missing-evidence hints`。
- **M2 source**：适合落在 `source_control` 的补充解释与待验证假设生成。
- **M2 sanitizer**：只适合做 `possible_sanitizer` 标注和“下一步该检查什么”，**不适合**直接进入 `blocking_factors` 或把 path 降成 `reachable=false`。

一句话收敛：

> 在 `semgrep-llm-vul` 当前 M1/M2 阶段，LLM 最合适的角色是“帮助我们更快知道该查什么、补什么、怀疑什么”，而不是“替我们宣布 source/sink/sanitizer 已经成立”。
