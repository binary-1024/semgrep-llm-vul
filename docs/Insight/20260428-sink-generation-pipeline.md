# Insight: sink 函数生成 pipeline

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：M1 sink 函数生成
- 关联 ADR：`docs/decisions/0006-use-evidence-first-sink-generation-pipeline.md`
- 决策类型：分析策略 | 数据模型 | 工程流程

## 背景

项目已经具备基础 harness、分析任务 YAML/JSON 输入格式、语言无关核心数据模型、Semgrep finding 归一化和 Semgrep taint-mode 候选路径归一化能力。

下一步进入 M1：sink 函数生成。该阶段需要支持两类场景：

- 已知 sink：用户提供 sink 函数完整签名和漏洞代码片段，系统需要确认、补证据和标准化输出。
- 未知 sink：用户只提供漏洞描述、目标 repo、受影响版本、修复版本或候选 PR，系统需要推断候选 sink。

如果此阶段直接依赖 LLM 根据描述自由生成 sink，结果很容易不可复现、证据链薄弱，也难以测试。因此需要先定义一个证据优先的 pipeline，再进入实现。

## 决策问题

M1 应如何从用户输入、修复 diff、Semgrep 结果和 LLM agent 推理中生成可审查、可测试、可复现的 sink candidate？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：sink 不是自然语言标签，而是代码中的危险操作、危险 API、危险分支或危险数据使用点，需要能落到文件、行号、函数或调用表达式。
- 最小必要能力：把输入线索转为候选代码位置，并保留位置证据、语义证据和来源证据。
- 不可牺牲约束：不能把 LLM 的解释当成事实；必须有代码、diff、Semgrep finding 或用户输入作为证据锚点。
- 最大风险：不同语言和框架对 sink 的表达不同，第一版如果过早绑定语言 AST，会拖慢语言无关目标。

### 工程化专家

- 根本问题：sink 生成需要可测试、可回归，而不是一次性人工分析报告。
- 最小必要能力：定义稳定的数据流、输入输出、错误状态和 fixture 分类，让后续实现可逐步替换内部策略。
- 不可牺牲约束：第一版不能依赖真实联网拉 repo、真实 LLM provider 或复杂服务环境，否则 harness 难以稳定。
- 最大风险：pipeline 边界不清，会把 repo 获取、diff 解析、LLM 调用、Semgrep 扫描和排序揉成一个不可测大函数。

### 漏洞安全专家

- 根本问题：sink 候选必须服务于漏洞验证，不是简单列出所有危险函数。
- 最小必要能力：区分“用户已提供的 sink”“修复 diff 暗示的 sink”“Semgrep 发现的危险调用”“LLM 推理出的候选”，并给出置信度和未确认点。
- 不可牺牲约束：不能输出没有证据链的最终 sink；不能把 candidate 直接标成 verified。
- 最大风险：错误 sink 会让后续 taint path、PoC 和 exp 全部偏离，越往后成本越高。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：SAST 工具通常从规则命中的 sink/source 出发，CodeQL、Semgrep taint-mode、Joern 等会把危险 API、规则 ID、数据流 trace 作为候选证据；漏洞研究也常从 patch diff 找安全检查、危险调用或行为变化。
- 备选方案：
  - A. 用户输入优先：已知 sink 直接标准化，未知 sink 暂不自动推断。
  - B. diff 优先：从修复 diff 中找删除、替换、新增校验附近的调用点和函数。
  - C. Semgrep 优先：先跑通用危险模式规则，从 finding 中找 sink。
  - D. LLM 优先：让 agent 阅读描述和代码后直接提出 sink。
- 优点：A 稳定但覆盖低；B 贴近真实修复证据；C 适合跨语言扫描；D 能处理自然语言和框架语义。
- 缺点和失败模式：A 无法覆盖未知 sink；B 依赖修复版本或 PR；C 规则覆盖有限且误报多；D 不可复现且容易幻觉。

### 工程化专家

- 业界常见做法：成熟系统通常把采集、解析、候选生成、排序和报告拆开，用统一 schema 串联；早期不会直接做全自动闭环，而是先做可审查候选。
- 备选方案：
  - A. 单阶段 pipeline：输入直接输出最终 sink。
  - B. 多阶段 pipeline：evidence collection -> candidate extraction -> candidate ranking -> report。
  - C. 插件式 pipeline：diff、Semgrep、LLM 都作为 provider 贡献候选。
- 优点：B 和 C 更容易测试、替换和扩展；每个 provider 可以有独立 fixture。
- 缺点和失败模式：多阶段需要更多模型和文档；插件化过早可能抽象过度。

### 漏洞安全专家

- 业界常见做法：漏洞 triage 常把 patch、commit message、CVE 描述、测试用例和 SAST 结果交叉验证；高置信结论通常要求至少一个代码证据和一个行为或修复证据。
- 备选方案：
  - A. 只输出 top-1 sink。
  - B. 输出候选列表，标记 confidence 和 evidence。
  - C. 输出候选列表，并明确 blocking questions 和 next analysis hints。
- 优点：B/C 保留不确定性，适合后续人工审查和 taint path 分析。
- 缺点和失败模式：候选过多会噪声大；置信度如果没有规则，会变成装饰字段。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果第一版不做真实 diff parser，未知 sink 如何落到代码位置？
- 需要验证的假设：即使不拉取真实 repo，也可以通过 fixture 中的漏洞描述、diff 片段、Semgrep finding 和代码片段验证 pipeline 结构。
- 当前最小可行决策：M1 第一版采用证据优先、多阶段 pipeline；输入可以先来自本地 fixture 和已解析 artifact，不直接负责 repo clone。
- 验证 harness：构造 known sink、unknown sink with diff、unknown sink with Semgrep finding、malformed evidence 四类 fixture。

### 工程化专家

- 对其他方案的质询：如果现在引入完整 provider 插件体系，会不会比实际需求更复杂？
- 需要验证的假设：可以先用简单函数和数据模型表达 provider 输出，等出现第二个真实 provider 后再抽象接口。
- 当前最小可行决策：先定义 `SinkCandidate` 的生成和排序语义，feature 分支实现本地、确定性的最小 pipeline。
- 验证 harness：不调用 LLM，不联网；用 fixture 输入驱动 deterministic 输出；CLI 或函数测试检查候选数量、排序、证据链和失败信息。

### 漏洞安全专家

- 对其他方案的质询：如果只做候选，不确认最终 sink，是否满足 M1？
- 需要验证的假设：M1 的目标是生成或确认 sink，其中“确认”应表示证据充分的推荐，不等于漏洞可利用确认。
- 当前最小可行决策：输出 `recommended` candidate，但保留 `status` 或 `confidence`，不使用 `verified` 这类容易和 exp 验证混淆的词。
- 验证 harness：每个推荐 sink 必须至少包含一种 evidence；未知 sink 若证据不足，应输出空候选或低置信候选及原因，不允许无证据推荐。

## 最终决策

M1 采用证据优先的 sink generation pipeline：

```text
VulnerabilityInput
  ↓
Evidence collection
  ↓
Sink candidate extraction
  ↓
Candidate ranking
  ↓
Sink generation report
```

第一版只做本地、确定性、可测试的最小 pipeline，不调用 LLM provider，不联网拉取真实 repo，不实现完整 diff parser。

两种输入场景分别处理：

- 已知 sink：把用户提供的 sink signature 作为高优先级候选，补充漏洞片段、artifact、描述和可选 Semgrep finding 作为证据。输出仍是 candidate，不直接标记为漏洞已确认。
- 未知 sink：从已提供的漏洞描述、候选 PR/diff artifact、Semgrep finding 和代码片段中提取候选。候选必须有证据锚点；证据不足时显式输出无法推荐的原因。

pipeline 职责边界：

- 用户输入：提供任务事实、已知 sink、描述、版本、artifact 引用。
- diff artifact：提供修复相关的代码变化证据，第一版可以使用结构化 fixture 或文本片段，不做完整 GitHub 拉取。
- Semgrep：提供规则命中的危险调用或 taint-mode finding，作为候选证据，不作为最终安全结论。
- LLM agent：M1 决策阶段只定义未来职责。第一版实现不接入真实 LLM，后续可作为 evidence summarizer 或 candidate ranker，但必须输出可追溯证据。
- 人工审查：用于确认候选是否进入后续 taint path 阶段。

候选排序原则：

1. 用户显式提供的 sink 优先级最高。
2. 同时被 diff 和 Semgrep 支持的候选优先级高于单一来源候选。
3. 有明确代码位置和函数签名的候选优先级高于只有自然语言描述的候选。
4. 证据不足时不强行输出高置信推荐。

## 为什么现在这样做

- sink 是后续污点路径、PoC 和 exp 的入口，错误 sink 会放大后续成本。
- 项目当前已经有 `VulnerabilityInput`、`SinkCandidate`、`Evidence` 和 `NormalizedFinding` 等基础模型，可以支撑最小 pipeline。
- 证据优先的设计更符合 harness 思想：每个判断都能回到 fixture、代码位置或 artifact。
- 不直接接入 LLM 和真实 GitHub repo，可以先把可测试边界打稳。

## 不采用的方案

- LLM 直接生成 top-1 sink：暂不采用。原因是不可复现、证据链弱、测试困难。
- 只支持已知 sink：暂不采用。原因是无法覆盖用户核心需求中的未知 sink 场景。
- 第一版实现完整 GitHub repo clone、PR diff 获取和多语言 AST：暂不采用。原因是范围过大，应在 pipeline schema 稳定后逐步引入。
- 把 Semgrep finding 等同于最终 sink：不采用。Semgrep 输出是候选证据，不是漏洞确认结论。

## 验证方式

下一步 feature 分支至少添加：

- known sink fixture：用户提供 sink signature，pipeline 输出高置信候选。
- unknown sink with diff fixture：从修复线索中输出候选。
- unknown sink with Semgrep fixture：从 `NormalizedFinding` 输出候选。
- insufficient evidence fixture：证据不足时不输出高置信推荐。
- malformed fixture：输入证据缺少必要字段时给出结构化错误。

测试断言至少覆盖：

- 候选必须携带 evidence。
- 推荐候选排序稳定。
- known sink 不需要 LLM 即可生成候选。
- Semgrep finding 只能作为候选证据。
- 未知 sink 证据不足时不会伪造推荐。
- `./scripts/check` 通过。

## 重新评估条件

以下情况出现时重新评估本决策：

- 接入真实 LLM provider。
- 接入真实 GitHub API 或自动 clone repo。
- 引入 CodeQL、Joern、SARIF 等新的程序分析工具。
- 需要跨语言 AST 或调用图能力。
- 后续 PoC/exp 阶段要求 sink 状态语义更精细。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [x] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
