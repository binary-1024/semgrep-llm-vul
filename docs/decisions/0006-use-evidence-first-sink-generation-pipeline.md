# Decision: 使用证据优先的 sink generation pipeline

## 背景

项目已经具备基础 harness、分析任务输入模型、语言无关核心数据模型、Semgrep finding 归一化和 Semgrep taint-mode 候选路径归一化能力。

下一步进入 M1：sink 函数生成。该阶段需要支持已知 sink 和未知 sink 两种场景。sink 是后续污点路径、PoC 和 exp 的入口，如果 sink 候选缺乏证据链，后续分析会放大错误。

## 决策

M1 采用证据优先、多阶段的 sink generation pipeline：

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

第一版实现必须保持本地、确定性、可测试：

- 不调用真实 LLM provider。
- 不联网拉取真实 GitHub repo。
- 不实现完整 diff parser。
- 不进入污点路径、PoC 或 exp 阶段。

已知 sink 场景：

- 用户提供的 sink signature 作为高优先级候选。
- 漏洞片段、artifact、描述和可选 Semgrep finding 作为补充证据。
- 输出仍为 candidate，不直接标记为漏洞已确认。

未知 sink 场景：

- 从漏洞描述、候选 PR/diff artifact、Semgrep finding 和代码片段中提取候选。
- 候选必须有证据锚点。
- 证据不足时显式输出无法推荐的原因，不伪造高置信 sink。

候选排序原则：

- 用户显式提供的 sink 优先级最高。
- 同时被 diff 和 Semgrep 支持的候选优先级高于单一来源候选。
- 有明确代码位置和函数签名的候选优先级高于只有自然语言描述的候选。
- Semgrep finding 是候选证据，不是最终安全结论。

## 影响

- sink 生成结果可审查、可测试、可回归。
- 后续 LLM agent 可以作为 evidence summarizer 或 ranker 接入，但不能绕过证据链。
- 后续真实 GitHub repo 获取、PR diff 解析、多语言 AST 和调用图能力可以作为独立里程碑引入。
- M1 的输出可以稳定衔接 M2 污点路径生成。

## 备选方案

- LLM 直接生成 top-1 sink：不采用，因为不可复现、证据链弱、测试困难。
- 只支持已知 sink：不采用，因为无法覆盖未知 sink 的核心使用场景。
- 第一版实现完整 GitHub repo clone、PR diff 获取和多语言 AST：暂不采用，因为范围过大，应先稳定 pipeline schema。
- 把 Semgrep finding 等同于最终 sink：不采用，因为 Semgrep 输出只能作为候选证据。

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
