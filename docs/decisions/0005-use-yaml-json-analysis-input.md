# Decision: 使用 YAML/JSON 作为分析任务输入格式

## 背景

项目已经具备语言无关核心模型、Semgrep finding 归一化、Semgrep taint trace 候选路径归一化，以及 Semgrep fixture 生成 harness。

后续 sink 生成、污点路径分析、PoC 和 exp 都需要统一任务入口。仅依赖聊天描述或 CLI 参数，无法稳定表达目标仓库、版本、漏洞描述、sink 信息、候选 PR 和证据来源。

## 决策

采用 `schema_version: 1` 的分析任务输入格式：

- 人工编写优先使用 YAML。
- 自动化或机器生成可以使用 JSON。
- YAML 和 JSON 映射到同一内部 `VulnerabilityInput` 模型。
- 第一版支持 `known_sink` 和 `unknown_sink` 两种模式。
- 输入文件只表达任务事实和引用，不表达最终分析结论。

第一版核心字段：

- `schema_version`
- `mode`
- `target`
- `description`
- `sink`
- `vulnerable_snippet`
- `candidate_prs`
- `artifacts`

## 影响

- 后续分析任务可以版本化、测试化和复现。
- CLI、agent 和未来服务化入口可以共享同一输入模型。
- 用户可以先提供不完整信息，但缺失字段会被显式记录或校验。
- 安全敏感内容应通过 artifact 引用和 `sensitive` 标记管理，不应默认内嵌到公开任务文件。

## 备选方案

- 只支持 JSON：不采用，因为人工编写多行描述和代码片段体验较差。
- 只支持 YAML：不采用，因为自动化系统和 API 对 JSON 更友好。
- 只使用 CLI 参数：不采用，因为复杂漏洞分析任务无法可靠表达。
- 第一版引入完整 JSON Schema：暂不采用，先用 Python 校验和测试锁定行为。

## 验证方式

下一步实现时添加：

- `examples/analysis/known-sink.yaml`
- `examples/analysis/unknown-sink.yaml`
- `fixtures/analysis/invalid-known-sink-missing-signature.yaml`
- `src/semgrep_llm_vul/analysis_input.py`
- `tests/test_analysis_input.py`

并确保：

- YAML known sink 能解析成 `VulnerabilityInput`。
- YAML unknown sink 能解析成 `VulnerabilityInput`。
- JSON 输入能解析成相同内部模型。
- `known_sink` 缺少 sink signature 时失败。
- 缺少 `schema_version` 或版本不支持时失败。
- artifact 的 sensitive 标记能保留。
