# 架构

本文档记录 `semgrep-llm-vul` 的当前架构状态和预期架构方向。

## 当前状态

仓库已经完成 M0 基础 harness，并具备语言无关数据模型、分析任务输入模型、Semgrep finding 归一化、Semgrep taint-mode trace 到候选 `TaintPath` 的最小归一化能力、M1 最小 sink generation pipeline，以及 M2 最小 taint path generation 入口。

## 当前数据流

```text
Semgrep JSON
  ↓
NormalizedFinding
  ↓
如果存在可识别 dataflow_trace
  ↓
TaintPath(reachable=None)
```

`TaintPath` 表示静态分析报告的候选路径，不代表最终可触达或可利用结论。

trace 缺失或结构不完整时，不强行生成 `TaintPath`；原始 finding 仍保留为 `NormalizedFinding`。

分析任务入口：

```text
YAML / JSON analysis input
  ↓
VulnerabilityInput
  ↓
sink 生成 / 污点路径分析 / PoC / exp
```

YAML 面向人工编写，JSON 面向机器生成；两者共享同一内部模型。

M1 sink 函数生成采用证据优先 pipeline：

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

第一版 sink generation pipeline 保持本地、确定性、可测试，不调用真实 LLM provider，不联网拉取真实 GitHub repo，不实现完整 diff parser。Semgrep finding、diff artifact、用户输入和漏洞描述都只能作为候选证据来源，不能直接等同于漏洞确认结论。

sink candidate extraction 将逐步使用本地内置 sink heuristic pack 组织规则。规则 pack 只负责把调用表达式映射为候选危险行为类别，并为证据链提供规则名、类别和说明；它不负责动态加载外部规则，也不把候选直接升级为可触达、可触发或已验证结论。

当前实现入口：

- `semgrep_llm_vul.sink_generation.generate_sink_report`
- 输出模型：`SinkGenerationReport`
- 输入证据：`VulnerabilityInput`、可选 `NormalizedFinding`、本地 diff artifact 和漏洞代码片段
- CLI：`uv run semgrep-llm-vul generate-sinks <analysis-input>`
- JSON 序列化：`semgrep_llm_vul.reporting.sink_generation_report_to_dict`

M2 第一版 taint path generation 只做候选路径对齐：

```text
VulnerabilityInput
  + SinkGenerationReport
  + Semgrep-derived TaintPath(reachable=None)
  ↓
TaintPathGenerationReport
```

当前实现入口：

- `semgrep_llm_vul.taint_path_generation.generate_taint_path_report`
- 输出模型：`TaintPathGenerationReport`
- 输入证据：`VulnerabilityInput`、`SinkGenerationReport`、已归一化的 Semgrep `TaintPath`
- CLI：`uv run semgrep-llm-vul generate-taint-paths <analysis-input> --semgrep-json <semgrep.json>`
- JSON 序列化：`semgrep_llm_vul.reporting.taint_path_generation_report_to_dict`
- 语义边界：只保留能与 sink candidate 对齐的路径；`reachable` 保持 `None`；不做调用图、入口可达性、sanitizer 充分性或可利用确认。

M2 第一版 reachability 采用本地可触达证据模型：

```text
TaintPath(reachable=None)
  + entrypoint evidence
  + call chain evidence
  + source control evidence
  + blocking factors
  ↓
ReachabilityAssessment(reachable=true|false|null)
```

第一版 reachability 只表示静态可触达性，不表示 PoC 可触发或漏洞已验证。

- `reachable=true`：存在本地静态证据支持入口到候选路径上下文可达。
- `reachable=false`：存在明确阻断证据；不能因为缺入口模型就输出 false。
- `reachable=null`：候选路径存在，但入口、调用链、source 可控性、sanitizer/guard 或版本证据不足。

预期 assessment 字段包括候选 `TaintPath` 引用、入口证据、调用链或近似链、source 可控性、blocking factors、evidence 和 unknowns。

当前实现入口：

- `semgrep_llm_vul.reachability.generate_reachability_report`
- `semgrep_llm_vul.reachability.discover_flask_route_evidence`
- 输出模型：`ReachabilityReport`
- 输入证据：`VulnerabilityInput`、`TaintPathGenerationReport`、本地 reachability evidence JSON、可选本地 source root
- CLI：`uv run semgrep-llm-vul confirm-reachability <analysis-input> --semgrep-json <semgrep.json> --reachability-json <reachability.json>`
- 本地入口提取：`uv run semgrep-llm-vul confirm-reachability <analysis-input> --semgrep-json <semgrep.json> --source-root <source-root>`
- JSON 序列化：`semgrep_llm_vul.reporting.reachability_report_to_dict`
- 语义边界：只消费本地结构化证据或最小 Flask route 源码入口；当前源码入口模型支持 handler 本体内 sink、同文件 direct helper call chain、direct import 的跨文件一层 helper call chain，以及 module alias attribute call 形式的一层 helper call chain；不扫描真实 repo；不构建完整跨语言调用图；不做 PoC/exp 验证。

## 预期方向

项目预计围绕以下能力展开：

- Semgrep 扫描输入
- 漏洞 finding 归一化
- Semgrep taint-mode 候选路径归一化
- LLM 辅助分析工作流
- 便于人工审查的输出
- 用于可重复验证的测试和 fixtures

## 待决策事项

- 支持哪些输出格式
- LLM provider 集成策略
- 仅本地运行还是服务化运行
- 源码片段的安全与隐私策略

已确认的重要决策记录在 `docs/decisions/`。
