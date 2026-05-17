# 架构

本文档记录 `semgrep-llm-vul` 的当前架构状态和预期架构方向。

## 当前状态

仓库已经完成 M0 基础 harness，并具备语言无关数据模型、分析任务输入模型、Semgrep finding 归一化、Semgrep taint-mode trace 到候选 `TaintPath` 的最小归一化能力、M1 最小 sink generation pipeline、M2 最小 taint path generation 与 reachability 入口、M3 最小结构化 PoC planning 入口、M4 最小结构化 exp verification 入口，以及用于未来 LLM 语义增强层的结构化 `SemanticHint` / `SemanticHintReport` contract。

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
- 语义边界：只消费本地结构化证据或最小 Flask route 源码入口；当前源码入口模型支持 `@*.route(...)` decorator route、Flask method-specific decorators（当前已回归 `@*.get(...)`）、Blueprint handler 与 `register_blueprint(..., url_prefix=...)` 的最小组合入口、模块级 `app.add_url_rule(...)` registration route、handler 本体内 sink、同文件 direct helper call chain、direct import 的跨文件一层 helper call chain、module alias attribute call 形式的一层 helper call chain、`from app import helpers` 与 `from app import helpers as h` 这类 `ImportFrom` module attribute call / alias call 形式的一层 helper call chain、最多两层 helper hop 的有界局部 helper chain，以及 handler-local 的最小相对路径 guard blocking evidence；source controllability 也已支持最小本地 AST 证据：当 `source.name` 只是局部变量时，可以根据 `source.location` 对应赋值语句确认它是否直接来自 `request.args/form/values/json` 等 Flask request 字段，并额外恢复 `request_field` / `request_key` 这类可供 M3 planning 消费的最小参数信息；普通 assignment alias（例如 `alias = h`）、更一般的动态 registration、未回归的 decorator alias、未注册 Blueprint、跨函数 guard/sanitizer 和跨语句传播仍不解析，遇到这类边界时保持 `reachable=null`；不扫描真实 repo；不构建完整跨语言调用图；不做 PoC/exp 验证。

M3 第一版采用结构化 PoC planning/report：

```text
ReachabilityAssessment(reachable=true)
  + entrypoint method/path
  + source control parameter evidence
  ↓
PocPlan(execution_state=not_run)
```

当前实现入口：

- `semgrep_llm_vul.poc_generation.generate_poc_report`
- 输出模型：`PocGenerationReport`
- 输入证据：`VulnerabilityInput`、`ReachabilityReport`
- CLI：`uv run semgrep-llm-vul generate-poc <analysis-input> --semgrep-json <semgrep.json> --source-root <source-root>`
- JSON 序列化：`semgrep_llm_vul.reporting.poc_generation_report_to_dict`
- 语义边界：第一版只消费 `reachable=true` 的路径，只支持安全验证型、默认 `execution_state=not_run` 的结构化 planning；当前优先覆盖 Flask open redirect 场景，可恢复入口 method/path、参数位置、参数键名、最小样例值、预期效果、前提条件、unknowns 和 limitations；`reachable=false` 与 `reachable=null` 只保留为证据，不进入 PoC 执行语义；不直接生成破坏性 payload，不声明 `verified`。

M4 第一版采用结构化 exp verification/report：

```text
PocPlan(execution_state=not_run)
  + exp request artifact
  + affected execution evidence
  + fixed execution evidence
  ↓
ExpVerificationReport(verdict=verified|not_verified|inconclusive)
```

当前实现入口：

- `semgrep_llm_vul.exp_verification.generate_exp_verification_report`
- `semgrep_llm_vul.exp_verification.collect_local_execution_records`
- `semgrep_llm_vul.exp_verification.collect_managed_fixture_execution_records`
- `semgrep_llm_vul.exp_verification.load_execution_evidence`
- `semgrep_llm_vul.managed_fixtures.managed_fixture_targets`
- 输出模型：`ExpVerificationReport`
- 输入证据：`VulnerabilityInput`、`PocGenerationReport`、本地 execution evidence JSON 或 loopback live HTTP 观察
- CLI：`uv run semgrep-llm-vul verify-exp <analysis-input> --semgrep-json <semgrep.json> --source-root <source-root> [--execution-json <execution.json> | --affected-base-url <base-url> --fixed-base-url <base-url>]`
- JSON 序列化：`semgrep_llm_vul.reporting.exp_verification_report_to_dict`
- 语义边界：第一版只消费 `PocPlan(execution_state=not_run)`；只支持 `http_request_replay` 这一类窄 runner；当前 effect observation 覆盖 Flask open redirect 的两类最小信号：header redirect（`30x + Location`）与 `meta refresh` body signature，可据此给出 `effect_observed`、`effect_not_observed` 或 `effect_unknown`；最终 verdict 只允许 `verified`、`not_verified`、`inconclusive`，并且 `verified` 必须要求 affected 观察到效果且 fixed 未观察到效果；当前支持三类 observation 来源：本地 execution evidence JSON、loopback live HTTP replay，以及仓库内置 managed fixture startup 驱动的 loopback live replay；managed fixture 当前作为内部 runtime 暴露给 pytest/live harness 和 opt-in live benchmark cases，不是公开 CLI startup 接口；live runner 只允许 `localhost` / `127.0.0.1` / `::1`，不自动启动真实项目服务，不跟随 redirect，不连接真实公网目标，不处理 secrets，不执行破坏性 payload；当前不支持通用 body diff、JS 执行或浏览器渲染。

## 预期方向

项目预计围绕以下能力展开：

- Semgrep 扫描输入
- 漏洞 finding 归一化
- Semgrep taint-mode 候选路径归一化
- 受证据约束的 LLM semantic hints
- LLM 辅助分析工作流
- 便于人工审查的输出
- 用于可重复验证的测试和 fixtures

## 待决策事项

- 支持哪些输出格式
- LLM provider 集成策略
- 仅本地运行还是服务化运行
- 源码片段的安全与隐私策略

已确认的重要决策记录在 `docs/decisions/`。
