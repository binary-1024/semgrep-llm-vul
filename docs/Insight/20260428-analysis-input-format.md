# Insight: 分析任务输入格式

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：分析任务输入文件格式设计
- 关联 ADR：`docs/decisions/0005-use-yaml-json-analysis-input.md`
- 决策类型：数据模型 | 分析策略 | 工程流程

## 背景

项目已经具备语言无关核心模型、Semgrep finding 归一化、Semgrep taint trace 候选路径归一化，以及 Semgrep fixture 生成 harness。

下一步需要定义用户如何提交一次漏洞分析任务。这个输入格式将成为 sink 生成、污点路径分析、PoC 生成和 exp 验证的统一入口。

当前 Python 模型已经有 `VulnerabilityInput`、`AnalysisTarget`、`FunctionSignature` 等结构，但还没有文件格式、字段约定、校验规则和示例。

## 决策问题

分析任务输入文件应该采用什么格式，如何同时支持人工编写、自动生成、版本演进和证据链要求？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：分析任务输入必须完整表达目标仓库、版本、漏洞描述、已知或未知 sink 场景，以及后续分析所需的语言/框架线索。
- 最小必要能力：repo、affected version、fixed/introduction version、description、mode、optional sink signature、candidate PRs、artifacts。
- 不可牺牲约束：不能强制用户一开始就提供完整信息；缺失信息必须显式表达，而不是由工具静默猜测。
- 最大风险：输入格式过于偏向某种语言或某个工具，导致后续跨语言目标受限。

### 工程化专家

- 根本问题：输入格式要适合人写、版本控制、测试 fixture 和 CLI 消费。
- 最小必要能力：schema version、稳定字段名、清晰错误信息、示例文件、解析测试。
- 不可牺牲约束：格式必须可演进；解析器必须拒绝明显错误；不能让 YAML 的灵活性变成隐式类型混乱。
- 最大风险：一开始做太复杂的 schema，导致实现和用户心智成本过高。

### 漏洞安全专家

- 根本问题：输入里可能包含敏感漏洞描述、代码片段、私有 repo、token 或 exploit 信息，需要明确安全边界。
- 最小必要能力：支持标记敏感 artifact；避免把凭据写入任务文件；记录数据来源和未确认项。
- 不可牺牲约束：任务输入不能默认包含秘密；PoC/exp 阶段前必须保留安全边界字段。
- 最大风险：用户把完整 exploit 或凭据放入公开仓库任务文件。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：SAST/安全平台通常用 YAML 配置扫描目标和规则，用 JSON 作为机器交换格式，用 SARIF 作为结果交换格式。
- 备选方案：
  - 方案 A：只支持 JSON。
  - 方案 B：只支持 YAML。
  - 方案 C：YAML 作为人工入口，JSON 作为机器入口，两者映射到同一内部模型。
- 优点：方案 C 同时适合人写任务和自动化系统生成任务。
- 缺点和失败模式：需要维护两种解析入口；字段语义必须统一，避免 YAML/JSON 行为不一致。

### 工程化专家

- 业界常见做法：配置文件通常带 `schema_version`，示例放在 `examples/`，测试 fixture 放在 `fixtures/`，解析错误尽量指向字段路径。
- 备选方案：
  - 方案 A：直接让用户传命令行参数。
  - 方案 B：任务文件 + CLI。
  - 方案 C：任务文件 + Python API + 后续 CLI。
- 优点：方案 C 保留测试友好性，也给后续 agent/服务化入口留下空间。
- 缺点和失败模式：如果一开始 CLI 参数太多，会和任务文件重复；应先实现文件解析和模型校验。

### 漏洞安全专家

- 业界常见做法：安全任务文件通常只存引用和脱敏摘要，敏感数据通过本地文件、环境变量或安全 secret 管理。
- 备选方案：
  - 方案 A：允许任务文件内嵌所有代码和 PoC。
  - 方案 B：任务文件只引用 artifact 路径/URL。
  - 方案 C：允许短代码片段，但禁止凭据和大段真实敏感源码，敏感内容用本地 artifact 引用。
- 优点：方案 C 兼顾可用性和安全。
- 缺点和失败模式：需要文档明确哪些内容不应提交到公开仓库。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果只支持命令行参数，如何表达多个 PR、引入版本、sink 签名和证据来源？
- 需要验证的假设：当前 `VulnerabilityInput` dataclass 是否足够承载第一版任务文件；如果不够，应小幅增加 artifact/source reference，而不是重写模型。
- 当前最小可行决策：定义 `schema_version: 1` 的 YAML/JSON 输入格式，覆盖已知 sink 和未知 sink 两种场景。
- 验证 harness：至少两个 fixture：`known-sink.yaml` 和 `unknown-sink.yaml`，再加一个 invalid case。

### 工程化专家

- 对其他方案的质询：YAML 易读但类型宽松，如何避免 `yes/no`、日期、版本号被错误解析？
- 需要验证的假设：使用 `ruamel-yaml` 或 Semgrep 依赖链已有 YAML parser 是否足够；解析后必须做显式字段校验。
- 当前最小可行决策：输入支持 YAML 和 JSON，内部统一转为 dict，再构建 `VulnerabilityInput`；错误信息包含字段路径。
- 验证 harness：解析测试覆盖必填字段缺失、mode 非法、known_sink 缺少 sink_signature。

### 漏洞安全专家

- 对其他方案的质询：如果任务文件会被提交到公开仓库，如何避免泄露私有 repo、token 或 exploit 细节？
- 需要验证的假设：第一版任务文件只包含公开 repo URL、版本、描述、PR URL、短代码片段和本地 artifact 引用。
- 当前最小可行决策：任务文件支持 `artifacts`，但默认只记录路径/URL、kind、sensitive 标记，不直接要求内嵌内容。
- 验证 harness：文档和示例中明确不要提交凭据、私有 token、未脱敏真实漏洞数据。

## 最终决策

采用 `schema_version: 1` 的分析任务输入格式：

- 人工编写优先使用 YAML。
- 自动化或机器生成可以使用 JSON。
- YAML 和 JSON 映射到同一内部 `VulnerabilityInput` 模型。
- 第一版必须支持已知 sink 和未知 sink 两种模式。
- 输入文件只表达任务事实和引用，不表达最终分析结论。

第一版字段：

```yaml
schema_version: 1
mode: known_sink | unknown_sink
target:
  repo_url: https://github.com/example/app
  affected_version: v1.0.0
  fixed_version: v1.0.1
  introduced_version:
  pre_introduced_version:
  language:
description: |
  漏洞描述。
sink:
  signature: package.module.func(arg)
  name:
  receiver:
  parameters: []
  returns:
  location:
    path:
    start_line:
    start_col:
    end_line:
    end_col:
vulnerable_snippet: |
  可选短代码片段。
candidate_prs:
  - https://github.com/example/app/pull/123
artifacts:
  - kind: advisory
    uri: https://example.com/advisory
    sensitive: false
```

## 为什么现在这样做

后续 sink 生成、路径分析、PoC 和 exp 都需要稳定输入。如果继续只靠聊天描述或临时代码参数，后续 agent 和测试都没有统一入口。

先定义任务输入格式，可以让后续每个阶段都基于同一份可版本化输入运行。

## 不采用的方案

- 只支持 JSON：不采用。JSON 适合机器，但多行漏洞描述和人工编辑体验较差。
- 只支持 YAML：不采用。自动化系统和 API 对 JSON 更友好。
- 只使用 CLI 参数：不采用。复杂任务无法可靠表达版本、PR、sink、artifact 和安全边界。
- 第一版引入完整 JSON Schema：暂不采用。先用 Python 校验和测试锁定行为，等字段稳定后再生成 schema。

## 验证方式

下一步实现时添加：

- `examples/analysis/known-sink.yaml`
- `examples/analysis/unknown-sink.yaml`
- `fixtures/analysis/invalid-known-sink-missing-signature.yaml`
- `src/semgrep_llm_vul/analysis_input.py`
- `tests/test_analysis_input.py`

测试覆盖：

- YAML known sink 能解析成 `VulnerabilityInput`。
- YAML unknown sink 能解析成 `VulnerabilityInput`。
- JSON 输入能解析成相同内部模型。
- `known_sink` 缺少 sink signature 时失败。
- 缺少 `schema_version` 或版本不支持时失败。
- artifact 的 sensitive 标记能保留。

## 重新评估条件

以下情况需要重新评估：

- 输入字段开始明显膨胀，需要正式 JSON Schema。
- 任务输入需要支持多目标、多漏洞或批量分析。
- 项目服务化，需要 API contract。
- PoC/exp 阶段需要更严格的安全策略和 secret 管理。

## 后续动作

- [x] 同步新增 `docs/decisions/0005-use-yaml-json-analysis-input.md`
- [x] 实现分析任务输入解析器
- [x] 添加 YAML/JSON 示例和 invalid fixture
- [x] 增加解析测试
- [x] 更新 `docs/architecture.md` 和 `README.md`
