# 架构

本文档记录 `semgrep-llm-vul` 的当前架构状态和预期架构方向。

## 当前状态

仓库处于 Python/uv 基础工程阶段。当前已有语言无关数据模型、Semgrep finding 归一化，以及 Semgrep taint-mode trace 到候选 `TaintPath` 的最小归一化能力。

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

## 预期方向

项目预计围绕以下能力展开：

- Semgrep 扫描输入
- 漏洞 finding 归一化
- Semgrep taint-mode 候选路径归一化
- LLM 辅助分析工作流
- 便于人工审查的输出
- 用于可重复验证的测试和 fixtures

## 待决策事项

- 支持哪些输入格式
- 支持哪些输出格式
- LLM provider 集成策略
- 仅本地运行还是服务化运行
- 源码片段的安全与隐私策略

已确认的重要决策记录在 `docs/decisions/`。
