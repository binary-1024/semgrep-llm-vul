# 决策记录

`docs/decisions/` 记录已经确定的最终决策，采用 ADR 风格，便于快速查阅“最后决定了什么”。

决策形成过程放在 `docs/Insight/`。需要理解“为什么这样决定”时，优先阅读对应 Insight。

## 索引

| 编号 | 决策 | 状态 | 关联 Insight | 影响范围 |
| --- | --- | --- | --- | --- |
| 0001 | [优先建立基础 Harness](0001-establish-foundation-harness.md) | Accepted | 无 | 项目基础工程 |
| 0002 | [使用 Python 3.10 与 uv 管理项目](0002-use-python-uv.md) | Accepted | 无 | 技术栈与依赖管理 |
| 0003 | [使用 Insight 记录关键决策过程](0003-use-insight-for-key-decisions.md) | Accepted | 无 | 决策流程 |
| 0004 | [将 Semgrep taint-mode 结果归一化为候选路径证据](0004-normalize-semgrep-taint-as-evidence.md) | Accepted | [Semgrep taint-mode 归一化](../Insight/20260427-semgrep-taint-normalization.md) | Semgrep adapter、taint path |
| 0005 | [使用 YAML/JSON 作为分析任务输入格式](0005-use-yaml-json-analysis-input.md) | Accepted | [分析任务输入格式](../Insight/20260428-analysis-input-format.md) | 分析任务入口 |
| 0006 | [使用证据优先的 sink generation pipeline](0006-use-evidence-first-sink-generation-pipeline.md) | Accepted | [sink 函数生成 pipeline](../Insight/20260428-sink-generation-pipeline.md) | M1 sink 生成 |
| 0007 | [使用可反驳的证据优先漏洞分析方法论](0007-use-falsifiable-evidence-first-methodology.md) | Accepted | [漏洞分析方法论基础](../Insight/20260428-methodology-foundation.md) | 全项目分析方法论 |
| 0008 | [使用本地内置 sink heuristic pack](0008-use-local-sink-heuristic-pack.md) | Accepted | [sink heuristic pack](../Insight/20260428-sink-heuristic-pack.md) | M1 sink 生成 |
| 0009 | [建立 benchmark 与 case harness](0009-use-benchmark-case-harness.md) | Accepted | [benchmark 与 case harness](../Insight/20260428-benchmark-case-harness.md) | 跨里程碑验证 |

## 使用方式

- 查最终结论：先读本目录中的 ADR。
- 查推理过程：再读关联的 `docs/Insight/`。
- 准备实现：确认相关 ADR 已合入 `main`，再开 `codex/feature-<topic>` 分支。
