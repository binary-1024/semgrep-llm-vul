# Decision: 将 Semgrep taint-mode 结果归一化为候选路径证据

## 背景

项目已经建立语言无关核心模型，并实现了 Semgrep JSON finding 到 `NormalizedFinding` 的最小归一化。

后续污点路径生成需要消费 Semgrep taint-mode 结果。但 Semgrep 输出可能因为版本、配置、CE/Pro 能力和输出格式不同而存在差异；同时 Semgrep 官方说明 taint finding 可能只报告一条代表 trace，而不是所有可能路径。

## 决策

采用“双层归一化”：

1. Semgrep 原始结果先归一化为 `NormalizedFinding`。
2. 如果 finding 中存在可识别 taint trace，则进一步派生为内部 `TaintPath`。
3. 如果 trace 缺失或不完整，仍保留为 `NormalizedFinding`，并在 evidence 中说明“仅有 finding，无完整 trace”。
4. `TaintPath.reachable` 默认保持 `None`，表示尚未完成可触达确认。
5. 所有 Semgrep 派生路径都必须保留 raw metadata 或 raw trace 摘要，作为后续复核依据。

## 影响

- Semgrep adapter 只负责解析和归一化，不负责判断漏洞是否真实可利用。
- `TaintPath` 表示 Semgrep 报告的候选路径，不表示最终漏洞结论。
- 可触达确认、PoC 生成和 exp 验证仍属于后续阶段。
- 后续测试必须覆盖有 trace、无 trace、畸形 trace 三类输入。

## 备选方案

- 直接把 Semgrep JSON 暴露给 agent：不采用，因为后续 agent 难以稳定消费，也不利于接入其他分析器。
- 强制所有 Semgrep finding 都转换成 `TaintPath`：不采用，因为 trace 可能缺失或不完整，会制造虚假的路径确定性。
- 只保留 `NormalizedFinding`，暂不建模 taint path：不采用，因为项目下一阶段要围绕污点路径生成推进，需要最小路径抽象。

## 验证方式

下一步实现时添加：

- `fixtures/semgrep/taint-result-with-trace.json`
- `fixtures/semgrep/taint-result-without-trace.json`
- `tests/test_semgrep_taint.py`

并确保：

- `./scripts/check` 通过。
- 有 trace 的 finding 能生成 `TaintPath`。
- 无 trace 的 finding 不生成误导性的完整路径。
- 所有派生路径都带 evidence 和未确认项。
