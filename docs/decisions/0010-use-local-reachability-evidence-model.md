# Decision: 使用本地可触达证据模型

## 背景

M2 已经可以生成最小 taint path candidate，并通过 benchmark/case harness 回归。当前 `TaintPath.reachable` 仍保持 `None`，表示候选路径尚未完成可触达确认。

在进入 PoC 生成之前，项目需要明确 reachable 的语义和证据标准，避免把静态候选路径误当作可触发漏洞。

## 决策

M2 采用本地、确定性、证据优先的 reachability evidence model。第一版只确认静态可触达性，不确认 PoC 可触发性，不确认漏洞可利用性。

`reachable` 的语义：

- `true`：存在本地静态证据支持入口到候选路径上下文可达。
- `false`：存在明确阻断证据。第一版应谨慎输出 false。
- `null`：候选路径存在，但入口、调用链、source 可控性、sanitizer/guard 或版本证据不足。

第一版 assessment 至少表达：

- 候选 `TaintPath` 引用。
- `reachable` 状态。
- 入口证据。
- 入口到路径上下文的调用链或近似链。
- source 可控性判断。
- sanitizer、guard、版本差异等阻断因素。
- evidence 和 unknowns。

## 影响

- Semgrep taint trace 仍然只是候选路径证据，不自动升级为 reachable。
- M2 可以在不联网、不调用真实 LLM、不实现完整跨语言调用图的前提下继续推进。
- M3 PoC 生成必须优先消费 `reachable=true` 的路径；`reachable=null` 只能作为待确认候选。
- `reachable=false` 必须有明确阻断证据，不能仅因缺少入口模型而输出。

## 备选方案

- 直接把 Semgrep taint trace 当作 reachable：不采用，因为 trace 不证明入口可达或攻击者可控。
- 直接实现完整跨语言调用图：不采用，因为当前阶段成本高、语言绑定重、难以稳定验证。
- 只有动态运行成功才输出 reachable：不采用，因为动态触发确认属于 M3/M4。
- 缺少入口就输出 unreachable：不采用，因为缺证据应保持 `null`。

## 验证方式

后续实现时添加：

- M2 reachability report 单元测试。
- positive/unknown/blocked 三类 curated cases。
- benchmark/case harness 回归，确保 candidate path 不会被误升级。
- `./scripts/check` 通过。

## 关联 Insight

- [M2 可触达确认最小模型](../Insight/20260428-m2-reachability-model.md)
