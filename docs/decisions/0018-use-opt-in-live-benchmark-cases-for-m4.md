# ADR 0018：M4.3 使用 opt-in live benchmark cases

## 状态

Accepted

## 背景

M4.2 已经支持受控 managed fixture runtime，但当前它主要服务 pytest/live harness。主线下一步要补的是“把真实 loopback 执行沉淀成少量可复用 case”，而不是让默认 benchmark suite 直接变成会主动起服务的执行器。

## 决策

项目在 M4.3 引入 **opt-in live benchmark cases**，并把它们放到单独的 `benchmarks/live-cases/` root。

第一版约束：

- 默认 `benchmarks/cases/`、`./scripts/benchmark`、`./scripts/benchmark-summary` 行为保持不变。
- `evaluate-case` / `evaluate-cases` 继续支持显式评估任意 root，因此可以单独运行 `benchmarks/live-cases/`。
- M4 case evaluator 允许使用 `inputs.managed_fixture` 作为 `execution_json` 的替代输入。
- 当前唯一允许的 managed fixture 仍是 `open_redirect_pair`。
- live case 必须显式声明 `safety.requires_isolation=true`。

## 后果

正面影响：

- managed fixture runtime 成为 pytest 之外的第二个消费者。
- M4 的真实执行闭环被沉淀成独立 case 资产，而不仅是测试辅助逻辑。
- 默认 benchmark suite 继续保持离线、确定性和稳定。

代价与约束：

- 现在会出现第二个 case root，需要在文档和脚本里明确区分默认 suite 与 opt-in live suite。
- live case 当前只覆盖极少数仓库内置 fixture，通用性很低。
- `benchmark-summary` / baseline 当前仍只覆盖默认 `benchmarks/cases/`。

## 不采用的方案

- 在默认 `benchmarks/cases/` 中混入 live case 并通过 flag/skip 控制。
- 继续只在 pytest 中验证 managed fixture runtime。
- 暴露任意 startup CLI、脚本路径或服务描述。

## 关联 Insight

- [为 M4.3 引入 opt-in live benchmark cases](../Insight/20260517-m4-opt-in-live-cases.md)
