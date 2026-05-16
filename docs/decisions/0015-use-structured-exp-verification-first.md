# ADR 0015：M4 第一版先使用结构化 exp verification/report

## 状态

Accepted

## 背景

M3 第一版已经形成最小闭环，能够输出带证据链的 `PocPlan(execution_state=not_run)`。主线下一步进入 M4：exp 验证与生成。

当前关键问题不是“能不能立刻跑一个更像 exploit 的脚本”，而是“如何在不破坏阶段语义和安全边界的前提下，把 M3 plan 推进成 affected/fixed 可对照的验证结论”。

## 决策

项目在 M4 第一版采用结构化、证据承载的 exp verification/report，而不是直接进入通用 exploit 生成与执行。

具体约束：

- 只消费 `PocPlan(execution_state=not_run)` 进入 M4。
- M4 report 必须把执行态、效果态和最终 verdict 分开：
  - `execution_state`：执行观察是否完成；
  - `effect_state`：预期效果是否被观察到；
  - `verification_verdict`：affected / fixed 对照后的 `verified`、`not_verified` 或 `inconclusive`。
- 第一版 runner 只支持窄类型 `http_request_replay`。
- 第一版观察规则只支持当前已被 M2/M3 稳定覆盖的 Flask open redirect 场景。
- 默认消费本地 execution evidence fixture，不连接真实公网目标，不处理 secrets，不执行破坏性 payload。

## 后果

正面影响：

- M4 可以在不引入真实在线执行平台的前提下形成最小闭环。
- 受影响版本 / 修复版本对照成为一等语义，`verified` 不再依赖单版本结果。
- 当前 benchmark/case harness、CLI 和报告契约测试可以继续复用和扩展。

代价与约束：

- 第一版不是通用 exp 平台，只支持很窄的 request replay 与 effect observation。
- 当前很多环境依赖、鉴权依赖和副作用治理问题仍然显式保留在边界外。
- 如果 `PocPlan` 不够具体，M4 结果会保守地停在 `inconclusive`。

## 不采用的方案

- 直接做通用 exploit 生成与执行。
- 只输出自由文本验证说明，不定义结构化 verification report。
- 继续停留在 M3，不进入 M4。

## 关联 Insight

- [为 M4 引入最小结构化 exp verification 闭环](../Insight/20260516-m4-structured-exp-verification.md)
