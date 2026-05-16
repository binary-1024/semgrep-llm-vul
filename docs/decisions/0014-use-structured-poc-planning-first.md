# ADR 0014：M3 第一版先使用结构化 PoC planning/report

## 状态

Accepted

## 背景

M2 第一版已经形成最小闭环，能够输出带本地源码证据的 `reachable=true|false|null` 三态。主线下一步进入 M3：PoC 生成。

当前关键问题不是“能不能直接生成一个脚本”，而是“如何在不破坏证据语义和安全边界的前提下，把已确认可触达路径推进成可验证的下一阶段输入”。

## 决策

项目在 M3 第一版采用结构化、证据承载的 PoC planning/report，而不是直接进入可执行 payload 或 exploit 脚本生成。

具体约束：

- 只消费 `reachable=true` 的路径进入 M3。
- `reachable=false` 与 `reachable=null` 保留为证据，不进入 PoC 执行语义。
- 默认执行状态为 `not_run`，不得冒充 `verified`。
- PoC report 必须是结构化 contract，而不是自由文本；至少包含入口、最小触发输入、请求形态、预期效果、前提条件、evidence、unknowns 和 limitations。
- 第一版优先支持已被当前 M2 source-root fixtures 稳定覆盖的本地 Flask open redirect 场景。

## 后果

正面影响：

- M3 可以在不引入真实执行环境的前提下形成最小闭环。
- 现有 benchmark/case harness、CLI 和报告契约测试可以直接复用。
- M3 与 M4 之间的阶段边界更清楚：M3 负责 planning，M4 再负责执行验证与 exp。

代价与约束：

- 第一版只证明“知道如何触发”，不证明“已经触发成功”。
- 大量环境依赖、鉴权依赖或副作用相关的问题会被显式保留到 M4。
- 当前支持范围需要保持窄，不能为了提高 PoC 产出率而放宽 M2 三态语义。

## 不采用的方案

- 直接生成可执行 payload/脚本。
- 只输出自由文本 PoC 描述，不定义结构化 report。
- 继续停留在 M2，不进入 M3。

## 关联 Insight

- [为 M3 引入最小结构化 PoC planning 闭环](../Insight/20260516-m3-minimal-poc-planning.md)
