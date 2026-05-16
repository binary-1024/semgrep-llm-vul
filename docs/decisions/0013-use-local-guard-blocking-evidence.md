# ADR 0013：使用最小本地 guard/blocking evidence 支撑 M2 的 `reachable=false`

## 状态

Accepted

## 背景

M2 当前已经能从本地源码中提取 Flask 入口、局部 helper chain 和 source controllability 证据，但
`reachable=false` 仍主要依赖手写 reachability JSON。随着入口模型逐步补齐，下一步更值得优先解决的，是让明确阻断证据也能从本地源码中生成。

## 决策

项目在当前阶段引入最小本地 guard/blocking evidence：

- 目标：为 `reachable=false` 提供本地、确定性、可回归的源码证据来源。
- 第一版边界：只支持 Flask handler-local、与当前 open redirect 语义直接对应的显式 guard 模式。
- 输出方式：继续复用 `blocking_factors`，不新增新的阶段结论类型。
- 默认保守：无法明确确认的 guard/sanitizer 继续保持 `reachable=null`。

## 后果

正面影响：

- `reachable=false` 不再只能依赖手写 JSON。
- M2 的 `true / false / null` 三态更接近源码闭环。
- 后续可以逐步扩展更多 guard pattern，同时保持 harness 驱动。

代价与约束：

- 第一版覆盖范围很窄，不是通用 sanitizer 引擎。
- 需要接受大量场景继续保持 `null`。
- 任何超出当前模式的 guard/sanitizer 都不能被强行升级为 false。

## 不采用的方案

- 继续只扩入口模型，不补本地 blocked 证据。
- 一步到位支持泛化的条件约束/跨函数 sanitizer 分析。
- 让 LLM 直接参与 `reachable=false` 判定。

## 关联 Insight

- [为 M2 引入最小本地 guard/blocking evidence](../Insight/20260516-m2-local-guard-blocking-evidence.md)
