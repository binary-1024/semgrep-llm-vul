# curated-open-redirect-reachability-blocked

## 背景

这是项目自建的最小 M2 reachability blocked case，用于验证 candidate taint path 只有在存在明确阻断证据时才能被标记为 `reachable=false`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-trace.json`
- Reachability fixture：`fixtures/reachability/open-redirect-blocked.json`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望阻断因素：`unregistered_handler`

## 当前已知失败模式

- 如果 evaluator 因缺少入口证据直接输出 `false`，会把未知误判为不可达。
- 如果 `reachable=false` 没有 blocking factor，PoC 生成阶段会消费弱证据。
- 如果 taint path candidate 自身被改写为 reachable，会破坏 candidate 与 reachability assessment 的阶段边界。

## 后续升级

后续可以把阻断证据从手写 JSON 升级为本地 fixture 源码中的路由清单或框架入口扫描结果。
