# curated-open-redirect-reachability

## 背景

这是项目自建的最小 M2 reachability case，用于验证 candidate taint path 可以被本地 reachability evidence 升级为 `reachable=true`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-trace.json`
- Source root fixture：`fixtures/reachability/flask-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`

## 当前已知失败模式

- 如果 evaluator 把 taint path candidate 自身改成 reachable，会破坏 M2 的阶段边界。
- 如果 Flask route 提取没有 entrypoint 和 call chain 就输出 `true`，会让 PoC 建立在弱证据上。

## 后续升级

后续可以增加 `reachable=false` 和 `reachable=null` 的 benchmark case；当前 case 只验证最小 positive reachability。
