# curated-open-redirect-reachability-multi-layer-helper

## 背景

这是项目自建的最小 M2 reachability multi-layer helper case，用于验证 candidate taint path
可以被本地 Flask route 入口证据升级为 `reachable=true`，即使 sink 不在 route handler
本体中，而是在同文件的第二层 helper 函数里。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-multi-layer-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-multi-layer-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> prepare_redirect -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 route 入口提取只支持一层 helper，该 case 会错误退回 `reachable=null`。
- 如果多层 helper 证据没有进入 call chain，后续 PoC 会缺少 route 到 sink 的局部调用上下文。

## 后续升级

后续可以扩展为跨文件多层 helper 或 helper/sanitizer 混合场景；当前 case 只覆盖同文件、
两层 helper 的有界局部调用链。
