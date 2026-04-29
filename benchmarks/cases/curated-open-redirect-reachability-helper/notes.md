# curated-open-redirect-reachability-helper

## 背景

这是项目自建的最小 M2 reachability helper call chain case，用于验证 candidate taint path
可以被本地 Flask route 入口证据升级为 `reachable=true`，即使 sink 不在 route handler
本体中，而是在同文件 helper 函数里。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 route 入口提取只支持 “sink 在 handler 函数体内”，该 case 会错误退回 `reachable=null`。
- 如果 helper 调用证据没有进入 call chain，后续 PoC 会缺少 route 到 sink 的局部调用上下文。

## 后续升级

后续可以扩展为多层 helper、跨文件 helper 或 route 调用 sanitizer/helper 混合场景；当前
case 只覆盖同文件、一层 direct helper call chain。
