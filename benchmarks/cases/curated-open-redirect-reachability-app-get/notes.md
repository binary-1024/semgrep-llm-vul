# curated-open-redirect-reachability-app-get

## 背景

这是项目自建的最小 M2 reachability case，用于验证当 Flask 入口使用 method-specific route
decorator，例如 `@app.get(...)` 时，系统仍能从本地源码中提取入口证据并输出
`reachable=true`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-app-get-trace.json`
- Source root fixture：`fixtures/reachability/flask-get-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望入口证据：`@app.get("/login")`

## 当前已知失败模式

- 如果入口提取仍然只接受 `@*.route(...)`，这个 case 会错误退回 `reachable=null`。
- 如果 method-specific decorator 被误当成 `POST`/`PUT` 等其他 method，会污染入口语义。
- 如果后续把更一般的动态 decorator alias 一起放开，这个 case 可能掩盖边界外能力，需要额外负例约束。

## 后续升级

后续可以扩展 `@app.post(...)`、`@bp.get(...)` 或更多 method-specific decorators；当前 case
只覆盖最小 `GET` 正例。
