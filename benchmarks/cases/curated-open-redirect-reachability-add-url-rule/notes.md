# curated-open-redirect-reachability-add-url-rule

## 背景

这是项目自建的最小 M2 reachability case，用于验证当 Flask 入口不是 `@app.route(...)`
装饰器，而是模块级 `app.add_url_rule(...)` 注册时，系统仍能从本地源码中提取入口证据并输出
`reachable=true`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-add-url-rule-trace.json`
- Source root fixture：`fixtures/reachability/flask-add-url-rule-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望入口证据：模块级 `app.add_url_rule("/login", view_func=login, methods=["GET"])`

## 当前已知失败模式

- 如果入口提取仍然只支持 `@*.route(...)` 装饰器，这个 case 会错误退回 `reachable=null`。
- 如果 `view_func` 不能解析到同文件局部函数，入口证据会缺失。
- 如果后续误把更一般的动态 registration 一起放开，这个 case 可能掩盖边界外能力，需要额外负例约束。

## 后续升级

后续可以扩展 `blueprint.add_url_rule(...)`、更复杂的 `endpoint` / `view_func` 变体或 wrapper
registration；当前 case 只覆盖“模块级、直接、局部函数引用”的最小正例。
