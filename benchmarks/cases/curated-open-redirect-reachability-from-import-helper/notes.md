# curated-open-redirect-reachability-from-import-helper

## 背景

这是项目自建的最小 M2 reachability from-import helper case，用于验证 candidate taint path
可以被本地 Flask route 入口证据升级为 `reachable=true`，即使 route handler 通过
`from app import helpers` 的 module import 形式调用 `helpers.issue_redirect(...)`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-from-import-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-from-import-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 route 入口提取只解析 `import app.helpers as helpers` 这类 `Import` 形式，`from app import helpers`
  会错误退回 `reachable=null`。
- 如果 `from app import helpers` 没有被解析为 module import，attribute call 会丢失跨文件上下文。

## 后续升级

后续可以扩展为更复杂的 `from package import submodule as alias` 或多层 package 结构；当前
case 只覆盖一层 `ImportFrom` + module attribute call。
