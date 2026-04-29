# curated-open-redirect-reachability-import-alias-helper

## 背景

这是项目自建的最小 M2 reachability import alias helper case，用于验证 candidate taint path
可以被本地 Flask route 入口证据升级为 `reachable=true`，即使 route handler 通过
`import app.helpers as helpers` 的 module alias 调用 helper 函数。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-import-alias-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-import-alias-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 route 入口提取只解析 `issue_redirect(...)` 这种直接名字调用，module alias attribute
  call 会错误退回 `reachable=null`。
- 如果 `import app.helpers as helpers` 没有被解析为 module import，call chain 会丢失跨文件上下文。

## 后续升级

后续可以扩展为 `from app import helpers`、更深层 attribute call 或 alias + sanitizer 混合场景；
当前 case 只覆盖一层 module alias attribute call。
