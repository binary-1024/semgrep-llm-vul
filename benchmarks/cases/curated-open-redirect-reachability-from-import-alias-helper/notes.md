# curated-open-redirect-reachability-from-import-alias-helper

## 背景

这是项目自建的最小 M2 reachability from-import alias helper case，用于把当前已隐式支持的
`from app import helpers as h` 形式锁进 harness，验证 candidate taint path 可以被本地
Flask route 入口证据升级为 `reachable=true`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-from-import-alias-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-from-import-alias-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 `from app import helpers as h` 没有被解析为 module import alias，该 case 会错误退回 `reachable=null`。
- 如果 `h.issue_redirect(...)` 的 attribute owner 没有和 imported module alias 对齐，call chain 会丢失跨文件上下文。

## 后续升级

后续可以扩展为更复杂的 `from package import submodule as alias` 或更一般的 alias/assignment 场景；
当前 case 只覆盖一层 `ImportFrom` module alias + attribute call。
