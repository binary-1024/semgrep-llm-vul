# curated-open-redirect-reachability-cross-file-helper

## 背景

这是项目自建的最小 M2 reachability cross-file helper case，用于验证 candidate taint path
可以被本地 Flask route 入口证据升级为 `reachable=true`，即使 route handler 调用的 helper
函数定义在另一个 Python 文件中。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-cross-file-helper-trace.json`
- Source root fixture：`fixtures/reachability/flask-cross-file-helper-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望调用链：`login -> issue_redirect -> redirect(next_url)`

## 当前已知失败模式

- 如果 route 入口提取只能在 sink 所在文件里寻找 route，跨文件 helper case 会错误退回
  `reachable=null`。
- 如果 direct import 没有被解析到 helper 定义，call chain 会丢失跨文件上下文。

## 后续升级

后续可以扩展为多层 helper、跨文件 helper + sanitizer、module alias 调用或更通用的
import 解析；当前 case 只覆盖 direct import + 一层 helper。
