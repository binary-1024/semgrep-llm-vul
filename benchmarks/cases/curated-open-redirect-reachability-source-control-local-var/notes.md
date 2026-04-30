# curated-open-redirect-reachability-source-control-local-var

## 背景

这是项目自建的最小 M2 reachability case，用于验证当 Semgrep trace 的 `source.name` 只是本地变量
`next_url` 时，系统仍能通过 `source.location` 对应的本地 AST 赋值语句识别出它直接来自
`request.values.get("next")`，并把 source controllability 升级为可确认。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
- Source root fixture：`fixtures/reachability/flask-source-control-local-var-app`
- 期望 source：`next_url`
- 期望 sink：`redirect`
- 期望入口类型：`flask_route`
- 期望 source controllability：由 `source.location` 对应赋值语句的本地 AST 证据确认

## 当前已知失败模式

- 如果 source controllability 仍只依赖 `source.name` 是否包含 `request.`，该 case 会错误保留为
  `reachable=true` 但 `source_control.controlled=null`，或者直接把 source 可控性误报为不足。
- 如果 `source.location` 没有对齐到本地赋值语句，当前 AST 证据会退回 unknown。
- 如果后续错误扩展为跨语句传播或 assignment alias，该 case 可能掩盖边界外能力，需继续由负例约束。

## 后续升级

后续可以扩展为 wrapper helper、跨文件赋值、attribute owner 或更一般的传播场景；当前 case 只覆盖
“同语句、同文件、直接从 Flask request 读取”的最小正例。
