# curated-open-redirect-poc-plan-source-control-local-var

## 背景

这个 case 用来锁定 M3 第一版的核心能力：当 Semgrep taint source 只给出局部变量
`next_url` 时，系统仍能借助 M2 的本地 AST source control 证据，恢复最小 PoC planning 所需的参数键名和请求形态。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`

## 验证重点

- 只消费 `reachable=true` 的路径进入 M3。
- 从 `request.values.get("next")` 恢复 `parameter_name=next`。
- 生成结构化 PoC plan，执行状态保持 `not_run`。
- 明确保留 `request.values` 的 query/form 二义性。
