# curated-open-redirect-exp-meta-refresh-verified

## 背景

这个 case 用来锁定 M4.4 新增的 body-signature observation：当 redirect 效果不出现在
`Location` header，而是出现在 response body 的 `meta refresh` 中时，系统仍应输出
`verified`。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect 的 `meta refresh` 差分 verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - `fixtures/execution/open-redirect-meta-refresh-verified.json`

## 验证重点

- M4 继续只消费 `PocPlan(execution_state=not_run)`。
- affected 的 body `meta refresh` 指向外部 URL。
- fixed 未在 body 中表达外跳效果。
- 最终 verdict 仍为 `verified`。
