# curated-open-redirect-exp-meta-refresh-live-verified

## 背景

这个 live case 用来锁定 M4.4 的第二条真实执行闭环：`managed_fixture(open_redirect_meta_refresh_pair)`
启动后，系统应能从真实 loopback 响应 body 的 `meta refresh` 中恢复 open redirect 效果。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：project-curated / managed fixture
- 语义：Flask open redirect 的 body-signature live verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - `managed_fixture=open_redirect_meta_refresh_pair`

## 验证重点

- 继续只允许仓库内置 managed fixture。
- affected 的真实 loopback 响应 body 中包含外部 `meta refresh`。
- fixed 的真实 loopback 响应 body 不表达外跳效果。
- 最终 verdict 为 `verified`。
