# curated-open-redirect-exp-refresh-header-live-verified

## 背景

这个 live case 用来锁定 M4.5 的第三条真实执行闭环：`managed_fixture(open_redirect_refresh_header_pair)`
启动后，系统应能从真实 loopback 响应头中的 `Refresh` 恢复 open redirect 效果。

## 设计

- 类型：`curated_minimal`
- 阶段：`M4`
- 执行模式：opt-in live case
- 隔离：仅限仓库内置 managed fixture，不连接公网

## 输入

- analysis input：`examples/analysis/unknown-sink.yaml`
- semgrep trace：`fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
- source root：`fixtures/reachability/flask-source-control-local-var-app`
- live harness：
  - `managed_fixture=open_redirect_refresh_header_pair`

## 期望

- affected 的真实 loopback 响应头中包含外部 `Refresh`。
- fixed 不再返回外部 `Refresh`。
- 最终 verdict 为 `verified`。
