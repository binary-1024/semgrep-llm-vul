# curated-open-redirect-exp-verified

## 背景

这个 case 用来锁定 M4 第一版最核心的正向闭环：当 M3 已经恢复出结构化 request artifact，且 affected / fixed 两边都提供了可比较的本地执行观察时，系统应输出 `verified`。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect 的差分 verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - `fixtures/execution/open-redirect-verified.json`

## 验证重点

- M4 只消费 `PocPlan(execution_state=not_run)`。
- 生成 `http_request_replay` 类型的最小 exp request artifact。
- affected 观察到外跳，fixed 未观察到外跳。
- 最终 verdict 为 `verified`。
