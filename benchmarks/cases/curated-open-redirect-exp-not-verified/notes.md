# curated-open-redirect-exp-not-verified

## 背景

这个 case 用来锁定 M4 的负结论：如果 affected 版本在可比较的本地观察里也没有出现预期的外跳效果，系统应输出 `not_verified`，而不是因为“有 plan”就假设漏洞成立。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect 的差分 verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - `fixtures/execution/open-redirect-not-verified.json`

## 验证重点

- 即使 M3 已经给出结构化 plan，M4 仍然必须以执行观察为准。
- affected 未观察到外跳效果时，最终 verdict 必须降级为 `not_verified`。
- 不能把 “有 exp request artifact” 当成 “已经验证漏洞成立”。
