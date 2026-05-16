# curated-open-redirect-exp-inconclusive

## 背景

这个 case 用来锁定 M4 的保守语义：即使 affected 版本已经观察到外跳效果，只要 fixed 版本缺少可比较的执行观察，最终结论也必须保持 `inconclusive`。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect 的差分 verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - `fixtures/execution/open-redirect-inconclusive.json`

## 验证重点

- affected / fixed 对照是 M4 的一等语义。
- fixed 执行环境缺失时，最终 verdict 必须保持 `inconclusive`。
- `verified` 必须要求两边都完成可比较的执行观察。
