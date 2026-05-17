# curated-open-redirect-exp-refresh-header-verified

## 背景

这个 case 用来锁定 M4.5 的第三类最小 redirect signal：当 open redirect 的效果不是通过
`Location` header，也不是通过 body `meta refresh`，而是通过 response header `Refresh`
表达时，系统仍应输出 `verified`。

## 设计

- 类型：`curated_minimal`
- 阶段：`M4`
- 语义：Flask open redirect 的 `Refresh` header 差分 verification

## 输入

- analysis input：`examples/analysis/unknown-sink.yaml`
- semgrep trace：`fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
- source root：`fixtures/reachability/flask-source-control-local-var-app`
- execution evidence：`fixtures/execution/open-redirect-refresh-header-verified.json`

## 期望

- affected 的 `Refresh` response header 指向外部 URL。
- fixed 不再返回外部 `Refresh` header。
- 最终 verdict 为 `verified`。
