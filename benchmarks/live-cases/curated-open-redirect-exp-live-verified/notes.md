# curated-open-redirect-exp-live-verified

## 背景

这个 case 用来把 M4.2 的 managed fixture runtime 正式沉淀成一条 opt-in live case。

它验证的不是离线 execution evidence JSON，而是：

`managed_fixture(open_redirect_pair) -> loopback live replay -> verified`

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated / managed fixture
- 语义：Flask open redirect 的真实 loopback 差分 verification
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-source-control-local-var-trace.json`
  - `fixtures/reachability/flask-source-control-local-var-app`
  - 仓库内置 `managed_fixture=open_redirect_pair`

## 验证重点

- M4 case evaluator 可以消费 `inputs.managed_fixture`。
- affected / fixed 版本的最小 loopback 服务由内置 runtime 受控启动和清理。
- 最终 verdict 为 `verified`。
- 该 case 默认不进入 `./scripts/benchmark`，只作为 opt-in live suite 执行。
