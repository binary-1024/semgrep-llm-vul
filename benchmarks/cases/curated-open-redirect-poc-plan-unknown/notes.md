# curated-open-redirect-poc-plan-unknown

## 背景

这个 case 用来锁定 M3 的另一条负边界：当 M2 仍然是 `reachable=null` 时，M3 必须保留
unknown，而不是把证据不足的路径强行升级成看起来可执行的 PoC plan。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect + assignment alias 未解析
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-alias-assignment-unknown-trace.json`
  - `fixtures/reachability/flask-alias-assignment-unknown-app`

## 验证重点

- `reachable=null` 不进入 PoC planning。
- report 中不出现 `plans`。
- unknowns 明确说明当前是证据不足，而不是判定安全。
