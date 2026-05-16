# curated-open-redirect-poc-plan-blocked

## 背景

这个 case 用来锁定 M3 的负边界：如果 M2 已经给出明确 `reachable=false`，M3 必须停止在
planning 之前，不能继续产出可执行导向的 PoC plan。

## 来源

- 来源类型：`curated_minimal`
- fixture 类型：generated / project-curated
- 语义：Flask open redirect + handler-local 相对路径 guard
- 依赖证据：
  - `fixtures/semgrep/taint-result-with-relative-path-guard-trace.json`
  - `fixtures/reachability/flask-relative-path-guard-app`

## 验证重点

- `reachable=false` 不进入 PoC planning。
- report 中不出现 `plans`。
- unknowns 明确说明该路径被阻断而未进入 planning。
