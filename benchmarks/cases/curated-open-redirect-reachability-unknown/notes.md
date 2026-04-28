# curated-open-redirect-reachability-unknown

## 背景

这是项目自建的最小 M2 reachability unknown case，用于验证缺少本地入口证据时，系统必须保持 `reachable=null`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-trace.json`
- 不提供 `inputs.reachability_json`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望 reachability：`null`

## 当前已知失败模式

- 如果 evaluator 把 Semgrep taint trace 自动升级为 `reachable=true`，会把 candidate path 误当作可触达漏洞。
- 如果 evaluator 因没有入口证据输出 `reachable=false`，会把缺证据误判为阻断证据。

## 后续升级

当本地入口提取能力落成后，可以保留该 case 作为没有入口模型或证据不匹配时的回归样例。
