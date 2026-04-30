# curated-open-redirect-reachability-alias-assignment-unknown

## 背景

这是项目自建的最小 M2 reachability negative case，用于验证即使存在本地 source root，
如果 route 到 sink 的局部调用链需要依赖普通 assignment alias，系统也必须保持
`reachable=null`，而不是错误升级为 `true` 或误判为 `false`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-alias-assignment-unknown-trace.json`
- Source root fixture：`fixtures/reachability/flask-alias-assignment-unknown-app`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望 reachability：`null`

## 当前已知失败模式

- 如果系统把普通 assignment alias 也当作 module alias 解析，该 case 会错误升级为 `reachable=true`。
- 如果系统因为 source root 存在但 call chain 不可确认就输出 `reachable=false`，会把缺证据误判为阻断证据。

## 后续升级

后续如果要支持 assignment alias、对象属性或更一般的 owner 解析，需要单独的 Insight 和新的
调用关系抽象；当前 case 用来锁住“assignment alias 仍属于 `reachable=null` 边界”。
