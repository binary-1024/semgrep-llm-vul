## 用途

这是项目自建的最小 M2 blocked case，用于验证当 handler-local guard 明确把
`redirect(next_url)` 的可达输入限制为相对路径时，系统可以从本地 AST 中直接生成
`reachable=false` 和 `blocking_factor`。

## 关注点

- route 入口仍然存在；
- candidate taint path 仍然存在；
- 但到达 sink 的输入被明确限制为以 `/` 开头的相对路径。

## 失败模式

- 如果系统仍然只能从手写 JSON 读取 blocked evidence，这个 case 会错误退回
  `reachable=true` 或 `reachable=null`。
- 如果 heuristic 过宽，把其他普通字符串判断也当成有效 guard，会污染 false 语义。

## 后续边界

后续可以扩展更多显式 guard/sanitizer 模式；当前 case 只锁定 handler-local 的相对路径约束。
