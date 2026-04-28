# curated-open-redirect-taint-path

## 背景

这是项目自建的最小 M2 case，用于验证 Semgrep taint-mode trace 能和 M1 sink candidate 对齐，生成候选 `TaintPath`。

## 关键证据

- Semgrep fixture：`fixtures/semgrep/taint-result-with-trace.json`
- 期望 source：`request.args["next"]`
- 期望 sink：`redirect`
- 期望 steps：`source -> intermediate -> sink`
- `reachable` 必须保持 `null`

## 当前已知失败模式

- 如果 sink candidate 与 Semgrep taint sink 的名称归一化失败，会漏掉路径。
- 如果 evaluator 将 candidate path 错误升级为 reachable，会混淆 M2 候选和可触达确认。

## 后续升级

后续可以增加可触达确认 case，但当前只验证候选路径生成。
