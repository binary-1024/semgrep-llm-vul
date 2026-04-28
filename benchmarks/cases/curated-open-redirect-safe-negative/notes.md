# curated-open-redirect-safe-negative

## 背景

这是项目自建的 M1 negative case，用于验证安全校验和安全封装不会被误判为直接 sink。

## 关键证据

- diff artifact：`fixtures/sink/safe-redirect-fix.diff`
- 禁止候选：`redirect`
- 禁止候选：`safe_redirect_target`

## 当前已知失败模式

- 如果匹配逻辑使用子串匹配，`safe_redirect_target` 可能被误判为 `redirect`。
- 如果 evaluator 只检查正向命中，不检查禁止项，就无法发现这类误报。

## 后续升级

后续可以加入更多 sanitizer wrapper negative case，覆盖不同语言和框架命名习惯。
