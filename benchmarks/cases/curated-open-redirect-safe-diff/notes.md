# curated-open-redirect-safe-diff

## 背景

这个 case 验证 diff 中的安全封装调用不应因为名称里包含 `redirect` 就被识别为直接 sink。

## 关键证据

- 输入 artifact：`fixtures/sink/safe-redirect-fix.diff`
- 期望：不生成 `redirect` 或 `safe_redirect` candidate。

## 已知失败模式

如果 sink heuristic 退化为子串匹配，`safe_redirect` 会被误判为 `redirect`。

## 后续升级

当前只覆盖 M1 negative case。后续如果引入 sanitizer/source 规则，可以把它升级为 M2 反证样例。
