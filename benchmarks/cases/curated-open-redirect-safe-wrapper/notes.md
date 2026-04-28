# curated-open-redirect-safe-wrapper

## 背景

这是项目自建的最小 M1 case，用于验证 open redirect sink candidate 的基本提取能力，以及安全封装不会被子串误判。

## 为什么选择这个 case

项目已经存在 `fixtures/sink/open-redirect-fix.diff` 和 `fixtures/sink/safe-redirect-fix.diff`。这个 case 把其中的正向期望固化到 benchmark/case harness 中，为后续 case loader 和 evaluator 提供最小样例。

## 关键证据

- diff artifact：`fixtures/sink/open-redirect-fix.diff`
- 期望 sink：`redirect`
- 期望位置：`app/routes.py:9`
- 期望类别：`open_redirect`

## 当前已知失败模式

- 如果只做子串匹配，可能把 `safe_redirect` 或 `is_safe_redirect` 错误识别为 sink。
- 如果 diff hunk 行号解析失败，可能无法给 sink evidence 提供稳定位置。

## 后续升级

当前只覆盖 M1 candidate。后续可以扩展为 M2 路径 case，增加 source、entrypoint 和 sanitizer 期望。
