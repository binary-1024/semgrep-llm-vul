# curated-safe-executor-submit

## 背景

这个 negative case 验证 `executor.submit(...)` 不应因为变量名包含 `exec` 前缀而被
识别为 command execution sink。

## 关键证据

- 输入 artifact：`fixtures/sink/safe-executor-fix.diff`
- 期望：不生成 `exec` 或 `submit` candidate。

## 已知失败模式

如果 heuristic 对调用表达式或 receiver 做了前缀/子串匹配，`executor.submit` 可能被误判。

## 后续升级

后续可以增加 `subprocess.run(...)` positive case，与该 negative case 形成对照。
