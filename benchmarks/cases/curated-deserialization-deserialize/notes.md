# curated-deserialization-deserialize

## 背景

这是项目自建的最小 M1 deserialization case，用于验证 `deserialize(...)` 能被识别为反序列化 sink candidate。

## 关键证据

- diff artifact：`fixtures/sink/deserialization-fix.diff`
- 期望 sink：`deserialize`
- 期望位置：`app/session.py:42`
- 期望类别：`deserialization`

## 当前已知失败模式

- 如果 heuristic pack 只覆盖命令执行和重定向，会漏掉反序列化 sink。
- 如果安全解析函数被误判为 sink，会让修复后代码产生噪声候选。

## 后续升级

后续可以升级为 M2/M3 case，加入外部 session 数据 source 和最小触发输入。
