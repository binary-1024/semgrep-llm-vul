# owasp-benchmark-command-injection-distilled

## 背景

这个 case 用项目自写的最小 diff 表达 OWASP Benchmark 中 command injection / CWE-78
类样例的核心形状：外部可控字符串进入命令执行 API。

没有复制 OWASP Benchmark 源码，也没有提交完整 benchmark 数据集。

## 来源

- 来源类型：`synthetic_benchmark`
- 原始来源：[OWASP Benchmark](https://owasp.org/www-project-benchmark/)
- 上游仓库参考：`https://github.com/OWASP-Benchmark/BenchmarkJava`
- fixture 类型：合成的项目内 distillation，不是上游源码裁剪版。
- 许可证：使用上游材料前需再确认；当前 fixture 为项目自写最小样例。

## 关键证据

- 输入 artifact：`fixtures/sink/benchmark-command-injection-fix.diff`
- 期望：生成 `exec` candidate，类别为 `command_execution`。

## 当前验证边界

只验证 M1 sink candidate extraction，不验证 source、taint path、PoC 或 exp。

## 已知失败模式

如果 Java 链式调用中的 `.exec(...)` 不能被 heuristic 识别，本 case 会失败。
