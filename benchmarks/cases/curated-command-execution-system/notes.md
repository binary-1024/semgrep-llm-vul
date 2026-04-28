# curated-command-execution-system

## 背景

这是项目自建的最小 M1 command execution case，用于验证 `os.system(...)` 能被识别为命令执行 sink candidate。

## 关键证据

- diff artifact：`fixtures/sink/command-exec-fix.diff`
- 期望 sink：`system`
- 期望位置：`app/tasks.py:20`
- 期望类别：`command_execution`

## 当前已知失败模式

- 如果规则只覆盖 Web 重定向类 sink，会漏掉命令执行。
- 如果把 `subprocess.run(..., shell=False)` 的 `run` 误判为 sink，会产生修复后代码的噪声候选。

## 后续升级

后续可以升级为 M2 case，增加命令参数 source 与 sanitizer 期望。
