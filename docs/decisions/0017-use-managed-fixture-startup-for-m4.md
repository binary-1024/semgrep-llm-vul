# ADR 0017：M4.2 使用受控 managed fixture startup

## 状态

Accepted

## 背景

M4.1 已经支持 loopback live runner，但仍要求外部先把本地服务起好。主线下一步要补的是“受控自动启动内置 fixture app”，不是通用环境编排。

## 决策

项目在 M4.2 引入 `--managed-fixture <name>`，只允许系统内置、显式 allowlist 的 fixture 对。

第一版约束：

- 当前唯一允许的值：`open_redirect_pair`。
- `--managed-fixture` 与 `--execution-json`、`--affected-base-url`、`--fixed-base-url` 互斥。
- managed fixture 只监听 loopback，只提供当前 open redirect 场景所需的最小 HTTP 行为。
- managed fixture 不执行任意 shell/code，不读取外部脚本，不连接公网，不处理 secrets。
- managed fixture 只负责生成 affected/fixed base URL；后续请求执行仍复用现有 live runner。

## 后果

正面影响：

- M4 的真实执行闭环更完整，CLI 不再依赖外部手工起服务。
- 测试和 CLI 可以共用同一套内置 fixture 启停能力。
- 当前安全边界仍然明确，没有滑成通用编排能力。

代价与约束：

- 目前只覆盖一个内置 fixture 名，通用性很低。
- benchmark suite 暂不一定直接消费这条能力，主要先通过 pytest/CLI 稳定回归。
- 一旦要支持真实项目服务，这个方案需要重新评估。

## 不采用的方案

- 继续只要求外部手动起服务。
- 允许 `--startup-cmd`、脚本路径或服务描述文件。
- 直接引入容器/真实项目环境编排。

## 关联 Insight

- [为 M4.2 引入受控 managed fixture app 启停](../Insight/20260517-m4-managed-fixture-startup.md)
