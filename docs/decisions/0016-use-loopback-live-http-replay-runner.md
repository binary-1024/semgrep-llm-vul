# ADR 0016：M4.1 使用 loopback live HTTP replay runner

## 状态

Accepted

## 背景

M4 第一版已经形成 `PocPlan(not_run) -> ExpVerificationReport` 的最小闭环，但 observation 仍然来自静态 execution evidence JSON。

主线下一步需要把 M4 推进到真实本地执行闭环，同时守住当前阶段的安全边界和 verdict 语义。

## 决策

项目在 M4.1 引入一个只面向 loopback 的 live HTTP replay runner，用于把已经运行在本机的 affected / fixed 目标的首跳 HTTP 响应归一化为 `ExecutionEvidenceRecord`。

具体约束：

- 只允许 `http://localhost:<port>`、`http://127.0.0.1:<port>`、`http://[::1]:<port>`。
- CLI 新增 `--affected-base-url`、`--fixed-base-url` 和 `--timeout-seconds`。
- live runner 不允许和 `--execution-json` 混用。
- live runner 不执行 `ExpRequestArtifact.command`，而是直接从 `PocRequestShape` 构造请求。
- 不跟随 redirect，不连接公网，不自动启动服务，不执行任意 shell/code。
- 当前仍只覆盖 Flask open redirect 的最小 observation 语义。
- `execution_state`、`effect_state` 与最终 verdict 的分层 contract 保持不变。

## 后果

正面影响：

- M4 可以从静态 JSON fixture 走到真实 loopback HTTP 响应。
- 当前 report schema、verdict 逻辑和 fixture 回归都能继续复用。
- 安全边界直接体现在 CLI 参数和测试里，更不容易被误用。

代价与约束：

- 当前还不负责服务启动、容器编排、会话、鉴权或 secrets。
- live runner 只支持很窄的 loopback HTTP replay，不是通用 exploit executor。
- benchmark executable suite 仍以离线 case 为主；live runner 当前主要通过 pytest 集成回归覆盖。

## 不采用的方案

- 自动启动 affected/fixed 服务。
- 执行 `ExpRequestArtifact.command`。
- 允许任意 host 或公网目标。
- 直接做通用 exploit executor。

## 关联 Insight

- [为 M4.1 引入 loopback live HTTP replay runner](../Insight/20260516-m4-local-http-replay-runner.md)
