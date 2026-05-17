# ADR 0021：将当前窄范围定义下的 M4 收口为完成状态

## 状态

Accepted

## 背景

当前仓库已经具备结构化 exp verification、loopback live runner、managed fixture runtime、
opt-in live cases、full-chain CLI E2E，以及 open redirect 场景下 `Location`、`Refresh`
与 body `meta refresh` 三类最小 observation signal。

如果继续把所有后续 observation family、更多漏洞族或更强运行环境都挂在 M4 名下，当前
路线图下的 M4 就会失去稳定的完成线。

## 决策

项目将 **当前窄范围定义下的 M4 收口为完成状态**。

这里的完成线包括：

- 结构化 `ExpVerificationReport` 已稳定；
- `verified` / `not_verified` / `inconclusive` verdict contract 已稳定；
- affected / fixed 差分验证闭环已建立；
- 本地 execution evidence、loopback live runner、managed fixture runtime、opt-in live cases
  与 full-chain E2E 已形成一条可回归链路；
- 当前 open redirect 主线的最小 response-level observation family 已建立。

这里的完成线不包括：

- 真实项目环境自动启动或容器隔离；
- 浏览器执行、鉴权或 secrets 处理；
- 通用 exploit 平台能力；
- 更多漏洞族或更广 observation family。

## 后果

正面影响：

- 当前路线图终于有了明确 stop rule，goal 模式可以基于证据链真正收口。
- 后续工作可以更清楚地写成“后 M4 扩展”，而不是继续模糊地占用主线。
- 项目状态、benchmark baseline 和架构文档的语义更加一致。

代价与约束：

- 需要在文档中明确“完成的是当前窄范围版本”，避免被误读为“大而全都完成了”。
- 后续如果要扩大执行面或场景族，需要新的 Insight/ADR，而不是默认继续算在当前 M4 里。

## 不采用的方案

- 继续把所有 observation 扩展都算作 M4 未完成项。
- 立刻引入新的 M5，而不先把当前 M4 完成线写清楚。
- 以真实项目环境编排或浏览器执行作为当前 M4 完成条件。

## 关联 Insight

- [当前窄范围下将 M4 收口为完成状态](../Insight/20260517-m4-completion-boundary.md)
