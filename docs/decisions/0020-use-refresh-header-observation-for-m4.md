# ADR 0020：M4.5 使用 refresh-header effect observation

## 状态

Accepted

## 背景

M4.4 已经具备结构化 exp verification、loopback live runner、managed fixture runtime、opt-in
live cases，以及 `meta refresh` body signature 这一类 response-level observation。

主线下一步要补的是 observation coverage，而不是扩大 runner 权限或引入通用 response diff 平台。

## 决策

项目在 M4.5 引入 **refresh-header effect observation**，第一版仅支持 open redirect 场景下的
`Refresh: ... url=...` response header。

具体约束：

- `verified` / `not_verified` / `inconclusive` 三态 verdict 保持不变。
- `execution_state`、`effect_state` 与最终 verdict 的分层 contract 保持不变。
- 不提升 exp verification report 的 `schema_version`。
- execution evidence JSON 与 live runner 复用现有 response header 承载能力。
- 第一版只支持带 `url=` 的 `Refresh` header，不支持任意 header 模糊匹配。
- 仍然只服务当前 open redirect 主线；不引入新的 `vulnerability_type`。

## 后果

正面影响：

- M4 获得第三类明确的 redirect effect 信号，而不再只依赖 `Location` header 与 body `meta refresh`。
- 离线 fixture、CLI、benchmark/live case 与 live runner 可以复用同一 observation family。
- 该能力仍保持在本地、可解释、可回归的安全边界内。

代价与约束：

- 当前仍然不是通用 response header/body analysis 平台。
- 只支持带 `url=` 的 `Refresh` header，覆盖率有限。
- 如果未来要支持 error signature、更广 response diff 或浏览器语义，需要新的 Insight/ADR。

## 不采用的方案

- 保持只支持 `Location` 与 `meta refresh`。
- 一次性做通用 response diff / error signature 平台。
- 引入浏览器执行或 JS 语义判断。

## 关联 Insight

- [为 M4.5 引入 refresh-header effect observation](../Insight/20260517-m4-refresh-header-observation.md)
