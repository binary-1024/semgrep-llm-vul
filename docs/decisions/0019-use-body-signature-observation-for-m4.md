# ADR 0019：M4.4 使用 body-signature effect observation

## 状态

Accepted

## 背景

M4.3 已经具备结构化 exp verification、loopback live runner、managed fixture runtime、opt-in
live case 和 full-chain E2E smoke，但当前 `effect observation` 仍然只支持 `30x + Location`
这一类 header-based redirect。

主线下一步要补的是 observation coverage，而不是扩大 runner 权限或引入通用 body diff 平台。

## 决策

项目在 M4.4 引入 **body-signature effect observation**，第一版仅支持 open redirect 场景下的
`meta refresh` body redirect signature。

具体约束：

- `verified` / `not_verified` / `inconclusive` 三态 verdict 保持不变。
- `execution_state`、`effect_state` 与最终 verdict 的分层 contract 保持不变。
- execution evidence JSON 与 live runner 都允许携带 response body。
- 第一版只支持 `meta refresh`，不支持任意 body diff、JS 执行或浏览器渲染。
- 仍然只服务当前 open redirect 主线；不引入新的 vulnerability_type。

## 后果

正面影响：

- M4 能覆盖第二类明确的 redirect effect，而不再只依赖 `Location` header。
- 离线 fixture、CLI、benchmark/live case 与 live runner 可以复用同一 observation family。
- 该能力仍然保留在本地、可解释、可回归的安全边界内。

代价与约束：

- 当前仍然不是通用 response body analysis 平台。
- 只支持 `meta refresh`，覆盖率有限。
- 如果未来要支持 JS redirect、error signature 或更通用 body diff，需要新的 Insight/ADR。

## 不采用的方案

- 继续只支持 header-based redirect。
- 一次性做通用 body diff / error signature 平台。
- 引入浏览器执行或 JS 语义判断。

## 关联 Insight

- [为 M4.4 引入 body-signature effect observation](../Insight/20260517-m4-body-signature-observation.md)
