# Execution Fixtures

本目录存放 M4 使用的本地 execution evidence fixture。

## 约定

- fixture 类型：generated / project-curated
- 来源：项目内合成的最小 HTTP request/response 观察
- 目的：离线表达 affected / fixed 版本在同一 request artifact 下的最小对照结果
- 当前覆盖场景：Flask open redirect（header redirect / body `meta refresh`）

## 文件说明

- `open-redirect-verified.json`：affected 观察到外跳，fixed 未观察到外跳。
- `open-redirect-meta-refresh-verified.json`：affected 在 response body 的 `meta refresh` 中表达外跳，fixed 未观察到该效果。
- `open-redirect-not-verified.json`：affected 与 fixed 都未观察到外跳，用于锁定 `not_verified`。
- `open-redirect-inconclusive.json`：affected 观察到外跳，但 fixed 环境缺失，结果保持 `inconclusive`。

这些 fixture 不代表真实在线执行日志，而是为 M4 第一版差分 verification harness 提供本地、可回归、可比较的最小观察工件。
