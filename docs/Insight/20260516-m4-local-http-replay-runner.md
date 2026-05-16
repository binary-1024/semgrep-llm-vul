# Insight: 为 M4.1 引入 loopback live HTTP replay runner

## 元信息

- 日期：2026-05-16
- 状态：Accepted
- 关联任务：M4.1 主线；把 M4 从 report-first 闭环推进到最小真实本地执行闭环
- 关联 ADR：`docs/decisions/0016-use-loopback-live-http-replay-runner.md`
- 决策类型：安全边界

## 背景

当前仓库已经完成 M4 第一版最小闭环，具备：

- `PocPlan(execution_state=not_run)`；
- `ExpVerificationReport`；
- `execution_state`、`effect_state`、`verdict` 三层分离；
- 基于本地 execution evidence JSON 的 affected / fixed 差分验证；
- Flask open redirect 这一条 M2/M3/M4 主线。

下一步自然问题不是“要不要立刻做通用 exploit 执行器”，而是：**如何在不破坏当前阶段语义和安全边界的前提下，把 M4 的 observation 来源从静态 fixture 推进到真实本地 HTTP 响应。**

## 决策问题

M4.1 是否应引入一个只面向 loopback 目标的 live HTTP replay runner，而不是直接进入自动启动服务、容器编排或通用命令执行？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：M4 当前已经能根据观察记录推出 verdict，但 observation 仍是静态 JSON，不是真实执行。
- 最小必要能力：把 `PocRequestShape` 变成真实首跳 HTTP 请求，并仍然产出 `ExecutionEvidenceRecord`。
- 不可牺牲约束：不能改坏 `execution_state / effect_state / verdict` 的分层语义。
- 最大风险：把“能发请求”误当成“已经完成 exploit 执行平台”。

### 工程化专家

- 根本问题：当前仓库擅长的是本地、确定性、可回归的小步推进；自动起服务或做环境 DSL 会明显扩大系统面。
- 最小必要能力：保留现有 report contract 和 verdict 逻辑，只替换 execution observation 的来源。
- 不可牺牲约束：live runner 不能让现有 `--execution-json` 回归失效，也不能把 `./scripts/check` 变脆。
- 最大风险：一边引入 live runner，一边重写 schema、CLI 语义或 benchmark 模型，导致主线扩散。

### 漏洞安全专家

- 根本问题：一旦进入真实请求，网络边界、跳转跟随、目标选择和副作用控制都会成为安全问题。
- 最小必要能力：只允许 loopback、只抓首跳响应、只看当前 open redirect 所需的 `status code + Location header`。
- 不可牺牲约束：不连公网、不自动获取 secrets、不执行任意 shell/code、不自动启动未知服务。
- 最大风险：跟随 30x、放开任意 host、把 `curl` 命令字符串直接拿去执行。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：先把 request replay / effect observation 做成窄类型 contract，再逐步扩 runner 和环境编排。
- 备选方案：
  - A. 继续只消费 execution evidence JSON；
  - B. 引入 loopback live HTTP replay；
  - C. 直接做自动启动服务或通用 exploit executor。
- 优点：B 能把 observation 从静态 fixture 升级为真实响应，又不破坏当前抽象。
- 缺点和失败模式：B 仍然依赖外部先把本地服务起好，不能替代环境 provisioning。

### 工程化专家

- 业界常见做法：保留结构化 request model，不执行自由命令字符串；live runner 只是 observation adapter。
- 备选方案：
  - A. 执行 `ExpRequestArtifact.command`；
  - B. 从 `PocRequestShape` 直接构造 HTTP 请求；
  - C. 做一套通用 runner plugin / DSL。
- 优点：B 最小、最可控，也最容易写出稳定回归。
- 缺点和失败模式：如果后续需要 session、auth、body diff，这个接口还需要扩展。

### 漏洞安全专家

- 业界常见做法：先连到受控 loopback 服务，不跟随 redirect，不自动跨出本地边界。
- 备选方案：
  - A. 允许任意 URL；
  - B. 只允许 `localhost` / `127.0.0.1` / `::1`；
  - C. 自动启动任意用户给定脚本。
- 优点：B 能直接把安全边界固化进 CLI 和测试。
- 缺点和失败模式：B 牺牲了灵活性，但这是当前阶段应接受的代价。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 live runner 不继续产出 `ExecutionEvidenceRecord`，后半段 verdict 逻辑还怎么复用？
- 需要验证的假设：当前 `PocRequestShape` 足以驱动最小 GET/query replay。
- 当前最小可行决策：live runner 只负责把本地 HTTP 响应归一化为 observation record。
- 验证 harness：至少覆盖 affected/fixed 都完成时的 `verified`，以及 fixed 缺失时的 `inconclusive`。

### 工程化专家

- 对其他方案的质询：如果一开始就做自动启动服务，谁来定义生命周期、健康检查、失败分类和清理策略？
- 需要验证的假设：可以先把“服务已在 loopback 上运行”当作 M4.1 的前提，而不是本阶段要解决的问题。
- 当前最小可行决策：新增 `--affected-base-url`、`--fixed-base-url` 和 timeout 参数，保留 `--execution-json` 路径不回退。
- 验证 harness：单元测试 + CLI 测试启动极小本地 HTTP 服务，`./scripts/check` 继续通过。

### 漏洞安全专家

- 对其他方案的质询：如果放开 redirect follow 或任意 host，怎么保证不会变成外连器？
- 需要验证的假设：open redirect 的最小 effect observation 只看首跳 `Location` 即可。
- 当前最小可行决策：只允许 `http://localhost`、`http://127.0.0.1`、`http://[::1]`，且必须显式带端口；不跟随 redirect；不执行 shell。
- 验证 harness：非 loopback base URL 必须直接报错；未监听端口应落到 `environment_missing`。

## 最终决策

M4.1 引入**loopback live HTTP replay runner**，但保持它是一个极窄的 observation adapter，而不是 exploit executor。

具体边界：

- 保持 `ExpVerificationReport` shape 和 verdict contract 不变。
- live runner 继续产出 `ExecutionEvidenceRecord`，后续 `effect_state` / `verdict` 逻辑原封复用。
- CLI 新增：
  - `--affected-base-url`
  - `--fixed-base-url`
  - `--timeout-seconds`
- 只允许 `http://localhost:<port>`、`http://127.0.0.1:<port>`、`http://[::1]:<port>`。
- 不允许和 `--execution-json` 混用。
- 不自动启动真实服务，不执行 `curl` 命令字符串，不跟随 redirect，不连接公网。
- 当前仍只覆盖 Flask open redirect 这一类可以由首跳 `Location` 表达的效果。

## 为什么现在这样做

- 它让 M4 真正跨过“静态 fixture -> 真实响应”的门槛，但没有一下子把项目带进环境编排。
- 它最大化复用了已经稳定的 report schema、observation 归一化和 verdict 逻辑。
- 它把安全边界直接固化在输入模型、CLI 校验和测试里，而不是靠使用习惯约束。

## 不采用的方案

- 自动启动 affected/fixed 服务：当前不采用，因为这会立刻引入生命周期、隔离、健康检查和清理复杂度。
- 执行 `ExpRequestArtifact.command`：当前不采用，因为这会把 shell 执行引入 runner 路径。
- 允许任意 host：当前不采用，因为这会突破本地验证边界。
- 直接做通用 exploit executor：当前不采用，因为与现阶段主线不匹配。

## 验证方式

- 引入 loopback live runner 的单元测试。
- 引入 `verify-exp` 的 CLI live runner 测试。
- 覆盖：
  - affected/fixed 双完成 -> `verified`
  - fixed 未监听 -> `inconclusive`
  - 非 loopback 目标 -> 直接报错
- 运行 `./scripts/check`。

## 重新评估条件

- 需要自动启动 fixture app、真实项目服务或容器。
- 需要跨请求会话、登录态、鉴权或 secrets。
- 需要支持 body diff、stdout/stderr、文件副作用等更广的 effect observation。
- 需要支持比 open redirect 更广的 live runner 语义族。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
