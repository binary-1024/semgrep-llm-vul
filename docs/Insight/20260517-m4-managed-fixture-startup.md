# Insight: 为 M4.2 引入受控 managed fixture app 启停

## 元信息

- 日期：2026-05-17
- 状态：Accepted
- 关联任务：M4.2 主线；把 M4.1 的 loopback live runner 推进到受控 fixture app 启停
- 关联 ADR：`docs/decisions/0017-use-managed-fixture-startup-for-m4.md`
- 决策类型：安全边界

## 背景

当前仓库已经完成：

- M4 第一版的结构化 exp verification/report；
- M4.1 的 loopback live HTTP replay runner；
- `verify-exp` 对已运行在 `localhost` / `127.0.0.1` / `::1` 上目标的真实首跳 replay。

但当前仍要求外部先把本地服务起好。项目下一步要解决的问题，不是“做通用环境编排”，而是**如何让系统在极窄场景下自己受控地启动/关闭内置 fixture app**，让 M4 的真实执行闭环更完整。

## 决策问题

M4.2 是否应引入只支持内置 fixture 对的 managed startup，而不是开放任意脚本、任意命令或任意服务描述？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：当前 live runner 已能消费真实响应，但启动目标环境仍依赖外部手工步骤。
- 最小必要能力：让 `verify-exp` 在已知的、受控的 fixture 语义下，自动获得 affected / fixed 两个 base URL。
- 不可牺牲约束：不能改变 `ExecutionEvidenceRecord -> ExpVerificationReport` 这条稳定收敛链。
- 最大风险：把“启动一个内置 fixture”扩写成“启动任意目标环境”。

### 工程化专家

- 根本问题：项目需要更完整的真实执行闭环，但不需要新的环境 DSL、容器层或编排平台。
- 最小必要能力：把现有测试里的本地 server helper 提升为 `src/` 下可复用的 managed fixture 能力。
- 不可牺牲约束：managed fixture 必须是显式枚举值，而不是用户给路径、命令或脚本。
- 最大风险：为追求通用性，过早引入 plugin system、subprocess executor 或复杂生命周期管理。

### 漏洞安全专家

- 根本问题：一旦允许系统主动启动服务，就更容易越过“只做本地安全验证”的边界。
- 最小必要能力：只允许内置、只监听 loopback、只提供当前 open redirect 场景所需的最小行为。
- 不可牺牲约束：不执行任意 shell/code，不连接公网，不加载 secrets，不读取外部用户脚本。
- 最大风险：把 managed fixture 变成“任意本地代码执行入口”。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：先把测试/fixture server 产品化为受控 harness 组件，再决定要不要走向真实服务编排。
- 备选方案：
  - A. 继续只允许外部手动起服务；
  - B. 只支持内置 managed fixture 对；
  - C. 允许用户给服务脚本或命令。
- 优点：B 能补上真实执行闭环的缺口，又不改变当前抽象分层。
- 缺点和失败模式：B 当前只能覆盖少量内置场景，短期内不通用。

### 工程化专家

- 业界常见做法：把 fixture server 做成上下文管理器或小型 runtime helper，并显式收敛到少量命名场景。
- 备选方案：
  - A. 继续把 server helper 放在 `tests/`；
  - B. 提升为 `src/` 下的 managed fixture helper，并暴露给 CLI；
  - C. 直接引入容器 / subprocess 编排。
- 优点：B 让测试和 CLI 共用同一能力，避免重复实现。
- 缺点和失败模式：如果把配置表做大，很容易演化成半个环境平台。

### 漏洞安全专家

- 业界常见做法：对主动启动能力采用 allowlist，不接受自由脚本输入。
- 备选方案：
  - A. `--managed-fixture open_redirect_pair`
  - B. `--startup-cmd <shell>`
  - C. `--service-spec <json/yaml>`
- 优点：A 最容易审计，也最容易测试。
- 缺点和失败模式：A 灵活性最低，但正好符合当前阶段需求。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 managed startup 不继续产出 loopback base URL，如何和现有 live runner 对接？
- 需要验证的假设：当前 open redirect 场景只需要一个受影响服务和一个修复服务的最小 HTTP 行为。
- 当前最小可行决策：managed fixture 只负责安全地生成两个 loopback base URL，其余仍走 `collect_local_execution_records`。
- 验证 harness：CLI `--managed-fixture open_redirect_pair` 应能直接得到 `verified`。

### 工程化专家

- 对其他方案的质询：如果现在允许任意脚本，和 `subprocess.run(user_input)` 有什么本质区别？
- 需要验证的假设：把测试 helper 提升到 `src/` 不会让现有 `./scripts/check` 变脆。
- 当前最小可行决策：只引入一个枚举值 `open_redirect_pair`，并用 context manager 统一启动/清理。
- 验证 harness：单元测试、CLI 测试、现有 benchmark 不回退。

### 漏洞安全专家

- 对其他方案的质询：如果 managed fixture 支持用户给路径、脚本或命令，这和“只做本地安全验证”还有什么关系？
- 需要验证的假设：当前 open redirect 只需要首跳 `302 + Location` 就够表达 affected/fixed 差分。
- 当前最小可行决策：managed fixture 仅支持内置 Flask-like open redirect pair；只监听 loopback；不读取外部配置。
- 验证 harness：未知 fixture 名必须立即失败；不会生成公网请求。

## 最终决策

M4.2 引入**受控 managed fixture startup**，但只允许系统内置、显式枚举的 fixture 对。

第一版边界：

- CLI 新增 `--managed-fixture <name>`。
- 当前唯一允许的值：`open_redirect_pair`。
- `--managed-fixture` 与 `--execution-json`、`--affected-base-url`、`--fixed-base-url` 互斥。
- managed fixture 只负责启动/清理内置 loopback 服务，并返回 affected/fixed base URL。
- 真正的请求执行仍复用现有 loopback live runner。
- 当前不引入任意脚本、任意命令、容器、环境 DSL、登录态、secrets 或公网目标。

## 为什么现在这样做

- 它把当前“测试里已有的最小本地 server”提升成可复用系统能力。
- 它补上了真实执行闭环里最后一段手工步骤，但没有把项目变成环境编排平台。
- 它仍然让现有 report contract、live runner contract 和 verdict contract 保持稳定。

## 不采用的方案

- 继续只要求外部手动起服务：当前不采用，因为这会让 M4 的真实执行闭环停在半自动状态。
- 允许 `--startup-cmd` 或任意脚本：当前不采用，因为这会直接突破安全边界。
- 直接引入容器或真实项目服务编排：当前不采用，因为这远超本阶段需求。

## 验证方式

- 引入 `managed fixture` 的单元测试或 CLI 测试。
- 至少覆盖：
  - `--managed-fixture open_redirect_pair` -> `verified`
  - 未知 fixture 名 -> 报错
  - 与其他 execution source 混用 -> 报错
- 运行 `./scripts/check` 与 `./scripts/benchmark`。

## 重新评估条件

- 需要支持多个漏洞类型的内置 fixture 家族。
- 需要支持真实项目 checkout/build/run。
- 需要登录态、数据库、副作用治理或容器隔离。
- 需要更广的 observation contract，而不是只看首跳 HTTP。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
