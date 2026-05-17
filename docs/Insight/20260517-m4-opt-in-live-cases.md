# Insight: 为 M4.3 引入 opt-in live benchmark cases

## 元信息

- 日期：2026-05-17
- 状态：Accepted
- 关联任务：M4.3 主线；把 M4.2 的 managed fixture runtime 推进到少量真实 live case
- 关联 ADR：`docs/decisions/0018-use-opt-in-live-benchmark-cases-for-m4.md`
- 决策类型：harness / 执行边界

## 背景

当前仓库已经完成：

- M4 第一版结构化 exp verification/report；
- M4.1 的 loopback live HTTP replay runner；
- M4.2 的仓库内置 managed fixture runtime；
- pytest/live harness 对 `open_redirect_pair` 的真实本地回归。

下一步要解决的问题，不是继续扩新的漏洞类型，也不是把 benchmark suite 直接升级成默认会启动本地服务的执行器，而是**如何把现有 managed fixture runtime 以 opt-in 方式接进少量 live case**，让 M4 主线多一层真实执行闭环。

## 决策问题

M4.3 是否应把 live case 放进现有 `benchmarks/cases/` 并依赖 flag/skip 控制，还是单独放进 opt-in root，让默认 `./scripts/benchmark` 保持纯离线、确定性和稳定？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：M4 当前已有真实 loopback replay 能力，但 benchmark executable suite 仍主要消费离线 evidence JSON。
- 最小必要能力：增加一条真实 live case，证明 `managed fixture runtime -> live replay -> verdict` 这条链在 benchmark 语义下也成立。
- 不可牺牲约束：不能让默认 suite 因 live case 引入环境脆弱性、端口竞争或启动失败噪音。
- 最大风险：把“少量 opt-in live case”误做成“默认 benchmark 都可能起服务”。

### 工程化专家

- 根本问题：当前需要一个让主线可持续前进的真实执行样例，但不需要为此重做 benchmark contract。
- 最小必要能力：让 M4 case evaluator 能在 `execution_json` 之外，选择性消费 `managed_fixture` 并产出同样的 `ExpVerificationReport`。
- 不可牺牲约束：默认 `benchmarks/cases/`、`./scripts/benchmark`、`./scripts/benchmark-summary` 行为保持稳定。
- 最大风险：在现有 root 里加入需要 flag/skip 的 live case，导致 suite 语义分裂和日常回归困惑。

### 漏洞安全专家

- 根本问题：一旦 live case 进入默认 suite，就更容易让“本地真实执行”从 opt-in 变成默认执行。
- 最小必要能力：只允许仓库内置 `managed_fixture`，只监听 loopback，只跑已知最小场景。
- 不可牺牲约束：不开放任意启动命令，不连接公网，不引入 secrets，不让 benchmark 成为通用执行入口。
- 最大风险：把安全边界模糊成“只要是 benchmark case 就能主动起环境”。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：把需要真实 I/O 的 case 单独分层，避免和纯离线 case 混在同一默认回归面板里。
- 备选方案：
  - A. 在 `benchmarks/cases/` 里加 live case，并靠 `--include-live` 或 skip 控制；
  - B. 单独使用 `benchmarks/live-cases/` 之类的 opt-in root；
  - C. 不做 live case，继续只靠 pytest 集成回归。
- 优点：B 既能保留 benchmark 语义，又能把真实 live 回归提升为可复用入口。
- 缺点和失败模式：B 会引入第二个 case root，需要清楚说明默认 suite 与 opt-in suite 的边界。

### 工程化专家

- 业界常见做法：默认回归保持快、稳、离线；真实 live case 通过单独脚本或独立 target 运行。
- 备选方案：
  - A. 在当前 `evaluate-cases` 上增加 live include/exclude flag；
  - B. 让 `evaluate-case` / `evaluate-cases` 对任意 root 都可工作，再额外提供 `scripts/benchmark-live`；
  - C. 把 live case 藏在 pytest，避免 benchmark 语义扩展。
- 优点：B 实现最小，且不会引入“同一个 root 里有的 case 默认执行、有的默认跳过”的模糊状态。
- 缺点和失败模式：如果未来 live case 太多，第二个 root 也可能需要自己的 summary/baseline 约定。

### 漏洞安全专家

- 业界常见做法：真实执行样例采用 allowlist 资源、显式 opt-in 和单独入口。
- 备选方案：
  - A. 默认 benchmark suite 内混入 live case；
  - B. 单独 live root + 内置 managed fixture allowlist；
  - C. 任意 startup CLI + benchmark case 描述文件。
- 优点：B 最容易审计，也最容易维持“默认不执行、需要时显式执行”的边界。
- 缺点和失败模式：B 通用性低，但和当前阶段目标一致。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果 live case 混进默认 `benchmarks/cases/`，开发者看到 `./scripts/benchmark` 失败时，怎么快速分辨是算法退化还是本地 live 环境问题？
- 需要验证的假设：`evaluate-case` / `evaluate-cases` 只要能接受任意 root，就足以支撑 opt-in live case，不必改动默认 suite contract。
- 当前最小可行决策：live case 单独放到 `benchmarks/live-cases/`，并复用现有 evaluator。
- 验证 harness：一条 `open_redirect_pair` live case 能在新 root 下通过，且默认 `./scripts/benchmark` 不变。

### 工程化专家

- 对其他方案的质询：如果采用 flag/skip，summary、baseline、total 计数和失败语义是否都会变复杂？
- 需要验证的假设：给 M4 evaluator 增加 `inputs.managed_fixture` 分支，比为整个 suite 引入 skip 分类更小、更稳。
- 当前最小可行决策：M4 evaluator 支持 `execution_json` 或 `managed_fixture` 二选一；单独加 `scripts/benchmark-live`。
- 验证 harness：默认 suite 计数不变；opt-in live suite 可独立通过。

### 漏洞安全专家

- 对其他方案的质询：如果 live case 在默认 root 中被发现，即使默认跳过，也会不会逐步把“启动本地服务”变成 benchmark 的常规预期？
- 需要验证的假设：单独 root 可以把 opt-in 意图体现到目录、脚本和文档层，而不是只靠运行参数记忆。
- 当前最小可行决策：live case 默认不被 `./scripts/benchmark` 和 `./scripts/benchmark-summary` 消费；只有显式运行 `scripts/benchmark-live` 或点名 `benchmarks/live-cases/<case-id>` 时才执行。
- 验证 harness：不存在任何公网目标；未知 fixture 名立即失败。

## 最终决策

M4.3 采用 **单独 opt-in live case root**，不把 live case 混入默认 `benchmarks/cases/`。

第一版边界：

- 新增 `benchmarks/live-cases/`，用于存放少量需要真实 loopback 执行的 case。
- 默认 `./scripts/benchmark`、`./scripts/benchmark-summary`、`benchmark-baseline` 继续只消费 `benchmarks/cases/`。
- `evaluate-case` / `evaluate-cases` 继续支持任意 root，因此可显式评估 `benchmarks/live-cases/`。
- M4 case evaluator 新增 `inputs.managed_fixture` 分支，用于消费仓库内置 managed fixture runtime。
- 第一版只支持 `open_redirect_pair` 这一类仓库内置 fixture，且 live case 必须显式声明 `safety.requires_isolation=true`。

## 为什么现在这样做

- 它让 managed fixture runtime 成为 pytest 之外的第二个消费者，但仍保持强边界。
- 它让“真实执行闭环”进入 benchmark/case 语义，而不污染默认日常回归。
- 它避免把当前 benchmark summary、baseline、默认 case 总数和失败语义变复杂。

## 不采用的方案

- 在 `benchmarks/cases/` 中混入 live case 并靠 flag/skip 控制：当前不采用，因为会使默认 suite 语义变复杂。
- 继续只在 pytest 中验证 live runner：当前不采用，因为这无法把真实执行闭环沉淀成独立 case 资产。
- 暴露任意 startup CLI 或脚本描述：当前不采用，因为这会突破 M4 的执行边界。

## 验证方式

- 新增 `benchmarks/live-cases/curated-open-redirect-exp-live-verified`。
- 新增 `scripts/benchmark-live`。
- 至少覆盖：
  - live case 通过 `managed_fixture=open_redirect_pair` 输出 `verified`；
  - 未声明 `safety.requires_isolation=true` 的 live case 被拒绝；
  - 默认 `./scripts/benchmark` 计数与结果不变。

## 重新评估条件

- live case 数量增长到需要自己的 summary/baseline contract。
- 需要在 live case 中支持多个 fixture family 或更复杂的环境准备。
- 需要把真实项目 checkout/build/run 纳入执行闭环。
- 需要容器、会话/鉴权、副作用治理或更广 observation contract。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新 `docs/benchmark.md`
- [x] 是否需要更新测试、case 或 script
