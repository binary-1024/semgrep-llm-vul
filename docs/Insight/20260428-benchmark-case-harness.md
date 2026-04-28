# Insight: benchmark 与 case harness

## 元信息

- 日期：2026-04-28
- 状态：Accepted
- 关联任务：跨里程碑验证能力建设
- 关联 ADR：`docs/decisions/0009-use-benchmark-case-harness.md`
- 决策类型：分析策略 | 工程流程 | 安全边界

## 背景

项目当前已经具备 M0 harness、M1 sink generation pipeline、Semgrep 归一化、taint candidate 归一化和本地 sink heuristic pack。继续纯开发会有一个明显风险：系统可能越来越会通过我们手写的 fixture，却不能解释它在真实漏洞、真实 patch、真实 benchmark 上的能力边界。

benchmark 与 case harness 的目标不是替代单元测试，而是引入一条面向真实世界的持续验证线：

- 用公开 benchmark 暴露规则覆盖、误报和漏报。
- 用真实漏洞 case 暴露 repo、版本、patch、sink、路径、PoC 和 exp 的端到端缺口。
- 用项目自建 curated cases 固化每次失败、修复和能力演进。

## 决策问题

项目是否应把 benchmark 与真实漏洞 case 作为独立 harness 建设，并如何在不引入大数据集和不扩大安全边界的前提下开始？

## 第 1 轮：第一性原理拆解

### 程序分析专家

- 根本问题：漏洞分析能力不能只靠自造 fixture 证明。真实代码存在框架封装、间接调用、宏、反射、动态分发、测试环境缺失等复杂性。
- 最小必要能力：建立 case schema，记录输入、期望输出、证据锚点、阶段状态和失败类型。
- 不可牺牲约束：benchmark 命中不能等于漏洞确认；真实 case 也必须区分 candidate、reachable、triggerable、verified。
- 最大风险：只追求 benchmark 分数会诱导规则过拟合，伤害真实漏洞分析能力。

### 工程化专家

- 根本问题：如果 benchmark/case 没有固定 schema 和评测入口，它会退化成散乱资料夹，无法进入 CI 或回归流程。
- 最小必要能力：先提交轻量目录、README、case manifest 示例和评测边界，不下载大数据集。
- 不可牺牲约束：不能把 SARD、OWASP Benchmark、Vul4J、CVEfixes 等大数据直接提交进仓库。
- 最大风险：过早引入大规模 benchmark 会拖慢仓库、CI 和开发节奏，也会模糊当前 M1 的重点。

### 漏洞安全专家

- 根本问题：真实漏洞验证需要可复现证据，尤其是受影响版本与修复版本对照。只有静态命中不能证明漏洞可利用。
- 最小必要能力：每个 case 明确安全边界、可运行性、PoC/exp 状态和未验证风险。
- 不可牺牲约束：不提交攻击性 payload、真实凭据、敏感源码或未授权利用脚本。
- 最大风险：case harness 如果只记录成功案例，会掩盖模型和工具的失败模式。

## 第 2 轮：业界做法与备选方案

### 程序分析专家

- 业界常见做法：SAST 工具常用 OWASP Benchmark、SARD/Juliet 等合成数据验证规则覆盖；漏洞研究常用 Vul4J、CVEfixes、真实 CVE patch 数据验证可复现性。
- 备选方案：
  - A. 继续只用项目内小 fixture。
  - B. 引入公开 benchmark 的索引和抽样 case。
  - C. 直接下载并纳入完整 benchmark。
  - D. 只维护手工 curated cases。
- 优点：A 快；B 能兼顾真实边界和仓库轻量；C 覆盖广；D 更贴近项目目标。
- 缺点和失败模式：A 容易自嗨；C 成本高且易污染仓库；D 覆盖有限且选择偏差大。

### 工程化专家

- 业界常见做法：成熟项目通常把大数据集放在外部下载或缓存层，把仓库内版本化内容限制为 manifest、最小样例和评测脚本。
- 备选方案：
  - A. `fixtures/` 继续承载所有 case。
  - B. 新建 `benchmarks/`，专门承载 benchmark/case harness。
  - C. 独立仓库维护 benchmark。
- 优点：B 最适合当前阶段，既能和项目代码同版本演进，又能和普通 unit fixture 区分。
- 缺点和失败模式：独立仓库会增加同步成本；全部塞进 `fixtures/` 会混淆单元 fixture 和真实 case。

### 漏洞安全专家

- 业界常见做法：真实漏洞 case 常记录 CVE、受影响版本、修复版本、patch、PoV/PoC、预期行为和验证日志；安全工具评测也会记录 false positive、false negative 和 unsupported。
- 备选方案：
  - A. 只记录成功 case。
  - B. 同时记录成功、失败和不支持 case。
  - C. 只记录最终 verified case。
- 优点：B 能真实暴露能力边界，是最适合开发期的反馈源。
- 缺点和失败模式：失败 case 需要更好的分类，否则容易变成噪声。

## 第 3 轮：交叉质询与收敛

### 程序分析专家

- 对其他方案的质询：如果不引入公开 benchmark，如何知道 heuristic pack 是否只是覆盖了我们想到的少数模式？
- 需要验证的假设：小规模抽样 case 足以先暴露明显边界，不需要一开始追求 benchmark 全量分数。
- 当前最小可行决策：建立 `benchmarks/` 目录和 case schema，先维护 3 到 5 个 curated cases。
- 验证 harness：每个 case 至少能映射到 M1/M2/M3/M4 中一个阶段，并记录 expected 和 current status。

### 工程化专家

- 对其他方案的质询：是否要把 benchmark 下载脚本和评测脚本同时做完？
- 需要验证的假设：先定义 schema 和目录，后续再做 loader/evaluator，可以避免实现跑偏。
- 当前最小可行决策：本次只做 docs-only，定义 benchmark 引入原则、case manifest 和后续实现入口。
- 验证 harness：文档链接检查和 `./scripts/check` 通过；不新增大文件。

### 漏洞安全专家

- 对其他方案的质询：case harness 会不会鼓励生成攻击性 exp？
- 需要验证的假设：只要 schema 明确 PoC/exp 安全边界，并默认隔离环境、无凭据、无破坏性 payload，就能把风险控制在项目规范内。
- 当前最小可行决策：第一版只记录 case 元数据和期望分析结果，不提交真实攻击脚本。
- 验证 harness：case README 明确禁止敏感数据、真实目标攻击和未授权利用。

## 最终决策

项目建立独立的 benchmark 与 case harness，用于持续验证工具在真实/半真实样例上的能力、边界和缺陷。

第一版只做文档、目录和 schema，不下载或提交大规模数据集。

目录策略：

```text
benchmarks/
  README.md
  cases/
    README.md
    <case-id>/
      case.yaml
      expected.json
      notes.md
```

case 分层：

- `synthetic_benchmark`：来自 SARD、Juliet、OWASP Benchmark 等合成或半合成 benchmark 的抽样。
- `real_vulnerability`：来自 Vul4J、CVEfixes、公开 CVE patch、真实项目安全修复等真实漏洞。
- `curated_minimal`：项目自建的最小复现 case，用于快速暴露某个能力边界。

case 状态：

- `candidate`：只验证候选 sink 或候选路径。
- `reachable`：静态或半自动证据支持路径可触达。
- `triggerable`：PoC 已能触发目标行为。
- `verified`：受影响版本和修复版本对照验证通过。
- `unsupported`：当前能力明确不支持。
- `blocked`：缺少环境、版本、依赖或权限。

## 为什么现在这样做

- M1 已经开始扩展 sink heuristic，如果没有真实 case，很容易过拟合项目内 fixture。
- benchmark/case harness 可以并行于功能开发，用 worktree 和 docs-only 分支推进，不阻塞主线。
- 先定义 schema 和边界，可以避免后续盲目下载大数据或把 benchmark 当成分数游戏。
- 真实 case 会推动方法论落地：每个结论必须能被证据支持，也能被失败 case 反驳。

## 不采用的方案

- 继续只用单元 fixture：不采用。单元 fixture 必要但不足以证明真实漏洞分析能力。
- 一次性下载完整 SARD/OWASP/Vul4J/CVEfixes 并提交：不采用。数据量、许可证、CI 成本和维护成本都不适合当前仓库。
- 只追求 benchmark 分数：不采用。项目目标是证据链、可触达路径、PoC/exp 验证，不是单一 SAST 排名。
- 第一版直接实现 evaluator：暂不采用。先稳定 case schema，再实现 loader/evaluator。

## 验证方式

本次 docs-only 分支：

- 新增 benchmark/case harness Insight 和 ADR。
- 新增 `benchmarks/README.md` 和 `benchmarks/cases/README.md`。
- 提供一个最小 `case.yaml` 和 `expected.json` 示例。
- 更新文档索引。
- 运行 `./scripts/check`。
- 检查不新增大数据集、缓存、外部下载产物或敏感数据。

后续 feature 分支：

- 实现 case loader。
- 实现最小 evaluator，先覆盖 M1 sink generation 输出。
- 将 3 到 5 个 curated cases 纳入回归。

## 重新评估条件

以下情况出现时重新评估本决策：

- 需要引入完整外部 benchmark 下载或缓存。
- 需要把 benchmark evaluator 接入 CI。
- case 中开始包含 PoC/exp 脚本。
- 需要处理第三方 benchmark 许可证或分发限制。
- case 数量增长到需要单独仓库或 artifact storage。

## 后续动作

- [x] 是否需要同步新增或更新 `docs/decisions/`
- [ ] 是否需要更新 `docs/architecture.md`
- [ ] 是否需要更新 `docs/product.md`
- [x] 是否需要更新测试或 fixture
