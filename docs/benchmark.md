# Benchmark 与 Case Harness

本文档定义项目如何使用公开 benchmark、真实漏洞 case 和项目自建 curated cases 来验证能力边界。

benchmark/case harness 不替代单元测试。它的职责是持续回答：

- 当前系统能在哪些样例上找到正确 sink？
- 哪些 case 会误报、漏报或无法判断？
- 哪些结论只有 candidate，哪些已经 reachable、triggerable 或 verified？
- 哪些失败应转化为规则、fixture、测试或架构调整？

## 数据来源分层

### synthetic_benchmark

合成或半合成 benchmark，用于验证规则覆盖和误报/漏报。

候选来源：

- NIST SARD / Juliet。
- OWASP Benchmark。

使用原则：

- 仓库只提交抽样 case 的 manifest、最小裁剪样例或引用，不提交完整大数据集。
- benchmark 分数只能作为辅助指标，不能替代证据链质量。
- 对每个抽样 case 标注原始来源、许可、漏洞类别和裁剪方式。

### real_vulnerability

真实漏洞 case，用于验证项目是否能处理真实 repo、版本、patch 和验证环境。

候选来源：

- Vul4J。
- CVEfixes。
- 公开 CVE patch。
- 真实项目安全修复 PR。

使用原则：

- 优先选择有明确 affected version、fixed version、patch 和可复现说明的 case。
- PoC/exp 默认只记录状态和安全边界，未经决策不提交真实攻击脚本。
- 真实 case 必须标注 blocked/unsupported 原因，不能只保留成功样例。

### curated_minimal

项目自建最小 case，用于快速验证某个具体边界，例如：

- `safe_redirect` 不应被误判为 `redirect`。
- diff 中删除行和新增行应保留不同 evidence。
- Semgrep `rule_id` 子串不应单独生成 sink。

使用原则：

- 尽量小、离线、确定性。
- 每个 case 只验证一个核心边界。
- 如果来自真实漏洞简化，需要在 notes 中说明简化内容。

## Case Schema

每个 case 目录包含：

```text
case.yaml
expected.json
notes.md
```

`case.yaml` 描述输入、来源和运行边界。

`expected.json` 描述当前期望输出。它不是永远正确的真理；当项目能力提升或发现期望有误时，应通过 review 更新。

`notes.md` 记录背景、证据链、失败模式和复盘。

## 状态语义

- `candidate`：只验证候选 sink 或候选路径。
- `reachable`：静态或半自动证据支持路径可触达。
- `triggerable`：PoC 已能触发目标行为。
- `verified`：受影响版本和修复版本对照验证通过。
- `unsupported`：当前能力明确不支持。
- `blocked`：缺少环境、版本、依赖或权限。

状态只能向证据充分的方向升级；如果证据被反驳，应降级并记录原因。

## 安全边界

- 不提交真实凭据、私有源码、敏感扫描输出或未授权目标信息。
- 不提交破坏性 payload。
- PoC/exp 进入仓库前必须有明确隔离环境和执行边界。
- 外部 benchmark 或 case 的许可证、来源和裁剪方式必须可追溯。
- 大数据集、下载缓存和生成产物不得进入版本库。

## 后续实现方向

第一阶段：

- 固化 `benchmarks/` 目录和 case schema。
- 维护 3 到 5 个小型 curated cases。

第二阶段：

- 实现 case loader。
- 实现 M1 sink generation evaluator。
- 输出 per-case pass/fail/blocked/unsupported 报告。

当前最小 evaluator 已支持评估单个 M1 case：

```bash
uv run semgrep-llm-vul evaluate-case \
  benchmarks/cases/curated-open-redirect-safe-wrapper \
  --repo-root .
```

也可以批量评估当前 `benchmarks/cases/` 下的 M1 cases：

```bash
uv run semgrep-llm-vul evaluate-cases benchmarks/cases --repo-root .
```

第三阶段：

- 扩展到 M2 taint path、M3 PoC、M4 exp。
- 支持外部 benchmark 下载缓存，但不提交原始大数据。
