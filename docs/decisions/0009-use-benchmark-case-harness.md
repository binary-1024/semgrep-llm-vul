# Decision: 建立 benchmark 与 case harness

## 背景

项目已经具备基础工程 harness、M1 sink generation pipeline 和本地 sink heuristic pack。继续只依赖项目内手写 fixture，会导致能力验证过窄，难以发现真实漏洞分析中的边界和失败模式。

## 决策

建立独立的 benchmark 与 case harness，用于持续验证项目在真实/半真实样例上的能力、边界和缺陷。

第一版只提交文档、目录结构、case schema 和最小示例，不下载、不提交完整外部 benchmark 或大数据集。

目录结构：

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

case 类型：

- `synthetic_benchmark`：来自 SARD、Juliet、OWASP Benchmark 等合成或半合成 benchmark 的抽样。
- `real_vulnerability`：来自 Vul4J、CVEfixes、公开 CVE patch、真实项目安全修复等真实漏洞。
- `curated_minimal`：项目自建的最小复现 case，用于快速验证某个能力边界。

case 状态：

- `candidate`：只验证候选 sink 或候选路径。
- `reachable`：静态或半自动证据支持路径可触达。
- `triggerable`：PoC 已能触发目标行为。
- `verified`：受影响版本和修复版本对照验证通过。
- `unsupported`：当前能力明确不支持。
- `blocked`：缺少环境、版本、依赖或权限。

## 影响

- benchmark/case 成为单元测试之外的第二条验证线。
- 后续 feature 可以基于 case schema 实现 loader 和 evaluator。
- 真实 case 的失败会沉淀为可复现的开发反馈，而不是只停留在聊天或人工判断中。
- 项目避免把外部大数据集、缓存、下载产物和敏感数据提交进仓库。

## 备选方案

- 继续只用单元 fixture：不采用，因为无法充分暴露真实代码、真实 patch 和真实环境边界。
- 一次性提交完整外部 benchmark：不采用，因为数据量、许可证、CI 成本和维护成本过高。
- 独立仓库维护 benchmark：暂不采用，因为当前 case 数量小，与主项目 schema 同步更重要。
- 第一版直接实现 evaluator：暂不采用，先稳定 case schema 和目录边界。

## 验证方式

本决策落地后：

- 文档索引包含 benchmark/case harness 入口。
- `benchmarks/` 包含 README、case schema 说明和最小示例。
- 不提交完整外部 benchmark、大文件、缓存、真实凭据、敏感源码或攻击性 payload。
- `./scripts/check` 通过。

后续实现阶段：

- 增加 case loader。
- 增加 M1 sink generation evaluator。
- 引入 3 到 5 个 curated cases，覆盖 positive、negative、unsupported 和 blocked。
