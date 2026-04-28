# Benchmark 与 Case 来源候选

本文档记录可用于后续采样的公开 benchmark、真实漏洞数据集和项目自建 case 来源。

当前阶段只记录来源、筛选价值和第一批采样方向；不下载、不提交完整外部数据集。

## 采样目标

benchmark/case harness 的目标不是追求一个总分，而是持续暴露能力边界：

- 能否从 patch、finding、代码片段中找到正确 sink。
- 能否避免把安全封装、规则名、描述关键词误判为 sink。
- 哪些 case 只适合 M1 candidate，哪些可以升级到 M2/M3/M4。
- 哪些失败应转化为 heuristic、fixture、测试或架构调整。

## 来源分层

| 来源 | 类型 | 价值 | 第一批采样方向 | 当前处理 |
| --- | --- | --- | --- | --- |
| [NIST SARD](https://www.nist.gov/itl/ssd/software-quality-group/samate/software-assurance-reference-dataset-sard) | synthetic_benchmark | 覆盖多语言、多 CWE，适合验证规则覆盖和 negative/positive 对照 | 只抽小型、单文件、sink 明确的 case | 记录来源，不下载全集 |
| [Juliet Test Suite](https://www.nist.gov/node/1656021) | synthetic_benchmark | SARD 中知名套件，C/C++、Java、C# 覆盖大量 CWE | Java 或 C/C++ 中 sink 明确、无复杂构建依赖的样例 | 记录来源，不下载全集 |
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | synthetic_benchmark | 面向 Web/SAST 工具评估，适合测试 scanner finding 与 sink generation 的衔接 | Java Web 中 XSS、SQLi、path traversal、command injection 小样例 | 记录来源，不下载全集 |
| [Vul4J](https://github.com/tuhh-softsec/vul4j) | real_vulnerability | 可复现 Java 真实漏洞，适合后续 M2/M3/M4 升级 | 先选 patch 小、sink 明确、测试可运行的 Java case | 记录来源，不自动 clone |
| [CVEfixes](https://github.com/secureIT-project/CVEfixes) | real_vulnerability | CVE、repo、commit、file、method 多层级信息，适合构造 patch/diff case | 从修复 commit 中抽取小 diff，标注 CVE 和许可证边界 | 记录来源，不下载数据库 |
| [PrimeVul](https://github.com/DLVulDet/PrimeVul) | real_vulnerability | 面向 code language model 的真实 C/C++ 漏洞检测数据集 | 暂作为参考来源，优先选择可回溯 repo/commit 的样例 | 记录来源，暂不作为首批 case |
| [DiverseVul](https://github.com/wagner-group/diversevul) | real_vulnerability | 大规模 C/C++ 函数级漏洞数据，适合观察模型/规则泛化边界 | 暂作为后续评估候选，避免第一批陷入大数据清洗 | 记录来源，暂不作为首批 case |

## 第一批 case 筛选标准

优先选择满足以下条件的样例：

- sink 能落到具体函数、方法或调用表达式。
- patch 或代码片段足够小，可以人工审查。
- 不需要联网、容器、服务编排或真实凭据即可作为 M1 case。
- 能明确标注 positive、negative、insufficient、blocked 或 unsupported。
- 可以解释当前系统预期通过或失败的原因。

暂缓选择以下样例：

- 需要完整项目构建或动态运行环境才能理解的 case。
- 只有漏洞描述、没有可回溯代码或 patch 的条目。
- 许可证、来源或裁剪方式不清楚的样例。
- 真实攻击 payload、敏感源码、私有仓库材料。

## 首批建议

第一批保持 3 到 5 个 curated/minimal case：

1. 已有 open redirect positive case：验证 diff -> `redirect` candidate。
2. 已有 safe wrapper negative case：验证 `safe_redirect` 不被子串误判。
3. 已有 insufficient evidence case：验证描述不能单独伪造 candidate。
4. 已有 OWASP Benchmark 风格 command injection distillation：验证 `exec/system/subprocess` 类 sink。
5. 已有 SARD/Juliet 风格 deserialization distillation：验证 `loads/deserialize` 类 sink。

当前两条外部 benchmark 风格 case 都是项目自写的最小 distillation，不是上游源码裁剪版。
这样可以先测试能力边界，同时避免把完整 benchmark、下载缓存或许可证边界不清的源码纳入仓库。

真实漏洞来源先以 intake case 记录边界：

- `vul4j-real-java-intake-blocked`：记录 Vul4J 需要选择具体 ID、隔离 checkout、compile/test 和 PoV 边界。
- `cvefixes-dataset-intake-unsupported`：记录 CVEfixes 需要先手工抽取小 patch，当前不直接导入完整数据库。

已加入一个真实 M1 patch 裁剪 case：

- `real-pypickle-cve-2025-5174-m1`：来源于公开 advisory 和修复 commit，验证 `pickle.load` 类 deserialization sink。

新增外部来源 case 时，每个 case 目录必须记录：

- 原始来源 URL。
- 许可证或使用边界。
- 是否为真实输出、真实输出裁剪版、还是合成近似结构。
- 裁剪了哪些内容。
- 当前只验证哪个阶段。
