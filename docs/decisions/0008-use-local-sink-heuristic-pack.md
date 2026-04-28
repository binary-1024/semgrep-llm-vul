# Decision: 使用本地内置 sink heuristic pack

## 背景

M1 sink generation pipeline 已经可以从 known sink、Semgrep finding、diff artifact 和漏洞片段中生成候选 sink，并保持证据优先、可测试和本地确定性。

当前危险调用识别仍依赖代码中的硬编码函数名列表。这个方式适合最小验证，但不适合继续扩展到更多语言、框架和漏洞类别。

## 决策

下一步使用本地内置 sink heuristic pack 替代散落的硬编码危险函数名。

第一版只做本地、确定性、可测试的内置规则对象，不引入外部规则文件、动态加载、远程规则源或插件系统。

规则对象至少表达：

- `name`：规则标识。
- `call_names`：精确匹配的危险调用末段或全名。
- `category`：漏洞或危险行为类别。
- `languages`：可选语言范围；为空表示语言无关启发式。
- `confidence`：候选证据置信度初值。
- `description`：规则命中的安全含义。

规则 pack 的职责：

- 为 diff、snippet、Semgrep finding 提供统一危险调用匹配来源。
- 为 evidence metadata 提供规则名和类别。
- 保持 candidate/evidence 语义，不直接输出 verified 结论。

规则 pack 不负责：

- 加载用户自定义规则。
- 下载或同步外部规则。
- 表达 source、sanitizer、propagator 或完整 taint spec。
- 替代 Semgrep、CodeQL、Joern 等专业分析工具。

## 影响

- sink 规则从硬编码函数名列表演进为可审查的本地规则集。
- diff、snippet、Semgrep finding 可以共享同一匹配逻辑。
- evidence metadata 可以携带规则名和类别，增强报告可解释性。
- 后续可以在 schema 稳定后再引入外部 YAML/JSON 规则或 provider 抽象。

## 备选方案

- 继续维护硬编码函数名列表：不采用，因为难以表达类别、语言范围、说明和置信度。
- 第一版直接读取外部 YAML/JSON 规则：暂不采用，因为会扩大加载、路径安全和错误处理边界。
- 第一版引入插件式 provider：暂不采用，因为当前只有一个本地 heuristic source。
- 根据 Semgrep `rule_id` 子串推断 sink：不采用，因为缺少代码调用证据，容易造成误判。

## 验证方式

后续 feature 分支至少添加或更新测试，覆盖：

- 规则 pack 命中后生成与当前行为兼容的 `SinkCandidate`。
- evidence metadata 包含规则名和类别。
- `safe_redirect`、`is_safe_redirect` 等安全封装不会因为子串包含危险词而误判。
- diff、snippet、Semgrep finding 共享同一匹配逻辑。
- `./scripts/check` 通过。
