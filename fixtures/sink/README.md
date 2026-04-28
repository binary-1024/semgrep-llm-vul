# Sink Generation Fixtures

本目录存放 M1 sink generation pipeline 的 fixture。

## 类型

- `known_sink`：用户已提供 sink signature，pipeline 应生成高优先级候选。
- `unknown_with_diff`：未知 sink，通过本地 diff artifact 提供候选证据。
- `unknown_with_semgrep`：未知 sink，通过 `NormalizedFinding` 提供候选证据。
- `insufficient`：证据不足时，不应伪造高置信推荐。
- `malformed`：证据结构存在问题时，应给出结构化错误。

## 规则

- fixture 必须离线、确定性、可提交。
- Semgrep finding 只能作为候选证据，不等同最终漏洞结论。
- diff fixture 是合成的最小修复线索，用于验证 pipeline 边界，不代表真实项目 patch。
