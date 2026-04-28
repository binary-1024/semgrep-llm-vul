# curated-insufficient-evidence

## 背景

这个 case 验证证据不足时，M1 sink generation 不应仅凭自然语言描述伪造候选 sink。

## 关键证据

- 输入只有漏洞描述、目标 repo 和版本。
- 没有 diff、Semgrep finding、代码片段或用户提供 sink。

## 已知失败模式

如果后续接入 LLM 或更激进的 description heuristic，可能会凭描述生成无证据候选。

## 后续升级

保持为 M1 insufficient evidence 回归样例。
