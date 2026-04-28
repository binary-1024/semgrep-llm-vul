# cvefixes-dataset-intake-unsupported

## 背景

这个 case 记录 CVEfixes 作为真实漏洞来源的边界。CVEfixes 很适合后续抽取
CVE、repo、commit、file 和 method 级别信息来构造 patch case，但当前 harness
不支持直接下载或读取完整数据库。

## 来源

- 来源类型：`real_vulnerability`
- 原始来源：[CVEfixes](https://github.com/secureIT-project/CVEfixes)
- 上游说明：CVEfixes 从 NVD CVE 记录自动收集开源项目漏洞及修复，提供 commit、
  file、method、repo 和 CVE 等多层级信息。
- fixture 类型：unsupported intake，占位记录，不包含上游数据库。

## 当前不支持

- 不下载 Zenodo 数据库。
- 不在本地直接执行数据库导入。
- 不把大规模自动采集样本直接纳入 M1 evaluator。

## 后续升级

先从 CVEfixes 中手工选择一个来源清楚、patch 小、sink 明确的 CVE，裁剪成
`real_vulnerability` M1 diff case，再考虑自动化 ingestion。
