# sard-juliet-deserialization-distilled

## 背景

这个 case 用项目自写的最小 diff 表达 SARD/Juliet 风格 CWE 样例的用途：
用小型、可审查程序覆盖明确 weakness 类别。当前样例聚焦 unsafe
deserialization sink。

没有复制 NIST SARD 或 Juliet 源码，也没有下载完整测试套件。

## 来源

- 来源类型：`synthetic_benchmark`
- 原始来源：[NIST SARD](https://www.nist.gov/itl/ssd/software-quality-group/samate/software-assurance-reference-dataset-sard)
- Juliet 描述参考：[SARD Acknowledgments and Test Suites Descriptions](https://www.nist.gov/node/1656021)
- fixture 类型：合成的项目内 distillation，不是上游源码裁剪版。
- 许可证：使用上游材料前需再确认；当前 fixture 为项目自写最小样例。

## 关键证据

- 输入 artifact：`fixtures/sink/benchmark-deserialization-fix.diff`
- 期望：生成 `loads` candidate，类别为 `deserialization`。

## 当前验证边界

只验证 M1 sink candidate extraction，不验证 source、taint path、PoC 或 exp。

## 已知失败模式

如果后续只支持 Java deserialization API，本 Python `pickle.loads` 样例不能代表
Juliet Java；届时应新增 Java `ObjectInputStream.readObject` 类 case。
