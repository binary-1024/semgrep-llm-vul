# vul4j-real-java-intake-blocked

## 背景

这个 case 不是可执行样例，而是一个真实漏洞来源的 intake 占位，用于记录当前
worktree 对 Vul4J 的边界：Vul4J 适合后续验证真实 Java 漏洞、PoV 和修复前后行为，
但当前阶段不应自动 checkout、compile 或 reproduce。

## 来源

- 来源类型：`real_vulnerability`
- 原始来源：[Vul4J](https://github.com/tuhh-softsec/vul4j)
- 上游说明：Vul4J 提供真实 Java 漏洞、人类补丁、PoV test case 和复现支持框架。
- 许可证：dataset 为 CC-BY-4.0，code 为 GPL-3.0。
- fixture 类型：blocked intake，占位记录，不包含上游源码。

## 当前阻塞

- 尚未选择具体 Vul4J ID。
- 需要隔离目录 checkout 目标项目。
- 需要确认编译、测试和 PoV 运行边界。
- 部分 Vul4J case 可能因为依赖老旧而不可复现，需要先做状态筛选。

## 后续升级

选定具体 Vul4J ID 后，先升级为 M1/M2 case，只裁剪 patch 和 sink 证据；确认隔离运行
边界后再进入 M3 triggerable 或 M4 verified。
