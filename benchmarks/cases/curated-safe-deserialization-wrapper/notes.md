# curated-safe-deserialization-wrapper

## 背景

这个 negative case 验证 `safe_loads(...)` 不应因为名称中包含 `loads` 就被识别为
unsafe deserialization sink。

## 关键证据

- 输入 artifact：`fixtures/sink/safe-deserialization-fix.diff`
- 期望：不生成 `loads` 或 `safe_loads` candidate。
- 新增行使用 `safe_json_parse(...)`，避免把本 case 变成对 `json.loads` 是否危险的策略判断。

## 已知失败模式

如果 sink heuristic 退化为子串匹配，`safe_loads` 会被误判。

## 后续升级

后续可以增加真正的 Java `ObjectInputStream.readObject(...)` positive case，与该
negative case 形成对照。
