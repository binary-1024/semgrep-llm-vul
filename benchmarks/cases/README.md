# Cases

本目录按 case 组织 benchmark/case harness。

## Case 目录结构

```text
<case-id>/
  case.yaml
  expected.json
  notes.md
```

新增 case 时可从 `../templates/` 复制 `case.yaml`、`expected.json` 和 `notes.md`，
再替换所有 `replace-with-*` 占位内容。

## case.yaml 字段

```yaml
schema_version: 1
id: curated-open-redirect-safe-wrapper
type: curated_minimal
target_stage: M1
status: candidate
source:
  name: project-curated
  url: null
  license: project
target:
  repo_url: https://github.com/example/flask-app
  affected_version: v1.0.0
  fixed_version: v1.0.1
  language: python
inputs:
  description: Open redirect through user-controlled next parameter.
  mode: unknown_sink
  artifacts:
    - kind: diff
      path: fixtures/sink/open-redirect-fix.diff
expected:
  sink:
    name: redirect
    location:
      path: app/routes.py
      start_line: 9
safety:
  contains_poc: false
  contains_exp: false
  requires_isolation: false
```

字段约束：

- `schema_version` 当前必须是 `1`。
- `type` 只能是 `curated_minimal`、`synthetic_benchmark` 或 `real_vulnerability`。
- `target_stage` 只能是 `M1`、`M2`、`M3` 或 `M4`。
- `status` 只能是 `candidate`、`blocked` 或 `unsupported`。
- `source.name` 和 `source.license` 必填；`source.url` 可以为 `null`。
- `safety.contains_poc`、`safety.contains_exp`、`safety.requires_isolation` 必须是 bool。

## expected.json 字段

`expected.json` 用于描述当前阶段的机器可比较期望。M1 case 使用
`sink_candidates` 和 `must_not_include`：

```json
{
  "schema_version": 1,
  "stage": "M1",
  "expected_status": "candidate",
  "sink_candidates": [
    {
      "name": "redirect",
      "path": "app/routes.py",
      "start_line": 9,
      "heuristic_category": "open_redirect"
    }
  ],
  "must_not_include": [
    {
      "name": "safe_redirect"
    }
  ]
}
```

字段约束：

- `schema_version` 当前必须是 `1`。
- `stage` 只能是 `M1`、`M2`、`M3` 或 `M4`。
- `expected_status` 只能是 `candidate`、`blocked` 或 `unsupported`。
- `sink_candidates` 和 `must_not_include` 必须是 object list。

M2 taint path case 使用 `inputs.semgrep_json` 指向本地 Semgrep JSON fixture，并在
`expected.json` 中使用 `taint_paths` 描述期望的 source、sink、step roles 和
candidate path 的 `reachable` 状态。

M2 reachability case 可以额外使用 `inputs.reachability_json` 指向本地
reachability evidence fixture，并在 `expected.json` 中使用 `reachability` 描述期望的
`reachable=true|false|null`、入口类型或阻断因素。

也可以使用 `inputs.source_roots` 指向本地源码 fixture。当前最小实现会从 Python
源码中提取 Flask `@*.route(...)` 入口证据，并尝试将入口所在 handler 与候选
taint path 对齐。当前还支持同文件、一层 direct helper call chain：如果 route
handler 直接调用同文件 helper，且 sink 位于 helper 函数体内，也可以输出
`reachable=true`。
当前还支持 direct import 的跨文件 helper call chain：如果 route handler 直接调用
另一个 Python 文件中导入的 helper，且 sink 位于该 helper 函数体内，也可以输出
`reachable=true`。
当前还支持 module alias attribute call：如果 route handler 通过
`import app.helpers as helpers` 之类的 alias 调用 `helpers.issue_redirect(...)`，且
sink 位于该 helper 函数体内，也可以输出 `reachable=true`。
当前还支持 `from app import helpers` 这类 `ImportFrom` module attribute call：如果
route handler 通过导入的 module 名调用 `helpers.issue_redirect(...)`，且 sink 位于
该 helper 函数体内，也可以输出 `reachable=true`。
当前也显式回归 `from app import helpers as h` 这类 `ImportFrom` module alias
attribute call：如果 route handler 通过导入别名调用 `h.issue_redirect(...)`，且
sink 位于该 helper 函数体内，也可以输出 `reachable=true`。
当前仍然**不**支持普通 assignment alias，例如 `alias = h; alias.issue_redirect(...)`。
这类场景即使存在 source root，也必须继续保持 `reachable=null`，直到我们单独引入更强的
调用关系抽象。
当前还支持有界多层 helper chain：如果 route handler 先调用同文件 helper，再由该
helper 继续进入第二层 helper，且 sink 位于该第二层 helper 函数体内，也可以输出
`reachable=true`。当前边界固定为最多两层 helper hop。

## notes.md 内容

`notes.md` 至少记录：

- 背景。
- 为什么选择这个 case。
- 关键证据。
- 当前已知失败模式。
- 后续是否可升级到 M2/M3/M4。

## 命名规则

case id 使用小写 kebab-case：

```text
<source>-<cwe-or-category>-<short-name>
```

示例：

- `curated-open-redirect-safe-wrapper`
- `curated-command-execution-system`
- `curated-deserialization-deserialize`
- `curated-open-redirect-safe-negative`
- `curated-open-redirect-taint-path`
- `vul4j-command-injection-example`
- `owasp-benchmark-xss-sample`

## 当前 curated cases

- `curated-open-redirect-safe-wrapper`：positive case，期望从 diff 中生成 `redirect` candidate，同时不包含安全封装名。
- `curated-open-redirect-taint-path`：M2 taint path candidate case，验证 Semgrep trace 与 `redirect` sink candidate 对齐。
- `curated-open-redirect-reachability`：M2 reachability positive case，验证本地入口证据可以输出 `reachable=true`。
- `curated-open-redirect-reachability-blocked`：M2 reachability blocked case，验证明确阻断因素可以输出 `reachable=false`。
- `curated-open-redirect-reachability-cross-file-helper`：M2 reachability cross-file helper case，验证 route handler 直接调用导入的 helper 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-alias-assignment-unknown`：M2 reachability negative case，验证 route handler 通过 assignment alias 调用 helper 时继续保持 `reachable=null`。
- `curated-open-redirect-reachability-from-import-alias-helper`：M2 reachability from-import alias helper case，验证 route handler 通过 `from app import helpers as h` 的 module alias 调用 helper 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-from-import-helper`：M2 reachability from-import helper case，验证 route handler 通过 `from app import helpers` 的 module import 调用 helper 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-helper`：M2 reachability helper call chain case，验证 route handler 直接调用同文件 helper 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-import-alias-helper`：M2 reachability import alias helper case，验证 route handler 通过 module alias attribute call 调用 helper 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-multi-layer-helper`：M2 reachability multi-layer helper case，验证 route handler 通过同文件两层 helper chain 调用 sink 时可以输出 `reachable=true`。
- `curated-open-redirect-reachability-unknown`：M2 reachability unknown case，验证缺入口证据时保持 `reachable=null`。
- `curated-open-redirect-safe-diff`：negative case，安全封装 diff 不应生成 direct sink candidate。
- `curated-insufficient-evidence`：insufficient evidence case，没有代码、diff 或 Semgrep 证据时不应生成候选。
- `curated-safe-deserialization-wrapper`：negative case，`safe_loads` 不应误判为 `loads`。
- `curated-safe-executor-submit`：negative case，`executor.submit` 不应误判为 `exec`。
- `owasp-benchmark-command-injection-distilled`：OWASP Benchmark 风格 command injection distillation，验证 `exec` sink。
- `sard-juliet-deserialization-distilled`：SARD/Juliet 风格 deserialization distillation，验证 `loads` sink。
- `real-pypickle-cve-2025-5174-m1`：真实 CVE patch 裁剪 case，验证 `pickle.load` deserialization sink。
- `vul4j-real-java-intake-blocked`：真实 Java 漏洞来源 intake，占位记录 Vul4J case 需要隔离 checkout/compile/PoV。
- `cvefixes-dataset-intake-unsupported`：真实漏洞数据集 intake，占位记录当前不支持直接导入 CVEfixes 数据库。
