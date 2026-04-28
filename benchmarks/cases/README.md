# Cases

本目录按 case 组织 benchmark/case harness。

## Case 目录结构

```text
<case-id>/
  case.yaml
  expected.json
  notes.md
```

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

## expected.json 字段

`expected.json` 用于描述当前阶段的机器可比较期望。第一版优先覆盖 M1：

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
- `vul4j-command-injection-example`
- `owasp-benchmark-xss-sample`
