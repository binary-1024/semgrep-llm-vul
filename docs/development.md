# 开发

## 工作流

以项目管理规范作为流程来源：

1. 理解目标。
2. 阅读相关文件。
3. 确认实现边界。
4. 制定简短计划。
5. 实施范围内变更。
6. 运行验证命令。
7. 修复失败项。
8. 总结变更、验证结果和风险。

## 任务模板

```md
## 任务

## 背景

## 范围

## 非目标

## 验收标准

## 风险

## 验证
```

## 本地命令

项目使用 Python 3.10 系列，并通过 `uv` 管理虚拟环境和依赖：

```bash
uv sync --dev
uv run python --version
```

项目内 `uv.toml` 已配置国内镜像：

- `[[index]]` 使用清华 PyPI 镜像，并设置为默认 index。
- `python-install-mirror` 使用 NJU 的 `python-build-standalone` GitHub Release 镜像。

常用检查命令：

```bash
./scripts/check
./scripts/test
./scripts/lint
./scripts/build
```

`./scripts/check` 会依次运行 lint、测试和构建。

## Python 项目约定

- 源码放在 `src/semgrep_llm_vul/`。
- 测试放在 `tests/`。
- fixture 放在 `fixtures/`。
- 使用 `ruff` 做静态检查。
- 使用 `pytest` 做测试。
- 使用 `uv build` 验证包构建。
- 项目 Python 版本约束为 `>=3.10,<3.11`。
