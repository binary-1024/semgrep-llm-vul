# semgrep-llm-vul

围绕 Semgrep findings 和 LLM 审查工作流构建的 AI 辅助漏洞分析项目。

当前仓库处于 Python/uv 基础工程阶段。第一目标是在加入业务逻辑前，让后续开发过程可观察、可测试、可审查。

## 项目状态

- 阶段：Python/uv 基础工程
- 主要规范：`项目开发管理规范.md`
- 技术栈：Python 3.10 系列，使用 `uv` 管理虚拟环境、依赖和构建
- 当前重点：Semgrep JSON 解析任务前的工程基础

## 仓库结构

```text
.
├── AGENTS.md
├── README.md
├── docs/
│   ├── architecture.md
│   ├── development.md
│   ├── git.md
│   ├── testing.md
│   └── decisions/
├── scripts/
│   ├── build
│   ├── check
│   ├── lint
│   └── test
├── src/
│   └── semgrep_llm_vul/
├── tests/
├── examples/
├── fixtures/
└── .github/
    └── workflows/
```

## 常用命令

```bash
./scripts/check
./scripts/test
./scripts/lint
./scripts/build
```

这些脚本通过 `uv` 执行：

- `./scripts/test` 运行 `pytest`
- `./scripts/lint` 运行 `ruff check .`
- `./scripts/build` 运行 `uv build`
- `./scripts/check` 依次运行 lint、test 和 build

## 项目文档

- [架构说明](docs/architecture.md)
- [开发流程](docs/development.md)
- [Git 管理](docs/git.md)
- [测试策略](docs/testing.md)
- [决策记录](docs/decisions/)

## Python 环境

项目使用 Python 3.10 系列：

```bash
uv sync --dev
uv run python --version
```

`.python-version` 和 `pyproject.toml` 会共同约束项目 Python 版本。

`uv.toml` 已配置国内镜像：

- Python 包索引：清华 PyPI 镜像
- Python 解释器下载：NJU `python-build-standalone` GitHub Release 镜像

## 沟通与文档语言

项目文档、任务说明、交付总结以及 Codex 与用户沟通默认使用中文。

文件名、命令、API 名、日志、第三方输出以及必要技术术语可以保留英文。

## 下一步

1. 定义 Semgrep JSON 基础解析与归一化任务。
2. 添加代表性的 `fixtures/` 样例。
3. 实现解析模块和测试。
4. 当解析流程稳定后，补充 CI。
