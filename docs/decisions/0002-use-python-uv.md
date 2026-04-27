# Decision: 使用 Python 3.10 与 uv 管理项目

## 背景

项目需要处理 Semgrep JSON 输出、实现 CLI、维护测试 fixture，并为后续 LLM 分析工作流打基础。

## 决策

项目使用 Python 3.10 系列实现，并使用 `uv` 管理：

- Python 版本
- 虚拟环境
- 依赖
- 测试命令
- 构建命令

项目版本约束写入 `pyproject.toml`：

```toml
requires-python = ">=3.10,<3.11"
```

本地版本提示写入 `.python-version`：

```text
3.10
```

项目级 `uv.toml` 配置国内镜像：

```toml
python-install-mirror = "https://mirror.nju.edu.cn/github-release/astral-sh/python-build-standalone/"

[[index]]
url = "https://pypi.tuna.tsinghua.edu.cn/simple"
default = true
```

## 影响

- 后续源码放在 `src/semgrep_llm_vul/`。
- 测试使用 `pytest`。
- 静态检查使用 `ruff`。
- 统一验证入口仍然是 `./scripts/check`。

## 备选方案

- TypeScript：适合前端或 Node 服务，但当前项目更偏 CLI、JSON 处理和分析流程，Python 启动成本更低。
- Rust：性能和分发体验好，但当前阶段会增加实现和迭代成本。
- 系统 Python + pip：不采用，因为虚拟环境和版本约束不如 `uv` 统一。
