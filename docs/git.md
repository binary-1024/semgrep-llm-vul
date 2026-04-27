# Git 管理

本文档定义 `semgrep-llm-vul` 的 Git 使用方式。目标是让每次变更都可审查、可验证、可回滚。

## 当前状态

当前目录尚未初始化为 Git 仓库。首次纳入版本管理时执行：

```bash
git init
git add .
git commit -m "chore: establish python uv project harness"
```

如果项目将推送到远程仓库，再补充 remote：

```bash
git remote add origin <remote-url>
git branch -M main
git push -u origin main
```

## 分支策略

长期分支：

- `main`：稳定主干，要求通过 `./scripts/check`。

任务分支：

- 功能：`codex/feature-<topic>`
- 修复：`codex/fix-<topic>`
- 重构：`codex/refactor-<topic>`
- 测试：`codex/test-<topic>`
- 文档：`codex/docs-<topic>`
- 工程配置：`codex/chore-<topic>`

示例：

```bash
git switch -c codex/feature-semgrep-json-parser
```

## 提交规范

提交信息使用 Conventional Commits 风格：

```text
feat: add semgrep json parser
fix: handle malformed semgrep result
test: cover finding normalization
docs: document git workflow
chore: configure uv mirrors
refactor: simplify parser errors
```

常用类型：

- `feat`：新增用户可见能力
- `fix`：修复缺陷
- `test`：新增或调整测试
- `docs`：文档变更
- `chore`：工具、依赖、构建、配置变更
- `refactor`：不改变外部行为的代码整理

每次提交应只表达一个明确意图。不要把功能实现、格式化、依赖升级和文档改写混在同一个提交里。

## 提交前检查

提交前至少运行：

```bash
./scripts/check
```

如果只改文档，也运行 `./scripts/check`，确保项目 harness 没有被破坏。

## 应提交的文件

通常应提交：

- 源码：`src/`
- 测试：`tests/`
- fixture：`fixtures/`
- 示例：`examples/`
- 文档：`README.md`、`AGENTS.md`、`docs/`
- 项目配置：`pyproject.toml`、`.python-version`、`uv.toml`
- 锁文件：`uv.lock`
- 脚本：`scripts/`
- CI 配置：`.github/workflows/`

`uv.lock` 应提交，用于保证依赖解析结果可复现。

## 不应提交的文件

不要提交：

- `.venv/`
- `dist/`
- `build/`
- `*.egg-info/`
- `.pytest_cache/`
- `.ruff_cache/`
- `__pycache__/`
- 本地密钥、令牌、扫描中的真实敏感源码或未脱敏漏洞数据

这些内容已在 `.gitignore` 中覆盖。若未来新增生成目录，需要同步更新 `.gitignore`。

## AI 协作规则

Codex 修改代码时遵循：

- 开始前先查看当前状态：`git status --short`。
- 不回滚用户已有改动，除非用户明确要求。
- 只修改当前任务相关文件。
- 提交前说明运行过哪些验证。
- 如果存在未验证项，必须明确写出。

## Review 要求

合并前重点检查：

- 是否满足任务验收标准
- diff 是否足够小且可读
- 是否有无关格式化或无关文件改动
- 是否更新了必要测试和文档
- 是否存在安全、隐私或凭据泄露风险
- `./scripts/check` 是否通过

## 推荐工作流

```bash
git switch main
git pull --ff-only
git switch -c codex/feature-semgrep-json-parser

# 实现任务
./scripts/check

git status --short
git add <changed-files>
git commit -m "feat: add semgrep json parser"
```

如果没有远程仓库或还没有多人协作，仍然建议使用任务分支和小提交。这样即使是本地开发，也能保持清晰历史和可回滚边界。
