"""命令行入口。"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from semgrep_llm_vul import __version__
from semgrep_llm_vul.analysis_input import AnalysisInputError, load_analysis_input


def main(argv: Sequence[str] | None = None) -> int:
    """运行项目 CLI。"""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-input":
        return _validate_input(args.path)

    parser.print_help()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="semgrep-llm-vul")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    validate_input = subparsers.add_parser(
        "validate-input",
        help="校验分析任务输入 YAML/JSON 文件",
    )
    validate_input.add_argument("path", help="分析任务输入文件路径")

    return parser


def _validate_input(path: str) -> int:
    try:
        task = load_analysis_input(path)
    except AnalysisInputError as exc:
        print(f"invalid analysis input: {exc}", file=sys.stderr)
        return 1

    print(
        "valid analysis input: "
        f"mode={task.mode.value} "
        f"repo={task.target.repo_url} "
        f"affected={task.target.affected_version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
