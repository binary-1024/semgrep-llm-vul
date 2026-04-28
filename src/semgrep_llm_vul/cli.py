"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from semgrep_llm_vul import __version__
from semgrep_llm_vul.analysis_input import AnalysisInputError, load_analysis_input
from semgrep_llm_vul.reporting import sink_generation_report_to_dict
from semgrep_llm_vul.semgrep import SemgrepParseError, load_semgrep_findings
from semgrep_llm_vul.sink_generation import SinkGenerationError, generate_sink_report


def main(argv: Sequence[str] | None = None) -> int:
    """运行项目 CLI。"""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-input":
        return _validate_input(args.path)
    if args.command == "generate-sinks":
        return _generate_sinks(
            args.path,
            semgrep_json=args.semgrep_json,
            artifact_base=args.artifact_base,
        )

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

    generate_sinks = subparsers.add_parser(
        "generate-sinks",
        help="生成 sink candidate JSON 报告",
    )
    generate_sinks.add_argument("path", help="分析任务输入文件路径")
    generate_sinks.add_argument(
        "--semgrep-json",
        action="append",
        default=[],
        help="可选 Semgrep JSON 结果路径，可重复传入",
    )
    generate_sinks.add_argument(
        "--artifact-base",
        default=None,
        help="解析本地 artifact 相对路径时使用的基准目录",
    )

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


def _generate_sinks(
    path: str,
    *,
    semgrep_json: Sequence[str],
    artifact_base: str | None,
) -> int:
    try:
        task = load_analysis_input(path)
        findings = tuple(
            finding
            for result_path in semgrep_json
            for finding in load_semgrep_findings(Path(result_path))
        )
        report = generate_sink_report(
            task,
            semgrep_findings=findings,
            artifact_base=artifact_base,
        )
    except (AnalysisInputError, SemgrepParseError, SinkGenerationError) as exc:
        print(f"generate sinks failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            sink_generation_report_to_dict(report, task=task),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
