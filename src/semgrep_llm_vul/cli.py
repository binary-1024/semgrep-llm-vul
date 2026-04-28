"""命令行入口。"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from semgrep_llm_vul import __version__
from semgrep_llm_vul.analysis_input import AnalysisInputError, load_analysis_input
from semgrep_llm_vul.benchmark import (
    BenchmarkCaseError as BenchmarkInventoryError,
)
from semgrep_llm_vul.benchmark import (
    benchmark_cases_to_dict,
    benchmark_evaluations_to_dict,
    discover_benchmark_cases,
)
from semgrep_llm_vul.benchmark import (
    evaluate_benchmark_case as evaluate_benchmark_inventory_case,
)
from semgrep_llm_vul.benchmark_cases import (
    BenchmarkCaseError,
    evaluate_benchmark_case,
    evaluate_benchmark_cases,
    summarize_benchmark_suite,
)
from semgrep_llm_vul.reachability import (
    ReachabilityEvidenceError,
    discover_flask_route_evidence,
    generate_reachability_report,
    load_reachability_evidence,
)
from semgrep_llm_vul.reporting import (
    reachability_report_to_dict,
    sink_generation_report_to_dict,
    taint_path_generation_report_to_dict,
)
from semgrep_llm_vul.semgrep import (
    SemgrepParseError,
    load_semgrep_findings,
    load_semgrep_taint_paths,
)
from semgrep_llm_vul.sink_generation import SinkGenerationError, generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report


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
    if args.command == "generate-taint-paths":
        return _generate_taint_paths(
            args.path,
            semgrep_json=args.semgrep_json,
            artifact_base=args.artifact_base,
        )
    if args.command == "confirm-reachability":
        return _confirm_reachability(
            args.path,
            semgrep_json=args.semgrep_json,
            reachability_json=args.reachability_json,
            source_root=args.source_root,
            artifact_base=args.artifact_base,
        )
    if args.command == "evaluate-case":
        return _evaluate_case(args.path, repo_root=args.repo_root)
    if args.command == "evaluate-cases":
        return _evaluate_cases(
            args.path,
            repo_root=args.repo_root,
            summary_only=args.summary_only,
        )
    if args.command == "evaluate-benchmarks":
        return _evaluate_benchmarks(
            args.path,
            artifact_base=args.artifact_base,
            include_reports=args.include_reports,
        )
    if args.command == "validate-benchmarks":
        return _validate_benchmarks(args.path)
    if args.command == "benchmark-summary":
        return _benchmark_summary(
            args.path,
            artifact_base=args.artifact_base,
            repo_root=args.repo_root,
        )
    if args.command == "benchmark-baseline":
        return _benchmark_baseline(
            args.path,
            artifact_base=args.artifact_base,
            repo_root=args.repo_root,
            markdown=args.markdown,
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

    generate_taint_paths = subparsers.add_parser(
        "generate-taint-paths",
        help="生成 taint path candidate JSON 报告",
    )
    generate_taint_paths.add_argument("path", help="分析任务输入文件路径")
    generate_taint_paths.add_argument(
        "--semgrep-json",
        action="append",
        default=[],
        help="Semgrep JSON 结果路径，可重复传入",
    )
    generate_taint_paths.add_argument(
        "--artifact-base",
        default=None,
        help="解析本地 artifact 相对路径时使用的基准目录",
    )

    confirm_reachability = subparsers.add_parser(
        "confirm-reachability",
        help="基于本地证据生成 reachability JSON 报告",
    )
    confirm_reachability.add_argument("path", help="分析任务输入文件路径")
    confirm_reachability.add_argument(
        "--semgrep-json",
        action="append",
        default=[],
        help="Semgrep JSON 结果路径，可重复传入",
    )
    confirm_reachability.add_argument(
        "--reachability-json",
        action="append",
        default=[],
        help="本地 reachability evidence JSON 路径，可重复传入",
    )
    confirm_reachability.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="用于提取最小入口证据的本地源码根目录，可重复传入",
    )
    confirm_reachability.add_argument(
        "--artifact-base",
        default=None,
        help="解析本地 artifact 相对路径时使用的基准目录",
    )

    evaluate_case = subparsers.add_parser(
        "evaluate-case",
        help="评估 benchmark case 的阶段期望",
    )
    evaluate_case.add_argument("path", help="benchmark case 目录路径")
    evaluate_case.add_argument(
        "--repo-root",
        default=None,
        help="解析 case 内本地 artifact 相对路径时使用的仓库根目录",
    )

    evaluate_cases = subparsers.add_parser(
        "evaluate-cases",
        help="批量评估 benchmark cases 的阶段期望",
    )
    evaluate_cases.add_argument("path", help="benchmark cases 根目录路径")
    evaluate_cases.add_argument(
        "--repo-root",
        default=None,
        help="解析 cases 内本地 artifact 相对路径时使用的仓库根目录",
    )
    evaluate_cases.add_argument(
        "--summary-only",
        action="store_true",
        help="仅输出 suite 摘要，不包含每个 case 的完整 sink_report",
    )

    evaluate_benchmarks = subparsers.add_parser(
        "evaluate-benchmarks",
        help="执行 benchmark/case harness 的 inventory evaluator",
    )
    evaluate_benchmarks.add_argument(
        "path",
        nargs="?",
        default="benchmarks/cases",
        help="case 目录或 cases 根目录，默认 benchmarks/cases",
    )
    evaluate_benchmarks.add_argument(
        "--artifact-base",
        default=None,
        help="解析本地 artifact 相对路径时使用的基准目录",
    )
    evaluate_benchmarks.add_argument(
        "--include-reports",
        action="store_true",
        help="在输出中包含每个 case 的 sink generation report",
    )

    validate_benchmarks = subparsers.add_parser(
        "validate-benchmarks",
        help="校验 benchmark/case 目录并输出 inventory",
    )
    validate_benchmarks.add_argument(
        "path",
        nargs="?",
        default="benchmarks/cases",
        help="case 目录或 cases 根目录，默认 benchmarks/cases",
    )

    benchmark_summary = subparsers.add_parser(
        "benchmark-summary",
        help="输出 benchmark/case harness 的短摘要",
    )
    benchmark_summary.add_argument(
        "path",
        nargs="?",
        default="benchmarks/cases",
        help="case 目录或 cases 根目录，默认 benchmarks/cases",
    )
    benchmark_summary.add_argument(
        "--artifact-base",
        default=None,
        help="解析 inventory evaluator 本地 artifact 相对路径时使用的基准目录",
    )
    benchmark_summary.add_argument(
        "--repo-root",
        default=None,
        help="解析 executable suite 本地 artifact 相对路径时使用的仓库根目录",
    )

    benchmark_baseline = subparsers.add_parser(
        "benchmark-baseline",
        help="生成 benchmark baseline 文档片段",
    )
    benchmark_baseline.add_argument(
        "path",
        nargs="?",
        default="benchmarks/cases",
        help="case 目录或 cases 根目录，默认 benchmarks/cases",
    )
    benchmark_baseline.add_argument(
        "--artifact-base",
        default=None,
        help="解析 inventory evaluator 本地 artifact 相对路径时使用的基准目录",
    )
    benchmark_baseline.add_argument(
        "--repo-root",
        default=None,
        help="解析 executable suite 本地 artifact 相对路径时使用的仓库根目录",
    )
    benchmark_baseline.add_argument(
        "--markdown",
        action="store_true",
        help="输出 Markdown baseline，而不是 JSON",
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


def _evaluate_case(path: str, *, repo_root: str | None) -> int:
    try:
        result = evaluate_benchmark_case(path, repo_root=repo_root)
    except (BenchmarkCaseError, SinkGenerationError) as exc:
        print(f"evaluate case failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def _evaluate_cases(path: str, *, repo_root: str | None, summary_only: bool) -> int:
    try:
        result = evaluate_benchmark_cases(path, repo_root=repo_root)
    except (BenchmarkCaseError, SinkGenerationError) as exc:
        print(f"evaluate cases failed: {exc}", file=sys.stderr)
        return 1

    if summary_only:
        result = summarize_benchmark_suite(result)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


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


def _generate_taint_paths(
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
        taint_paths = tuple(
            taint_path
            for result_path in semgrep_json
            for taint_path in load_semgrep_taint_paths(Path(result_path))
        )
        sink_report = generate_sink_report(
            task,
            semgrep_findings=findings,
            artifact_base=artifact_base,
        )
        report = generate_taint_path_report(
            task,
            sink_report=sink_report,
            semgrep_taint_paths=taint_paths,
        )
    except (AnalysisInputError, SemgrepParseError, SinkGenerationError) as exc:
        print(f"generate taint paths failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            taint_path_generation_report_to_dict(report, task=task),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _confirm_reachability(
    path: str,
    *,
    semgrep_json: Sequence[str],
    reachability_json: Sequence[str],
    source_root: Sequence[str],
    artifact_base: str | None,
) -> int:
    try:
        task = load_analysis_input(path)
        findings = tuple(
            finding
            for result_path in semgrep_json
            for finding in load_semgrep_findings(Path(result_path))
        )
        taint_paths = tuple(
            taint_path
            for result_path in semgrep_json
            for taint_path in load_semgrep_taint_paths(Path(result_path))
        )
        evidence_records = tuple(
            record
            for evidence_path in reachability_json
            for record in load_reachability_evidence(Path(evidence_path))
        ) + tuple(
            record
            for root in source_root
            for record in discover_flask_route_evidence(
                Path(root),
                taint_paths=taint_paths,
            )
        )
        sink_report = generate_sink_report(
            task,
            semgrep_findings=findings,
            artifact_base=artifact_base,
        )
        taint_report = generate_taint_path_report(
            task,
            sink_report=sink_report,
            semgrep_taint_paths=taint_paths,
        )
        report = generate_reachability_report(
            task,
            taint_report=taint_report,
            evidence_records=evidence_records,
        )
    except (
        AnalysisInputError,
        ReachabilityEvidenceError,
        SemgrepParseError,
        SinkGenerationError,
    ) as exc:
        print(f"confirm reachability failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            reachability_report_to_dict(report, task=task),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _evaluate_benchmarks(
    path: str,
    *,
    artifact_base: str | None,
    include_reports: bool,
) -> int:
    try:
        cases = discover_benchmark_cases(path)
        evaluations = tuple(
            evaluate_benchmark_inventory_case(case, artifact_base=artifact_base)
            for case in cases
        )
    except BenchmarkInventoryError as exc:
        print(f"evaluate benchmarks failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            benchmark_evaluations_to_dict(
                evaluations,
                include_reports=include_reports,
                cases=cases,
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if any(item.outcome in {"failed", "error"} for item in evaluations) else 0


def _validate_benchmarks(path: str) -> int:
    try:
        cases = discover_benchmark_cases(path)
    except BenchmarkInventoryError as exc:
        print(f"validate benchmarks failed: {exc}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            benchmark_cases_to_dict(cases),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _benchmark_summary(
    path: str,
    *,
    artifact_base: str | None,
    repo_root: str | None,
) -> int:
    try:
        summary = _benchmark_summary_data(
            path,
            artifact_base=artifact_base,
            repo_root=repo_root,
        )
    except (BenchmarkCaseError, BenchmarkInventoryError, SinkGenerationError) as exc:
        print(f"benchmark summary failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def _benchmark_baseline(
    path: str,
    *,
    artifact_base: str | None,
    repo_root: str | None,
    markdown: bool,
) -> int:
    try:
        summary = _benchmark_summary_data(
            path,
            artifact_base=artifact_base,
            repo_root=repo_root,
        )
    except (BenchmarkCaseError, BenchmarkInventoryError, SinkGenerationError) as exc:
        print(f"benchmark baseline failed: {exc}", file=sys.stderr)
        return 1

    if markdown:
        print(_benchmark_baseline_markdown(summary))
    else:
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


def _benchmark_summary_data(
    path: str,
    *,
    artifact_base: str | None,
    repo_root: str | None,
) -> dict[str, object]:
    inventory_cases = discover_benchmark_cases(path)
    inventory = benchmark_cases_to_dict(inventory_cases)
    evaluations = tuple(
        evaluate_benchmark_inventory_case(case, artifact_base=artifact_base)
        for case in inventory_cases
    )
    evaluation = benchmark_evaluations_to_dict(evaluations, cases=inventory_cases)
    executable = summarize_benchmark_suite(
        evaluate_benchmark_cases(path, repo_root=repo_root)
    )
    passed = (
        evaluation["summary"]["failed"] == 0
        and evaluation["summary"]["error"] == 0
        and executable["passed"]
    )
    return {
        "schema_version": 2,
        "kind": "benchmark_summary",
        "passed": passed,
        "known_limitations": [
            (
                "inventory_evaluation 当前只评估 M1 sink generation inventory/gap；"
                "M2 pass/fail 以 executable_suite 为准。"
            )
        ],
        "inventory": {
            "scope": "case inventory, source coverage, declared status, and stage coverage",
            "summary": inventory["summary"],
            "coverage": inventory["coverage"],
        },
        "inventory_evaluation": {
            "scope": "M1 sink generation inventory/gap evaluation",
            "summary": evaluation["summary"],
            "gaps": evaluation["gaps"],
        },
        "executable_suite": {
            "scope": "M1/M2 staged executable case checks",
            "total": executable["total"],
            "passed": executable["passed"],
            "passed_count": executable["passed_count"],
            "failed_count": executable["failed_count"],
        },
    }


def _benchmark_baseline_markdown(summary: dict[str, object]) -> str:
    inventory = summary["inventory"]
    evaluation = summary["inventory_evaluation"]
    executable = summary["executable_suite"]
    inventory_summary = inventory["summary"]
    coverage = inventory["coverage"]
    evaluation_summary = evaluation["summary"]
    lines = [
        "# Benchmark Baseline",
        "",
        "## Inventory",
        "",
        "| 维度 | 数量 |",
        "| --- | ---: |",
        *_summary_rows(inventory_summary, ("total", "candidate", "unsupported", "blocked")),
        "",
        "### 按阶段",
        "",
        "| 阶段 | 数量 |",
        "| --- | ---: |",
        *_mapping_rows(coverage["by_stage"]),
        "",
        "### 按类型",
        "",
        "| 类型 | 数量 |",
        "| --- | ---: |",
        *_mapping_rows(coverage["by_type"]),
        "",
        "## Inventory Evaluation",
        "",
        str(evaluation["scope"]),
        "",
        "| outcome | 数量 |",
        "| --- | ---: |",
        *_summary_rows(
            evaluation_summary,
            ("passed", "unsupported", "blocked", "failed", "error", "total"),
        ),
        "",
        "## Gaps",
        "",
        "| case | code | 说明 |",
        "| --- | --- | --- |",
        *_gap_rows(evaluation["gaps"]),
        "",
        "## Executable Suite",
        "",
        str(executable["scope"]),
        "",
        "| 指标 | 数量 |",
        "| --- | ---: |",
        f"| total | {executable['total']} |",
        f"| passed_count | {executable['passed_count']} |",
        f"| failed_count | {executable['failed_count']} |",
        "",
        "## Known Limitations",
        "",
        *_known_limitation_rows(summary["known_limitations"]),
    ]
    return "\n".join(lines)


def _summary_rows(summary: dict[str, object], keys: tuple[str, ...]) -> list[str]:
    return [f"| {key} | {summary[key]} |" for key in keys]


def _mapping_rows(mapping: dict[str, object]) -> list[str]:
    return [f"| {key} | {value} |" for key, value in mapping.items()]


def _gap_rows(gaps: list[dict[str, object]]) -> list[str]:
    if not gaps:
        return ["| 无 | 无 | 无 |"]
    return [
        f"| `{gap['case_id']}` | `{gap['code']}` | {gap['message']} |"
        for gap in gaps
    ]


def _known_limitation_rows(limitations: list[str]) -> list[str]:
    if not limitations:
        return ["- 无"]
    return [f"- {item}" for item in limitations]


if __name__ == "__main__":
    raise SystemExit(main())
