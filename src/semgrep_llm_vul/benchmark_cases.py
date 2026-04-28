"""benchmark/case harness 的最小 M1 evaluator。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from semgrep_llm_vul.analysis_input import AnalysisInputError, parse_analysis_input
from semgrep_llm_vul.reporting import sink_generation_report_to_dict
from semgrep_llm_vul.sink_generation import generate_sink_report


class BenchmarkCaseError(ValueError):
    """benchmark case 无法读取或无法评估。"""


def evaluate_benchmark_case(
    case_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """评估一个 benchmark case 的 M1 sink candidate 期望。"""

    case_path = Path(case_dir)
    case_data = _load_case_yaml(case_path / "case.yaml")
    expected = _load_expected_json(case_path / "expected.json")

    if case_data.get("target_stage") != "M1":
        raise BenchmarkCaseError("第一版 evaluator 仅支持 target_stage=M1")
    if expected.get("stage") != "M1":
        raise BenchmarkCaseError("第一版 evaluator 仅支持 expected.stage=M1")

    task = _case_to_task(case_data)
    root = Path(repo_root) if repo_root is not None else Path.cwd()
    sink_report = generate_sink_report(task, artifact_base=root)
    report_dict = sink_generation_report_to_dict(sink_report, task=task)
    checks = [
        *_expected_sink_checks(report_dict, expected),
        *_must_not_include_checks(report_dict, expected),
    ]

    return {
        "schema_version": 1,
        "kind": "benchmark_case_evaluation",
        "case_id": _required_str(case_data, "id"),
        "stage": "M1",
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "sink_report": report_dict,
    }


def evaluate_benchmark_cases(
    cases_root: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """评估目录下的多个 benchmark cases。"""

    root = Path(cases_root)
    case_dirs = _discover_case_dirs(root)
    results = [
        evaluate_benchmark_case(case_dir, repo_root=repo_root)
        for case_dir in case_dirs
    ]
    passed_count = sum(1 for result in results if result["passed"])
    return {
        "schema_version": 1,
        "kind": "benchmark_case_suite_evaluation",
        "cases_root": str(root),
        "total": len(results),
        "passed": passed_count == len(results),
        "passed_count": passed_count,
        "failed_count": len(results) - passed_count,
        "results": results,
    }


def summarize_benchmark_suite(result: dict[str, Any]) -> dict[str, Any]:
    """将 suite evaluation 压缩为适合日常回归查看的摘要。"""

    return {
        "schema_version": result["schema_version"],
        "kind": "benchmark_case_suite_summary",
        "cases_root": result["cases_root"],
        "total": result["total"],
        "passed": result["passed"],
        "passed_count": result["passed_count"],
        "failed_count": result["failed_count"],
        "cases": [_case_summary(item) for item in result["results"]],
    }


def _case_to_task(case_data: dict[str, Any]):
    inputs = _required_mapping(case_data, "inputs")
    analysis_input = {
        "schema_version": 1,
        "mode": _required_str(inputs, "mode"),
        "description": _required_str(inputs, "description"),
        "target": _required_mapping(case_data, "target"),
        "artifacts": inputs.get("artifacts", []),
        "candidate_prs": inputs.get("candidate_prs", []),
        "vulnerable_snippet": inputs.get("vulnerable_snippet"),
    }
    try:
        return parse_analysis_input(analysis_input)
    except AnalysisInputError as exc:
        raise BenchmarkCaseError(f"case.yaml 无法转换为分析任务：{exc}") from exc


def _case_summary(result: dict[str, Any]) -> dict[str, Any]:
    failed_checks = [check for check in result["checks"] if not check["passed"]]
    return {
        "case_id": result["case_id"],
        "stage": result["stage"],
        "passed": result["passed"],
        "failed_checks": failed_checks,
    }


def _discover_case_dirs(cases_root: Path) -> list[Path]:
    if not cases_root.exists():
        raise BenchmarkCaseError(f"cases 目录不存在：{cases_root}")
    if not cases_root.is_dir():
        raise BenchmarkCaseError(f"cases 路径必须是目录：{cases_root}")

    case_dirs = [
        path
        for path in sorted(cases_root.iterdir())
        if path.is_dir() and (path / "case.yaml").exists() and (path / "expected.json").exists()
    ]
    if not case_dirs:
        raise BenchmarkCaseError(f"cases 目录未发现可评估 case：{cases_root}")
    return case_dirs


def _expected_sink_checks(
    report: dict[str, Any],
    expected: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = []
    for index, expected_sink in enumerate(expected.get("sink_candidates", [])):
        if not isinstance(expected_sink, dict):
            raise BenchmarkCaseError(f"expected.sink_candidates[{index}] 必须是 object")
        matched = any(
            _candidate_matches(candidate, expected_sink) for candidate in report["candidates"]
        )
        checks.append(
            {
                "name": f"expected_sink[{index}]",
                "passed": matched,
                "expected": expected_sink,
                "message": (
                    "期望 sink candidate 已出现" if matched else "期望 sink candidate 未出现"
                ),
            }
        )
    return checks


def _must_not_include_checks(
    report: dict[str, Any],
    expected: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = []
    for index, forbidden in enumerate(expected.get("must_not_include", [])):
        if not isinstance(forbidden, dict):
            raise BenchmarkCaseError(f"expected.must_not_include[{index}] 必须是 object")
        name = _required_str(forbidden, "name")
        found = any(candidate["signature"]["name"] == name for candidate in report["candidates"])
        checks.append(
            {
                "name": f"must_not_include[{index}]",
                "passed": not found,
                "expected": forbidden,
                "message": "禁止项未出现" if not found else "禁止项错误出现",
            }
        )
    return checks


def _candidate_matches(candidate: dict[str, Any], expected_sink: dict[str, Any]) -> bool:
    signature = candidate["signature"]
    location = signature.get("location") or {}

    if signature.get("name") != expected_sink.get("name"):
        return False
    if "path" in expected_sink and location.get("path") != expected_sink["path"]:
        return False
    if "start_line" in expected_sink and location.get("start_line") != expected_sink["start_line"]:
        return False
    if "heuristic_category" in expected_sink:
        categories = {
            evidence["source"]["metadata"].get("heuristic_category")
            for evidence in candidate.get("evidence", [])
        }
        if expected_sink["heuristic_category"] not in categories:
            return False
    return True


def _load_case_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkCaseError(f"无法读取 case.yaml：{path}") from exc
    yaml = YAML(typ="safe")
    try:
        data = yaml.load(text)
    except YAMLError as exc:
        raise BenchmarkCaseError(f"case.yaml 解析失败：{path}") from exc
    if not isinstance(data, dict):
        raise BenchmarkCaseError("case.yaml 必须是 object")
    if data.get("schema_version") != 1:
        raise BenchmarkCaseError("case.yaml schema_version 必须是 1")
    return data


def _load_expected_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkCaseError(f"无法读取 expected.json：{path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BenchmarkCaseError(f"expected.json 解析失败：{path}") from exc
    if not isinstance(data, dict):
        raise BenchmarkCaseError("expected.json 必须是 object")
    if data.get("schema_version") != 1:
        raise BenchmarkCaseError("expected.json schema_version 必须是 1")
    return data


def _required_mapping(data: dict[str, Any], field: str) -> dict[str, Any]:
    value = data.get(field)
    if not isinstance(value, dict):
        raise BenchmarkCaseError(f"{field} 必须是 object")
    return value


def _required_str(data: dict[str, Any], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise BenchmarkCaseError(f"{field} 必须是非空字符串")
    return value
