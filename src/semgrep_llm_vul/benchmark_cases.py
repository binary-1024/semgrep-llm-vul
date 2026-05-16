"""benchmark/case harness 的最小 M1/M2/M3/M4 evaluator。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from semgrep_llm_vul.analysis_input import AnalysisInputError, parse_analysis_input
from semgrep_llm_vul.exp_verification import (
    ExecutionEvidenceError,
    generate_exp_verification_report,
    load_execution_evidence,
)
from semgrep_llm_vul.poc_generation import generate_poc_report
from semgrep_llm_vul.reachability import (
    ReachabilityEvidenceError,
    discover_flask_route_evidence,
    generate_reachability_report,
    load_reachability_evidence,
)
from semgrep_llm_vul.reporting import (
    exp_verification_report_to_dict,
    poc_generation_report_to_dict,
    reachability_report_to_dict,
    sink_generation_report_to_dict,
    taint_path_generation_report_to_dict,
)
from semgrep_llm_vul.semgrep import (
    SemgrepParseError,
    load_semgrep_findings,
    load_semgrep_taint_paths,
)
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report


class BenchmarkCaseError(ValueError):
    """benchmark case 无法读取或无法评估。"""


def evaluate_benchmark_case(
    case_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """评估一个 benchmark case 的阶段期望。"""

    case_path = Path(case_dir)
    case_data = _load_case_yaml(case_path / "case.yaml")
    expected = _load_expected_json(case_path / "expected.json")

    stage = _required_str(case_data, "target_stage")
    if expected.get("stage") != stage:
        raise BenchmarkCaseError("case target_stage 必须与 expected.stage 一致")

    if stage == "M1":
        return _evaluate_m1_case(case_data, expected, repo_root=repo_root)
    if stage == "M2":
        return _evaluate_m2_case(case_data, expected, repo_root=repo_root)
    if stage == "M3":
        return _evaluate_m3_case(case_data, expected, repo_root=repo_root)
    if stage == "M4":
        return _evaluate_m4_case(case_data, expected, repo_root=repo_root)
    raise BenchmarkCaseError("第一版 evaluator 仅支持 target_stage=M1、M2、M3 或 M4")


def _evaluate_m1_case(
    case_data: dict[str, Any],
    expected: dict[str, Any],
    *,
    repo_root: str | Path | None,
) -> dict[str, Any]:
    task = _case_to_task(case_data)
    root = _repo_root(repo_root)
    sink_report = generate_sink_report(task, artifact_base=root)
    report_dict = sink_generation_report_to_dict(sink_report, task=task)
    checks = _m1_checks(report_dict, expected)

    return {
        "schema_version": 1,
        "kind": "benchmark_case_evaluation",
        "case_id": _required_str(case_data, "id"),
        "stage": _required_str(case_data, "target_stage"),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "sink_report": report_dict,
    }


def _evaluate_m2_case(
    case_data: dict[str, Any],
    expected: dict[str, Any],
    *,
    repo_root: str | Path | None,
) -> dict[str, Any]:
    task = _case_to_task(case_data)
    root = _repo_root(repo_root)
    semgrep_json = _semgrep_json_paths(case_data, repo_root=root)
    reachability_json = _reachability_json_paths(case_data, repo_root=root)
    source_roots = _source_root_paths(case_data, repo_root=root)
    try:
        findings = tuple(
            finding
            for result_path in semgrep_json
            for finding in load_semgrep_findings(result_path)
        )
        taint_paths = tuple(
            taint_path
            for result_path in semgrep_json
            for taint_path in load_semgrep_taint_paths(result_path)
        )
        reachability_records = tuple(
            record
            for evidence_path in reachability_json
            for record in load_reachability_evidence(evidence_path)
        )
    except (ReachabilityEvidenceError, SemgrepParseError) as exc:
        raise BenchmarkCaseError(f"case evidence 无法解析：{exc}") from exc

    sink_report = generate_sink_report(task, semgrep_findings=findings, artifact_base=root)
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=taint_paths,
    )
    try:
        source_root_records = tuple(
            record
            for source_root in source_roots
            for record in discover_flask_route_evidence(
                source_root,
                taint_paths=taint_report.paths,
            )
        )
    except ReachabilityEvidenceError as exc:
        raise BenchmarkCaseError(f"case source root 无法解析：{exc}") from exc
    report_dict = taint_path_generation_report_to_dict(taint_report, task=task)
    reachability_report = generate_reachability_report(
        task,
        taint_report=taint_report,
        evidence_records=(*reachability_records, *source_root_records),
    )
    reachability_dict = reachability_report_to_dict(reachability_report, task=task)
    checks = [
        *_m2_checks(report_dict, expected),
        *_reachability_checks(reachability_dict, expected),
    ]

    result = {
        "schema_version": 1,
        "kind": "benchmark_case_evaluation",
        "case_id": _required_str(case_data, "id"),
        "stage": _required_str(case_data, "target_stage"),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "taint_path_report": report_dict,
    }
    if reachability_json or source_roots or expected.get("reachability"):
        result["reachability_report"] = reachability_dict
    return result


def _evaluate_m3_case(
    case_data: dict[str, Any],
    expected: dict[str, Any],
    *,
    repo_root: str | Path | None,
) -> dict[str, Any]:
    task = _case_to_task(case_data)
    root = _repo_root(repo_root)
    semgrep_json = _semgrep_json_paths(case_data, repo_root=root)
    reachability_json = _reachability_json_paths(case_data, repo_root=root)
    source_roots = _source_root_paths(case_data, repo_root=root)
    try:
        findings = tuple(
            finding
            for result_path in semgrep_json
            for finding in load_semgrep_findings(result_path)
        )
        taint_paths = tuple(
            taint_path
            for result_path in semgrep_json
            for taint_path in load_semgrep_taint_paths(result_path)
        )
        reachability_records = tuple(
            record
            for evidence_path in reachability_json
            for record in load_reachability_evidence(evidence_path)
        )
    except (ReachabilityEvidenceError, SemgrepParseError) as exc:
        raise BenchmarkCaseError(f"case evidence 无法解析：{exc}") from exc

    sink_report = generate_sink_report(task, semgrep_findings=findings, artifact_base=root)
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=taint_paths,
    )
    try:
        source_root_records = tuple(
            record
            for source_root in source_roots
            for record in discover_flask_route_evidence(
                source_root,
                taint_paths=taint_report.paths,
            )
        )
    except ReachabilityEvidenceError as exc:
        raise BenchmarkCaseError(f"case source root 无法解析：{exc}") from exc

    reachability_report = generate_reachability_report(
        task,
        taint_report=taint_report,
        evidence_records=(*reachability_records, *source_root_records),
    )
    poc_report = generate_poc_report(
        task,
        reachability_report=reachability_report,
    )
    reachability_dict = reachability_report_to_dict(reachability_report, task=task)
    poc_dict = poc_generation_report_to_dict(poc_report, task=task)
    checks = _m3_checks(poc_dict, expected)

    return {
        "schema_version": 1,
        "kind": "benchmark_case_evaluation",
        "case_id": _required_str(case_data, "id"),
        "stage": _required_str(case_data, "target_stage"),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "reachability_report": reachability_dict,
        "poc_report": poc_dict,
    }


def _evaluate_m4_case(
    case_data: dict[str, Any],
    expected: dict[str, Any],
    *,
    repo_root: str | Path | None,
) -> dict[str, Any]:
    task = _case_to_task(case_data)
    root = _repo_root(repo_root)
    semgrep_json = _semgrep_json_paths(case_data, repo_root=root)
    reachability_json = _reachability_json_paths(case_data, repo_root=root)
    source_roots = _source_root_paths(case_data, repo_root=root)
    execution_json = _execution_json_paths(case_data, repo_root=root)
    try:
        findings = tuple(
            finding
            for result_path in semgrep_json
            for finding in load_semgrep_findings(result_path)
        )
        taint_paths = tuple(
            taint_path
            for result_path in semgrep_json
            for taint_path in load_semgrep_taint_paths(result_path)
        )
        reachability_records = tuple(
            record
            for evidence_path in reachability_json
            for record in load_reachability_evidence(evidence_path)
        )
        execution_records = tuple(
            record
            for evidence_path in execution_json
            for record in load_execution_evidence(evidence_path)
        )
    except (
        ExecutionEvidenceError,
        ReachabilityEvidenceError,
        SemgrepParseError,
    ) as exc:
        raise BenchmarkCaseError(f"case evidence 无法解析：{exc}") from exc

    sink_report = generate_sink_report(task, semgrep_findings=findings, artifact_base=root)
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=taint_paths,
    )
    try:
        source_root_records = tuple(
            record
            for source_root in source_roots
            for record in discover_flask_route_evidence(
                source_root,
                taint_paths=taint_report.paths,
            )
        )
    except ReachabilityEvidenceError as exc:
        raise BenchmarkCaseError(f"case source root 无法解析：{exc}") from exc

    reachability_report = generate_reachability_report(
        task,
        taint_report=taint_report,
        evidence_records=(*reachability_records, *source_root_records),
    )
    poc_report = generate_poc_report(
        task,
        reachability_report=reachability_report,
    )
    exp_report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=execution_records,
    )
    exp_dict = exp_verification_report_to_dict(exp_report, task=task)
    checks = _m4_checks(exp_dict, expected)

    return {
        "schema_version": 1,
        "kind": "benchmark_case_evaluation",
        "case_id": _required_str(case_data, "id"),
        "stage": _required_str(case_data, "target_stage"),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "exp_report": exp_dict,
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


def _repo_root(repo_root: str | Path | None) -> Path:
    return Path(repo_root) if repo_root is not None else Path.cwd()


def _semgrep_json_paths(case_data: dict[str, Any], *, repo_root: Path) -> tuple[Path, ...]:
    return _input_paths(case_data, field="semgrep_json", repo_root=repo_root)


def _reachability_json_paths(
    case_data: dict[str, Any],
    *,
    repo_root: Path,
) -> tuple[Path, ...]:
    return _input_paths(case_data, field="reachability_json", repo_root=repo_root)


def _source_root_paths(
    case_data: dict[str, Any],
    *,
    repo_root: Path,
) -> tuple[Path, ...]:
    return _input_paths(case_data, field="source_roots", repo_root=repo_root)


def _execution_json_paths(
    case_data: dict[str, Any],
    *,
    repo_root: Path,
) -> tuple[Path, ...]:
    return _input_paths(case_data, field="execution_json", repo_root=repo_root)


def _input_paths(
    case_data: dict[str, Any],
    *,
    field: str,
    repo_root: Path,
) -> tuple[Path, ...]:
    inputs = _required_mapping(case_data, "inputs")
    paths = inputs.get(field, [])
    if not isinstance(paths, list):
        raise BenchmarkCaseError(f"inputs.{field} 必须是 list")
    resolved = []
    for index, item in enumerate(paths):
        if not isinstance(item, str) or not item:
            raise BenchmarkCaseError(f"inputs.{field}[{index}] 必须是非空字符串")
        path = Path(item)
        resolved.append(path if path.is_absolute() else repo_root / path)
    return tuple(resolved)


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

    case_dirs = []
    for path in sorted(cases_root.iterdir()):
        if (
            not path.is_dir()
            or not (path / "case.yaml").exists()
            or not (path / "expected.json").exists()
        ):
            continue
        case_data = _load_case_yaml(path / "case.yaml")
        if case_data.get("status") != "candidate":
            continue
        if case_data.get("target_stage") not in {"M1", "M2", "M3", "M4"}:
            continue
        case_dirs.append(path)
    if not case_dirs:
        raise BenchmarkCaseError(f"cases 目录未发现可评估 case：{cases_root}")
    return case_dirs


def _m1_checks(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        *_expected_sink_checks(report, expected),
        *_must_not_include_checks(report, expected),
    ]


def _m2_checks(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    for index, expected_path in enumerate(expected.get("taint_paths", [])):
        if not isinstance(expected_path, dict):
            raise BenchmarkCaseError(f"expected.taint_paths[{index}] 必须是 object")
        matched = any(
            _taint_path_matches(candidate, expected_path) for candidate in report["paths"]
        )
        checks.append(
            {
                "name": f"expected_taint_path[{index}]",
                "passed": matched,
                "expected": expected_path,
                "message": "期望 taint path 已出现" if matched else "期望 taint path 未出现",
            }
        )
    return checks


def _reachability_checks(
    report: dict[str, Any],
    expected: dict[str, Any],
) -> list[dict[str, Any]]:
    checks = []
    for index, expected_assessment in enumerate(expected.get("reachability", [])):
        if not isinstance(expected_assessment, dict):
            raise BenchmarkCaseError(f"expected.reachability[{index}] 必须是 object")
        matched = any(
            _reachability_matches(candidate, expected_assessment)
            for candidate in report["assessments"]
        )
        checks.append(
            {
                "name": f"expected_reachability[{index}]",
                "passed": matched,
                "expected": expected_assessment,
                "message": (
                    "期望 reachability assessment 已出现"
                    if matched
                    else "期望 reachability assessment 未出现"
                ),
            }
        )
    return checks


def _m3_checks(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    expected_plan_count = expected.get("plan_count")
    if expected_plan_count is not None:
        if not isinstance(expected_plan_count, int) or expected_plan_count < 0:
            raise BenchmarkCaseError("expected.plan_count 必须是非负整数")
        actual_count = len(report["plans"])
        checks.append(
            {
                "name": "expected_plan_count",
                "passed": actual_count == expected_plan_count,
                "expected": expected_plan_count,
                "message": (
                    "PoC plan 数量符合预期"
                    if actual_count == expected_plan_count
                    else f"PoC plan 数量不符：actual={actual_count}"
                ),
            }
        )

    for index, expected_plan in enumerate(expected.get("poc_plans", [])):
        if not isinstance(expected_plan, dict):
            raise BenchmarkCaseError(f"expected.poc_plans[{index}] 必须是 object")
        matched = any(_poc_plan_matches(candidate, expected_plan) for candidate in report["plans"])
        checks.append(
            {
                "name": f"expected_poc_plan[{index}]",
                "passed": matched,
                "expected": expected_plan,
                "message": "期望 PoC plan 已出现" if matched else "期望 PoC plan 未出现",
            }
        )

    for index, fragment in enumerate(expected.get("unknowns_include", [])):
        if not isinstance(fragment, str) or not fragment:
            raise BenchmarkCaseError(f"expected.unknowns_include[{index}] 必须是非空字符串")
        matched = any(fragment in item for item in report.get("unknowns", [])) or any(
            fragment in item
            for plan in report.get("plans", [])
            for item in plan.get("unknowns", [])
        )
        checks.append(
            {
                "name": f"unknowns_include[{index}]",
                "passed": matched,
                "expected": fragment,
                "message": (
                    "报告 unknowns 包含预期片段"
                    if matched
                    else "报告 unknowns 缺少预期片段"
                ),
            }
        )

    return checks


def _m4_checks(report: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    expected_count = expected.get("verification_count")
    if expected_count is not None:
        if not isinstance(expected_count, int) or expected_count < 0:
            raise BenchmarkCaseError("expected.verification_count 必须是非负整数")
        actual_count = len(report["verifications"])
        checks.append(
            {
                "name": "expected_verification_count",
                "passed": actual_count == expected_count,
                "expected": expected_count,
                "message": (
                    "exp verification 数量符合预期"
                    if actual_count == expected_count
                    else f"exp verification 数量不符：actual={actual_count}"
                ),
            }
        )

    for index, expected_verification in enumerate(expected.get("exp_verifications", [])):
        if not isinstance(expected_verification, dict):
            raise BenchmarkCaseError(
                f"expected.exp_verifications[{index}] 必须是 object"
            )
        matched = any(
            _exp_verification_matches(candidate, expected_verification)
            for candidate in report["verifications"]
        )
        checks.append(
            {
                "name": f"expected_exp_verification[{index}]",
                "passed": matched,
                "expected": expected_verification,
                "message": (
                    "期望 exp verification 已出现"
                    if matched
                    else "期望 exp verification 未出现"
                ),
            }
        )

    for index, fragment in enumerate(expected.get("unknowns_include", [])):
        if not isinstance(fragment, str) or not fragment:
            raise BenchmarkCaseError(f"expected.unknowns_include[{index}] 必须是非空字符串")
        matched = any(fragment in item for item in report.get("unknowns", [])) or any(
            fragment in item
            for verification in report.get("verifications", [])
            for item in verification.get("unknowns", [])
        )
        checks.append(
            {
                "name": f"unknowns_include[{index}]",
                "passed": matched,
                "expected": fragment,
                "message": (
                    "报告 unknowns 包含预期片段"
                    if matched
                    else "报告 unknowns 缺少预期片段"
                ),
            }
        )
    return checks


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


def _taint_path_matches(candidate: dict[str, Any], expected_path: dict[str, Any]) -> bool:
    source = expected_path.get("source", {})
    sink = expected_path.get("sink", {})
    if not isinstance(source, dict) or not isinstance(sink, dict):
        raise BenchmarkCaseError("expected.taint_paths[].source/sink 必须是 object")

    if (
        "source_name" in expected_path
        and candidate["source"]["name"] != expected_path["source_name"]
    ):
        return False
    if "sink_name" in expected_path:
        if candidate["sink"]["signature"]["name"] != expected_path["sink_name"]:
            return False
    if "reachable" in expected_path and candidate.get("reachable") != expected_path["reachable"]:
        return False
    if "step_roles" in expected_path:
        roles = [step["role"] for step in candidate["steps"]]
        if roles != expected_path["step_roles"]:
            return False
    if source and not _location_matches(candidate["source"]["location"], source):
        return False
    sink_location = candidate["sink"]["signature"].get("location")
    if sink and not _location_matches(sink_location, sink):
        return False
    return True


def _location_matches(actual: dict[str, Any] | None, expected: dict[str, Any]) -> bool:
    if actual is None:
        return False
    if "path" in expected and actual.get("path") != expected["path"]:
        return False
    if "start_line" in expected and actual.get("start_line") != expected["start_line"]:
        return False
    return True


def _reachability_matches(
    candidate: dict[str, Any],
    expected_assessment: dict[str, Any],
) -> bool:
    if (
        "reachable" in expected_assessment
        and candidate.get("reachable") != expected_assessment["reachable"]
    ):
        return False
    if "sink_name" in expected_assessment:
        sink_name = candidate["path"]["sink"]["signature"]["name"]
        if sink_name != expected_assessment["sink_name"]:
            return False
    if "source_name" in expected_assessment:
        source_name = candidate["path"]["source"]["name"]
        if source_name != expected_assessment["source_name"]:
            return False
    if "entrypoint_kind" in expected_assessment:
        entrypoint = candidate.get("entrypoint") or {}
        if entrypoint.get("kind") != expected_assessment["entrypoint_kind"]:
            return False
    if "blocking_factor_kind" in expected_assessment:
        kinds = {factor["kind"] for factor in candidate.get("blocking_factors", [])}
        if expected_assessment["blocking_factor_kind"] not in kinds:
            return False
    return True


def _poc_plan_matches(
    candidate: dict[str, Any],
    expected_plan: dict[str, Any],
) -> bool:
    if "verdict" in expected_plan and candidate.get("verdict") != expected_plan["verdict"]:
        return False
    if (
        "execution_state" in expected_plan
        and candidate.get("execution_state") != expected_plan["execution_state"]
    ):
        return False
    if (
        "vulnerability_type" in expected_plan
        and candidate.get("vulnerability_type") != expected_plan["vulnerability_type"]
    ):
        return False
    if "sink_name" in expected_plan:
        sink_name = candidate["path"]["sink"]["signature"]["name"]
        if sink_name != expected_plan["sink_name"]:
            return False
    if "source_name" in expected_plan:
        source_name = candidate["path"]["source"]["name"]
        if source_name != expected_plan["source_name"]:
            return False
    entrypoint = candidate.get("entrypoint") or {}
    if (
        "entrypoint_name" in expected_plan
        and entrypoint.get("name") != expected_plan["entrypoint_name"]
    ):
        return False
    trigger_input = candidate.get("trigger_input") or {}
    if (
        "parameter_location" in expected_plan
        and trigger_input.get("location") != expected_plan["parameter_location"]
    ):
        return False
    if (
        "parameter_name" in expected_plan
        and trigger_input.get("name") != expected_plan["parameter_name"]
    ):
        return False
    request = candidate.get("request") or {}
    if (
        "request_method" in expected_plan
        and request.get("method") != expected_plan["request_method"]
    ):
        return False
    if "request_path" in expected_plan and request.get("path") != expected_plan["request_path"]:
        return False
    return True


def _exp_verification_matches(
    candidate: dict[str, Any],
    expected_verification: dict[str, Any],
) -> bool:
    if (
        "verdict" in expected_verification
        and candidate.get("verdict") != expected_verification["verdict"]
    ):
        return False
    if (
        "vulnerability_type" in expected_verification
        and candidate.get("vulnerability_type") != expected_verification["vulnerability_type"]
    ):
        return False
    poc_plan = candidate.get("poc_plan") or {}
    if "entrypoint_name" in expected_verification:
        entrypoint = poc_plan.get("entrypoint") or {}
        if entrypoint.get("name") != expected_verification["entrypoint_name"]:
            return False
    if "parameter_name" in expected_verification:
        trigger_input = poc_plan.get("trigger_input") or {}
        if trigger_input.get("name") != expected_verification["parameter_name"]:
            return False
    if "runner" in expected_verification:
        exp_request = candidate.get("exp_request") or {}
        if exp_request.get("runner") != expected_verification["runner"]:
            return False
    affected = candidate.get("affected") or {}
    if (
        "affected_execution_state" in expected_verification
        and affected.get("execution_state") != expected_verification["affected_execution_state"]
    ):
        return False
    if (
        "affected_effect_state" in expected_verification
        and affected.get("effect_state") != expected_verification["affected_effect_state"]
    ):
        return False
    fixed = candidate.get("fixed") or {}
    if (
        "fixed_execution_state" in expected_verification
        and fixed.get("execution_state") != expected_verification["fixed_execution_state"]
    ):
        return False
    if (
        "fixed_effect_state" in expected_verification
        and fixed.get("effect_state") != expected_verification["fixed_effect_state"]
    ):
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
