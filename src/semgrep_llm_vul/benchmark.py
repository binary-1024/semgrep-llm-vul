"""benchmark/case harness 的最小 M1 evaluator。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from semgrep_llm_vul.analysis_input import AnalysisInputError, parse_analysis_input
from semgrep_llm_vul.models import SinkCandidate, SinkGenerationReport, VulnerabilityInput
from semgrep_llm_vul.reporting import sink_generation_report_to_dict
from semgrep_llm_vul.sink_generation import SinkGenerationError, generate_sink_report

SUPPORTED_CASE_SCHEMA_VERSION = 1
SUPPORTED_EXPECTED_SCHEMA_VERSION = 1
SUPPORTED_CASE_TYPES = {"curated_minimal", "synthetic_benchmark", "real_vulnerability"}
SUPPORTED_CASE_STATUSES = {"candidate", "blocked", "unsupported"}
SUPPORTED_STAGES = {"M1", "M2", "M3", "M4"}


class BenchmarkCaseError(ValueError):
    """benchmark case 读取或执行失败。"""


@dataclass(frozen=True)
class BenchmarkCase:
    """一个可执行 benchmark/case。"""

    case_id: str
    case_type: str
    target_stage: str
    status: str
    source: dict[str, Any]
    safety: dict[str, bool]
    task: VulnerabilityInput
    expected: dict[str, Any]
    case_dir: Path


@dataclass(frozen=True)
class BenchmarkEvaluation:
    """单个 case 的 evaluator 结果。"""

    case_id: str
    stage: str
    outcome: str
    details: tuple[str, ...]
    report: SinkGenerationReport | None = None


def load_benchmark_case(case_dir: str | Path) -> BenchmarkCase:
    """读取一个包含 case.yaml 和 expected.json 的 case 目录。"""

    directory = Path(case_dir)
    _validate_notes_file(directory)
    case_data = _load_yaml_mapping(directory / "case.yaml")
    expected = _load_json_mapping(directory / "expected.json")

    schema_version = case_data.get("schema_version")
    if schema_version != SUPPORTED_CASE_SCHEMA_VERSION:
        raise BenchmarkCaseError("case.yaml schema_version 必须是 1")

    case_id = _required_str(case_data, "id")
    case_type = _required_choice(case_data, "type", SUPPORTED_CASE_TYPES)
    target_stage = _required_choice(case_data, "target_stage", SUPPORTED_STAGES)
    status = _required_choice(case_data, "status", SUPPORTED_CASE_STATUSES)
    source = _parse_source(case_data)
    safety = _parse_safety(case_data)
    _validate_expected(expected)
    task = _parse_case_task(case_data)

    return BenchmarkCase(
        case_id=case_id,
        case_type=case_type,
        target_stage=target_stage,
        status=status,
        source=source,
        safety=safety,
        task=task,
        expected=expected,
        case_dir=directory,
    )


def discover_benchmark_cases(root: str | Path) -> tuple[BenchmarkCase, ...]:
    """从单个 case 目录或 cases 根目录发现 case。"""

    path = Path(root)
    if (path / "case.yaml").is_file():
        return (load_benchmark_case(path),)

    search_root = path / "cases" if (path / "cases").is_dir() else path
    case_dirs = sorted(item for item in search_root.iterdir() if (item / "case.yaml").is_file())
    return tuple(load_benchmark_case(item) for item in case_dirs)


def benchmark_cases_to_dict(cases: tuple[BenchmarkCase, ...]) -> dict[str, Any]:
    """将 case inventory 转成稳定 JSON 结构，不执行 evaluator。"""

    return {
        "schema_version": 1,
        "kind": "benchmark_case_inventory",
        "summary": {
            "total": len(cases),
            "candidate": sum(case.status == "candidate" for case in cases),
            "blocked": sum(case.status == "blocked" for case in cases),
            "unsupported": sum(case.status == "unsupported" for case in cases),
        },
        "coverage": _case_coverage_summary(cases),
        "cases": [_case_to_dict(case) for case in cases],
    }


def evaluate_benchmark_case(
    case: BenchmarkCase,
    *,
    artifact_base: str | Path | None = None,
) -> BenchmarkEvaluation:
    """执行一个 case 的 M1 sink generation 评估。"""

    stage = case.expected.get("stage", case.target_stage)
    if case.status in {"blocked", "unsupported"}:
        return BenchmarkEvaluation(
            case_id=case.case_id,
            stage=str(stage),
            outcome=case.status,
            details=(f"case status is {case.status}",),
        )

    if stage != "M1" or case.target_stage != "M1":
        return BenchmarkEvaluation(
            case_id=case.case_id,
            stage=str(stage),
            outcome="unsupported",
            details=("当前 evaluator 只支持 M1 sink generation。",),
        )

    try:
        report = generate_sink_report(case.task, artifact_base=artifact_base)
    except SinkGenerationError as exc:
        return BenchmarkEvaluation(
            case_id=case.case_id,
            stage=stage,
            outcome="error",
            details=(str(exc),),
        )

    details = _compare_m1_expectations(case.expected, report)
    return BenchmarkEvaluation(
        case_id=case.case_id,
        stage=stage,
        outcome="passed" if not details else "failed",
        details=tuple(details),
        report=report,
    )


def evaluate_benchmark_cases(
    root: str | Path,
    *,
    artifact_base: str | Path | None = None,
) -> tuple[BenchmarkEvaluation, ...]:
    """发现并执行一组 benchmark cases。"""

    return tuple(
        evaluate_benchmark_case(case, artifact_base=artifact_base)
        for case in discover_benchmark_cases(root)
    )


def benchmark_evaluations_to_dict(
    evaluations: tuple[BenchmarkEvaluation, ...],
    *,
    include_reports: bool = False,
    cases: tuple[BenchmarkCase, ...] = (),
) -> dict[str, Any]:
    """将 evaluator 结果转成稳定 JSON 结构。"""

    case_by_id = {case.case_id: case for case in cases}
    return {
        "schema_version": 1,
        "kind": "benchmark_evaluation_report",
        "summary": {
            "total": len(evaluations),
            "passed": sum(item.outcome == "passed" for item in evaluations),
            "failed": sum(item.outcome == "failed" for item in evaluations),
            "blocked": sum(item.outcome == "blocked" for item in evaluations),
            "unsupported": sum(item.outcome == "unsupported" for item in evaluations),
            "error": sum(item.outcome == "error" for item in evaluations),
        },
        "coverage": _coverage_summary(evaluations, case_by_id),
        "gaps": _gap_summary(evaluations, case_by_id),
        "cases": [
            _evaluation_to_dict(
                evaluation,
                include_report=include_reports,
                case=case_by_id.get(evaluation.case_id),
            )
            for evaluation in evaluations
        ],
    }


def _gap_summary(
    evaluations: tuple[BenchmarkEvaluation, ...],
    case_by_id: dict[str, BenchmarkCase],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for evaluation in evaluations:
        if evaluation.outcome == "passed":
            continue
        case = case_by_id.get(evaluation.case_id)
        if case is None:
            continue
        for code, message in _gap_codes(evaluation, case):
            gaps.append(
                {
                    "case_id": evaluation.case_id,
                    "code": code,
                    "stage": evaluation.stage,
                    "source": case.source.get("name"),
                    "message": message,
                }
            )
    return gaps


def _gap_codes(
    evaluation: BenchmarkEvaluation,
    case: BenchmarkCase,
) -> tuple[tuple[str, str], ...]:
    if evaluation.outcome == "blocked":
        if case.safety.get("requires_isolation"):
            return (("blocked_runtime", "需要隔离环境、checkout 或运行边界后才能执行。"),)
        return (("blocked_case", "case 当前被人工标记为 blocked。"),)

    if evaluation.outcome == "unsupported":
        source_name = str(case.source.get("name") or "").lower()
        if "cvefixes" in source_name:
            return (("unsupported_source_ingestion", "当前不支持直接导入完整 CVEfixes 数据库。"),)
        return (("unsupported_stage", f"当前 evaluator 不支持 {evaluation.stage}。"),)

    if evaluation.outcome == "error":
        return (("evaluator_error", "case 执行时发生 evaluator 错误。"),)

    gap_codes: list[tuple[str, str]] = []
    for detail in evaluation.details:
        if detail.startswith("missing expected sink candidate"):
            gap_codes.append(("missing_expected_candidate", detail))
        elif detail.startswith("forbidden sink candidate"):
            gap_codes.append(("forbidden_candidate", detail))
        else:
            gap_codes.append(("expectation_mismatch", detail))
    return tuple(gap_codes)


def _coverage_summary(
    evaluations: tuple[BenchmarkEvaluation, ...],
    case_by_id: dict[str, BenchmarkCase],
) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_stage: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for evaluation in evaluations:
        case = case_by_id.get(evaluation.case_id)
        if case is None:
            continue
        by_type[case.case_type] = by_type.get(case.case_type, 0) + 1
        by_stage[evaluation.stage] = by_stage.get(evaluation.stage, 0) + 1
        source_name = str(case.source.get("name") or "unknown")
        by_source[source_name] = by_source.get(source_name, 0) + 1

    return {
        "by_type": dict(sorted(by_type.items())),
        "by_stage": dict(sorted(by_stage.items())),
        "by_source": dict(sorted(by_source.items())),
    }


def _case_coverage_summary(cases: tuple[BenchmarkCase, ...]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_stage: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for case in cases:
        by_type[case.case_type] = by_type.get(case.case_type, 0) + 1
        by_stage[case.target_stage] = by_stage.get(case.target_stage, 0) + 1
        source_name = str(case.source.get("name") or "unknown")
        by_source[source_name] = by_source.get(source_name, 0) + 1

    return {
        "by_type": dict(sorted(by_type.items())),
        "by_stage": dict(sorted(by_stage.items())),
        "by_source": dict(sorted(by_source.items())),
    }


def _case_to_dict(case: BenchmarkCase) -> dict[str, Any]:
    return {
        "id": case.case_id,
        "type": case.case_type,
        "target_stage": case.target_stage,
        "status": case.status,
        "source": {
            "name": case.source.get("name"),
            "url": case.source.get("url"),
            "license": case.source.get("license"),
        },
        "safety": case.safety,
    }


def _evaluation_to_dict(
    evaluation: BenchmarkEvaluation,
    *,
    include_report: bool,
    case: BenchmarkCase | None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": evaluation.case_id,
        "stage": evaluation.stage,
        "outcome": evaluation.outcome,
        "details": list(evaluation.details),
    }
    if case is not None:
        data["type"] = case.case_type
        data["declared_status"] = case.status
        data["source"] = {
            "name": case.source.get("name"),
            "url": case.source.get("url"),
            "license": case.source.get("license"),
        }
    if include_report and evaluation.report is not None and case is not None:
        data["sink_generation_report"] = sink_generation_report_to_dict(
            evaluation.report,
            task=case.task,
        )
    return data


def _compare_m1_expectations(
    expected: dict[str, Any],
    report: SinkGenerationReport,
) -> list[str]:
    details: list[str] = []
    for expected_candidate in _mapping_list(expected.get("sink_candidates"), "sink_candidates"):
        matched = any(
            _candidate_matches(candidate, expected_candidate)
            for candidate in report.candidates
        )
        if not matched:
            details.append(f"missing expected sink candidate: {expected_candidate}")

    for forbidden in _mapping_list(expected.get("must_not_include"), "must_not_include"):
        if any(_candidate_matches(candidate, forbidden) for candidate in report.candidates):
            details.append(f"forbidden sink candidate was produced: {forbidden}")

    return details


def _candidate_matches(candidate: SinkCandidate, expected: dict[str, Any]) -> bool:
    signature = candidate.signature
    if "name" in expected and signature.name != expected["name"]:
        return False
    if "path" in expected:
        if signature.location is None or signature.location.path != expected["path"]:
            return False
    if "start_line" in expected:
        if signature.location is None or signature.location.start_line != expected["start_line"]:
            return False
    if "heuristic_category" in expected:
        categories = {
            evidence.source.metadata.get("heuristic_category")
            for evidence in candidate.evidence
        }
        if expected["heuristic_category"] not in categories:
            return False
    return True


def _parse_case_task(case_data: dict[str, Any]) -> VulnerabilityInput:
    inputs = _required_mapping(case_data, "inputs")
    analysis_input = {
        "schema_version": 1,
        "target": _required_mapping(case_data, "target"),
        "description": _required_str(inputs, "description"),
        "mode": _required_str(inputs, "mode"),
        "sink": inputs.get("sink"),
        "vulnerable_snippet": inputs.get("vulnerable_snippet"),
        "candidate_prs": inputs.get("candidate_prs"),
        "artifacts": inputs.get("artifacts"),
    }
    try:
        return parse_analysis_input(analysis_input)
    except AnalysisInputError as exc:
        raise BenchmarkCaseError(str(exc)) from exc


def _parse_source(case_data: dict[str, Any]) -> dict[str, Any]:
    source = _required_mapping(case_data, "source")
    return {
        "name": _required_str(source, "name"),
        "url": _optional_str(source.get("url"), field="source.url"),
        "license": _required_str(source, "license"),
    }


def _parse_safety(case_data: dict[str, Any]) -> dict[str, bool]:
    safety = _required_mapping(case_data, "safety")
    parsed = {}
    for field in ("contains_poc", "contains_exp", "requires_isolation"):
        parsed[field] = _required_bool(safety, field=f"safety.{field}", key=field)
    return parsed


def _validate_expected(expected: dict[str, Any]) -> None:
    schema_version = expected.get("schema_version")
    if schema_version != SUPPORTED_EXPECTED_SCHEMA_VERSION:
        raise BenchmarkCaseError("expected.json schema_version 必须是 1")
    _required_choice(expected, "stage", SUPPORTED_STAGES)
    _required_choice(expected, "expected_status", SUPPORTED_CASE_STATUSES)
    _mapping_list(expected.get("sink_candidates"), "sink_candidates")
    _mapping_list(expected.get("must_not_include"), "must_not_include")


def _validate_notes_file(directory: Path) -> None:
    notes_path = directory / "notes.md"
    if not notes_path.is_file():
        raise BenchmarkCaseError(f"缺少 benchmark case notes：{notes_path}")


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkCaseError(f"无法读取 benchmark case：{path}") from exc
    try:
        data = YAML(typ="safe").load(text)
    except YAMLError as exc:
        raise BenchmarkCaseError(f"YAML 解析失败：{path}") from exc
    if not isinstance(data, dict):
        raise BenchmarkCaseError("case.yaml 必须是 object")
    return data


def _load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except OSError as exc:
        raise BenchmarkCaseError(f"无法读取 benchmark expected：{path}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkCaseError(f"expected.json 解析失败：{path}") from exc
    if not isinstance(data, dict):
        raise BenchmarkCaseError("expected.json 必须是 object")
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


def _optional_str(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BenchmarkCaseError(f"{field} 必须是 string 或 null")
    return value


def _required_choice(data: dict[str, Any], field: str, allowed: set[str]) -> str:
    value = _required_str(data, field)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise BenchmarkCaseError(f"{field} 必须是：{choices}")
    return value


def _required_bool(data: dict[str, Any], *, field: str, key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise BenchmarkCaseError(f"{field} 必须是 bool")
    return value


def _mapping_list(value: Any, field: str) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise BenchmarkCaseError(f"{field} 必须是 object list")
    return tuple(value)
