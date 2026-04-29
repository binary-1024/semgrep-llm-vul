import json
import shutil
from pathlib import Path

import pytest

from semgrep_llm_vul.benchmark_cases import (
    evaluate_benchmark_case,
    evaluate_benchmark_cases,
    summarize_benchmark_suite,
)

ROOT = Path(__file__).resolve().parent.parent
CASES_ROOT = ROOT / "benchmarks" / "cases"
CASE_DIR = CASES_ROOT / "curated-open-redirect-safe-wrapper"


@pytest.mark.parametrize(
    ("case_id", "recommended_name"),
    [
        ("curated-open-redirect-safe-wrapper", "redirect"),
        ("curated-command-execution-system", "system"),
        ("curated-deserialization-deserialize", "deserialize"),
        ("curated-open-redirect-safe-negative", None),
    ],
)
def test_evaluate_benchmark_case_passes_curated_m1_cases(
    case_id: str,
    recommended_name: str | None,
) -> None:
    result = evaluate_benchmark_case(CASES_ROOT / case_id, repo_root=ROOT)

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == case_id
    assert result["stage"] == "M1"
    assert result["passed"] is True
    assert all(check["passed"] for check in result["checks"])
    recommended = result["sink_report"]["recommended"]
    if recommended_name is None:
        assert recommended is None
    else:
        assert recommended["signature"]["name"] == recommended_name


def test_evaluate_benchmark_case_reports_failed_expected_sink(tmp_path) -> None:
    case_dir = tmp_path / "case"
    shutil.copytree(CASE_DIR, case_dir)
    expected_path = case_dir / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["sink_candidates"][0]["name"] = "missing_sink"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")

    result = evaluate_benchmark_case(case_dir, repo_root=ROOT)

    assert result["passed"] is False
    assert result["checks"][0]["name"] == "expected_sink[0]"
    assert result["checks"][0]["passed"] is False


def test_evaluate_benchmark_case_passes_curated_m2_taint_path_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-taint-path",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-taint-path"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assert result["checks"][0]["name"] == "expected_taint_path[0]"
    assert result["taint_path_report"]["paths"][0]["sink"]["signature"]["name"] == "redirect"
    assert result["taint_path_report"]["paths"][0]["reachable"] is None
    assert "sink_report" not in result


def test_evaluate_benchmark_case_passes_curated_m2_reachability_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assert result["checks"][1]["name"] == "expected_reachability[0]"
    assert result["taint_path_report"]["paths"][0]["reachable"] is None
    assert result["reachability_report"]["assessments"][0]["reachable"] is True
    assert (
        result["reachability_report"]["assessments"][0]["entrypoint"]["kind"]
        == "flask_route"
    )


def test_evaluate_benchmark_case_passes_curated_m2_reachability_blocked_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-blocked",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-blocked"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assert result["taint_path_report"]["paths"][0]["reachable"] is None
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is False
    assert assessment["path"]["reachable"] is False
    assert assessment["blocking_factors"][0]["kind"] == "unregistered_handler"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_cross_file_helper_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-cross-file-helper",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-cross-file-helper"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["path"]["reachable"] is True
    assert assessment["call_chain"][1]["location"]["path"] == "app/helpers.py"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_import_alias_helper_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-import-alias-helper",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-import-alias-helper"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["path"]["reachable"] is True
    assert assessment["call_chain"][1]["location"]["path"] == "app/helpers.py"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_from_import_helper_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-from-import-helper",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-from-import-helper"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["path"]["reachable"] is True
    assert assessment["call_chain"][1]["location"]["path"] == "app/helpers.py"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_multi_layer_helper_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-multi-layer-helper",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-multi-layer-helper"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["path"]["reachable"] is True
    assert [step["symbol"] for step in assessment["call_chain"]] == [
        "login",
        "prepare_redirect",
        "issue_redirect",
        "redirect(next_url)",
    ]


def test_evaluate_benchmark_case_passes_curated_m2_reachability_unknown_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-unknown",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-unknown"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assert result["taint_path_report"]["paths"][0]["reachable"] is None
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is None
    assert assessment["path"]["reachable"] is None
    assert "未找到匹配该 taint path" in assessment["unknowns"][0]


def test_evaluate_benchmark_cases_summarizes_curated_cases() -> None:
    result = evaluate_benchmark_cases(CASES_ROOT, repo_root=ROOT)

    assert result["kind"] == "benchmark_case_suite_evaluation"
    assert result["total"] == 20
    assert result["passed"] is True
    assert result["passed_count"] == 20
    assert result["failed_count"] == 0
    assert {item["case_id"] for item in result["results"]} == {
        "curated-command-execution-system",
        "curated-deserialization-deserialize",
        "curated-insufficient-evidence",
        "curated-open-redirect-safe-diff",
        "curated-open-redirect-safe-negative",
        "curated-open-redirect-safe-wrapper",
        "curated-open-redirect-reachability",
        "curated-open-redirect-reachability-blocked",
        "curated-open-redirect-reachability-cross-file-helper",
        "curated-open-redirect-reachability-from-import-helper",
        "curated-open-redirect-reachability-helper",
        "curated-open-redirect-reachability-import-alias-helper",
        "curated-open-redirect-reachability-multi-layer-helper",
        "curated-open-redirect-reachability-unknown",
        "curated-open-redirect-taint-path",
        "curated-safe-deserialization-wrapper",
        "curated-safe-executor-submit",
        "owasp-benchmark-command-injection-distilled",
        "real-pypickle-cve-2025-5174-m1",
        "sard-juliet-deserialization-distilled",
    }


def test_summarize_benchmark_suite_omits_full_sink_reports() -> None:
    result = evaluate_benchmark_cases(CASES_ROOT, repo_root=ROOT)

    summary = summarize_benchmark_suite(result)

    assert summary["kind"] == "benchmark_case_suite_summary"
    assert summary["total"] == 20
    assert summary["passed"] is True
    assert all("sink_report" not in item for item in summary["cases"])
    assert all(item["failed_checks"] == [] for item in summary["cases"])
