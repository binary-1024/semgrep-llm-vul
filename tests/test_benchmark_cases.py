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


def test_evaluate_benchmark_case_passes_curated_m2_reachability_app_get_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-app-get",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-app-get"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["entrypoint"]["kind"] == "flask_route"
    assert assessment["entrypoint"]["evidence"][0]["source"]["metadata"]["entrypoint_model"] == (
        "method_decorator_get"
    )


def test_evaluate_benchmark_case_passes_curated_m2_reachability_blueprint_prefix_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-blueprint-prefix",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-blueprint-prefix"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["entrypoint"]["name"] == "GET /auth/login"
    assert assessment["entrypoint"]["evidence"][0]["source"]["metadata"]["entrypoint_model"] == (
        "blueprint_method_decorator_get"
    )


def test_evaluate_benchmark_case_passes_blueprint_unregistered_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-blueprint-unregistered",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-blueprint-unregistered"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is None


def test_evaluate_benchmark_case_passes_relative_path_guard_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-relative-path-guard",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-relative-path-guard"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is False
    assert assessment["blocking_factors"][0]["kind"] == "relative_path_guard"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_add_url_rule_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-add-url-rule",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-add-url-rule"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["entrypoint"]["kind"] == "flask_route"
    assert assessment["entrypoint"]["evidence"][0]["source"]["metadata"]["entrypoint_model"] == (
        "add_url_rule"
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


def test_evaluate_benchmark_case_passes_curated_m2_reachability_from_import_alias_helper_case(
) -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-from-import-alias-helper",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-from-import-alias-helper"
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


def test_evaluate_benchmark_case_passes_curated_m2_source_control_local_var_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-source-control-local-var",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-source-control-local-var"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is True
    assert assessment["path"]["source"]["name"] == "next_url"
    assert assessment["source_control"]["controlled"] is True
    assert assessment["source_control"]["evidence"][0]["source"]["metadata"]["evidence_type"] == (
        "source_assignment_ast"
    )


def test_evaluate_benchmark_case_passes_curated_m3_poc_plan_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-poc-plan-source-control-local-var",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-poc-plan-source-control-local-var"
    assert result["stage"] == "M3"
    assert result["passed"] is True
    plan = result["poc_report"]["plans"][0]
    assert plan["execution_state"] == "not_run"
    assert plan["request"]["method"] == "GET"
    assert plan["request"]["path"] == "/login"
    assert plan["trigger_input"]["location"] == "query_or_form"
    assert plan["trigger_input"]["name"] == "next"


def test_evaluate_benchmark_case_passes_curated_m3_blocked_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-poc-plan-blocked",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-poc-plan-blocked"
    assert result["stage"] == "M3"
    assert result["passed"] is True
    assert result["poc_report"]["plans"] == []
    assert "reachable=false 的路径保留为阻断证据" in result["poc_report"]["unknowns"][0]


def test_evaluate_benchmark_case_passes_curated_m4_verified_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-exp-verified",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-exp-verified"
    assert result["stage"] == "M4"
    assert result["passed"] is True
    verification = result["exp_report"]["verifications"][0]
    assert verification["verdict"] == "verified"
    assert verification["exp_request"]["runner"] == "http_request_replay"
    assert verification["affected"]["effect_state"] == "effect_observed"
    assert verification["fixed"]["effect_state"] == "effect_not_observed"


def test_evaluate_benchmark_case_passes_curated_m4_not_verified_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-exp-not-verified",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-exp-not-verified"
    assert result["stage"] == "M4"
    assert result["passed"] is True
    verification = result["exp_report"]["verifications"][0]
    assert verification["verdict"] == "not_verified"
    assert verification["affected"]["effect_state"] == "effect_not_observed"


def test_evaluate_benchmark_case_passes_curated_m4_inconclusive_case() -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-exp-inconclusive",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-exp-inconclusive"
    assert result["stage"] == "M4"
    assert result["passed"] is True
    verification = result["exp_report"]["verifications"][0]
    assert verification["verdict"] == "inconclusive"
    assert verification["fixed"]["execution_state"] == "environment_missing"


def test_evaluate_benchmark_case_passes_curated_m2_reachability_alias_assignment_unknown_case(
) -> None:
    result = evaluate_benchmark_case(
        CASES_ROOT / "curated-open-redirect-reachability-alias-assignment-unknown",
        repo_root=ROOT,
    )

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-reachability-alias-assignment-unknown"
    assert result["stage"] == "M2"
    assert result["passed"] is True
    assessment = result["reachability_report"]["assessments"][0]
    assert assessment["reachable"] is None
    assert assessment["path"]["reachable"] is None


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
    assert result["total"] == 34
    assert result["passed"] is True
    assert result["passed_count"] == 34
    assert result["failed_count"] == 0
    assert {item["case_id"] for item in result["results"]} == {
        "curated-command-execution-system",
        "curated-deserialization-deserialize",
        "curated-open-redirect-exp-inconclusive",
        "curated-open-redirect-exp-not-verified",
        "curated-open-redirect-exp-verified",
        "curated-insufficient-evidence",
        "curated-open-redirect-poc-plan-blocked",
        "curated-open-redirect-poc-plan-source-control-local-var",
        "curated-open-redirect-poc-plan-unknown",
        "curated-open-redirect-reachability-app-get",
        "curated-open-redirect-reachability-add-url-rule",
        "curated-open-redirect-reachability-alias-assignment-unknown",
        "curated-open-redirect-reachability-blueprint-prefix",
        "curated-open-redirect-reachability-blueprint-unregistered",
        "curated-open-redirect-safe-diff",
        "curated-open-redirect-safe-negative",
        "curated-open-redirect-safe-wrapper",
        "curated-open-redirect-reachability",
        "curated-open-redirect-reachability-blocked",
        "curated-open-redirect-reachability-cross-file-helper",
        "curated-open-redirect-reachability-from-import-alias-helper",
        "curated-open-redirect-reachability-from-import-helper",
        "curated-open-redirect-reachability-helper",
        "curated-open-redirect-reachability-import-alias-helper",
        "curated-open-redirect-reachability-multi-layer-helper",
        "curated-open-redirect-reachability-relative-path-guard",
        "curated-open-redirect-reachability-source-control-local-var",
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
    assert summary["total"] == 34
    assert summary["passed"] is True
    assert all("sink_report" not in item for item in summary["cases"])
    assert all(item["failed_checks"] == [] for item in summary["cases"])
