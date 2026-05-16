from pathlib import Path

from semgrep_llm_vul.analysis_input import load_analysis_input
from semgrep_llm_vul.exp_verification import (
    ExpVerificationReport,
    generate_exp_verification_report,
    load_execution_evidence,
)
from semgrep_llm_vul.poc_generation import generate_poc_report
from semgrep_llm_vul.reachability import (
    discover_flask_route_evidence,
    generate_reachability_report,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent


def _poc_report():
    task = load_analysis_input(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    fixture = (
        ROOT
        / "fixtures"
        / "semgrep"
        / "taint-result-with-source-control-local-var-trace.json"
    )
    source_root = ROOT / "fixtures" / "reachability" / "flask-source-control-local-var-app"
    sink_report = generate_sink_report(
        task,
        semgrep_findings=tuple(load_semgrep_findings(fixture)),
    )
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=tuple(load_semgrep_taint_paths(fixture)),
    )
    reachability_report = generate_reachability_report(
        task,
        taint_report=taint_report,
        evidence_records=discover_flask_route_evidence(
            source_root,
            taint_paths=taint_report.paths,
        ),
    )
    return task, generate_poc_report(task, reachability_report=reachability_report)


def test_generate_exp_verification_report_returns_verified_for_affected_fixed_diff() -> None:
    task, poc_report = _poc_report()
    execution_fixture = ROOT / "fixtures" / "execution" / "open-redirect-verified.json"

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=load_execution_evidence(execution_fixture),
    )

    assert isinstance(report, ExpVerificationReport)
    assert len(report.verifications) == 1
    verification = report.verifications[0]
    assert verification.verdict.value == "verified"
    assert verification.exp_request.runner == "http_request_replay"
    assert "TARGET_HOST" in verification.exp_request.command
    assert verification.affected.effect_state.value == "effect_observed"
    assert verification.fixed.effect_state.value == "effect_not_observed"


def test_generate_exp_verification_report_returns_not_verified_when_affected_has_no_effect(
) -> None:
    task, poc_report = _poc_report()
    execution_fixture = ROOT / "fixtures" / "execution" / "open-redirect-not-verified.json"

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=load_execution_evidence(execution_fixture),
    )

    verification = report.verifications[0]
    assert verification.verdict.value == "not_verified"
    assert verification.affected.effect_state.value == "effect_not_observed"
    assert verification.fixed.effect_state.value == "effect_not_observed"


def test_generate_exp_verification_report_returns_inconclusive_when_fixed_env_missing() -> None:
    task, poc_report = _poc_report()
    execution_fixture = ROOT / "fixtures" / "execution" / "open-redirect-inconclusive.json"

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=load_execution_evidence(execution_fixture),
    )

    verification = report.verifications[0]
    assert verification.verdict.value == "inconclusive"
    assert verification.affected.effect_state.value == "effect_observed"
    assert verification.fixed.execution_state.value == "environment_missing"
    assert any("fixed 版本执行未完成" in item for item in verification.unknowns)
