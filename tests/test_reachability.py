from pathlib import Path

import pytest

from semgrep_llm_vul import AnalysisTarget, InputMode, VulnerabilityInput
from semgrep_llm_vul.reachability import (
    ReachabilityEvidenceError,
    generate_reachability_report,
    load_reachability_evidence,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent
SEMGREP_DIR = ROOT / "fixtures" / "semgrep"
REACHABILITY_DIR = ROOT / "fixtures" / "reachability"


def _task() -> VulnerabilityInput:
    return VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through user-controlled next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )


def _taint_report():
    task = _task()
    findings = tuple(load_semgrep_findings(SEMGREP_DIR / "taint-result-with-trace.json"))
    sink_report = generate_sink_report(task, semgrep_findings=findings)
    semgrep_paths = tuple(load_semgrep_taint_paths(SEMGREP_DIR / "taint-result-with-trace.json"))
    return generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=semgrep_paths,
    )


def test_generate_reachability_report_marks_matching_path_reachable() -> None:
    task = _task()
    records = load_reachability_evidence(REACHABILITY_DIR / "open-redirect-reachable.json")

    report = generate_reachability_report(
        task,
        taint_report=_taint_report(),
        evidence_records=records,
    )

    assert report.unknowns == ()
    assert len(report.assessments) == 1
    assessment = report.assessments[0]
    assert assessment.reachable is True
    assert assessment.path.reachable is True
    assert assessment.entrypoint is not None
    assert assessment.entrypoint.kind == "flask_route"
    assert [step.symbol for step in assessment.call_chain] == [
        "login",
        "redirect(next_url)",
    ]
    assert assessment.source_control is not None
    assert assessment.source_control.controlled is True
    assert "尚未运行 PoC" in assessment.unknowns[0]


def test_generate_reachability_report_keeps_unmatched_path_unknown() -> None:
    task = _task()

    report = generate_reachability_report(task, taint_report=_taint_report())

    assert "缺少本地 reachability evidence" in report.unknowns[0]
    assert report.assessments[0].reachable is None
    assert report.assessments[0].path.reachable is None
    assert "未找到匹配" in report.assessments[0].unknowns[0]


def test_generate_reachability_report_allows_false_only_with_blocking_factor() -> None:
    task = _task()
    records = load_reachability_evidence(REACHABILITY_DIR / "open-redirect-blocked.json")

    report = generate_reachability_report(
        task,
        taint_report=_taint_report(),
        evidence_records=records,
    )

    assessment = report.assessments[0]
    assert assessment.reachable is False
    assert assessment.path.reachable is False
    assert assessment.blocking_factors[0].kind == "unregistered_handler"


def test_load_reachability_evidence_rejects_false_without_blocking_factor() -> None:
    with pytest.raises(ReachabilityEvidenceError, match="blocking_factors"):
        load_reachability_evidence(
            REACHABILITY_DIR / "invalid-unreachable-without-blocking.json"
        )
