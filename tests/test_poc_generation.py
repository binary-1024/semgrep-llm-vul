from pathlib import Path

from semgrep_llm_vul.analysis_input import load_analysis_input
from semgrep_llm_vul.poc_generation import generate_poc_report
from semgrep_llm_vul.reachability import (
    discover_flask_route_evidence,
    generate_reachability_report,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent


def test_generate_poc_report_builds_structured_plan_from_local_var_source_control() -> None:
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
        evidence_records=discover_flask_route_evidence(source_root, taint_paths=taint_report.paths),
    )

    report = generate_poc_report(task, reachability_report=reachability_report)

    assert len(report.plans) == 1
    plan = report.plans[0]
    assert plan.verdict.value == "planned"
    assert plan.execution_state.value == "not_run"
    assert plan.trigger_input.location.value == "query_or_form"
    assert plan.trigger_input.name == "next"
    assert plan.request.method == "GET"
    assert plan.request.path == "/login"
    assert plan.request.parameters[0].value == "https://attacker.example/poc"
    assert "request.values" in plan.unknowns[0]


def test_generate_poc_report_keeps_blocked_path_out_of_planning() -> None:
    task = load_analysis_input(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    fixture = ROOT / "fixtures" / "semgrep" / "taint-result-with-relative-path-guard-trace.json"
    source_root = ROOT / "fixtures" / "reachability" / "flask-relative-path-guard-app"

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
        evidence_records=discover_flask_route_evidence(source_root, taint_paths=taint_report.paths),
    )

    report = generate_poc_report(task, reachability_report=reachability_report)

    assert report.plans == ()
    assert any("reachable=false 的路径保留为阻断证据" in item for item in report.unknowns)


def test_generate_poc_report_keeps_unknown_path_out_of_planning() -> None:
    task = load_analysis_input(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    fixture = (
        ROOT
        / "fixtures"
        / "semgrep"
        / "taint-result-with-alias-assignment-unknown-trace.json"
    )
    source_root = ROOT / "fixtures" / "reachability" / "flask-alias-assignment-unknown-app"

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
        evidence_records=discover_flask_route_evidence(source_root, taint_paths=taint_report.paths),
    )

    report = generate_poc_report(task, reachability_report=reachability_report)

    assert report.plans == ()
    assert any("reachable=null 的路径证据不足" in item for item in report.unknowns)
