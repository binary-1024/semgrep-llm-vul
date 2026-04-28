from pathlib import Path

from semgrep_llm_vul import AnalysisTarget, InputMode, VulnerabilityInput
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixtures" / "semgrep"


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


def test_generate_taint_path_report_aligns_semgrep_trace_to_sink_candidate() -> None:
    task = _task()
    findings = tuple(load_semgrep_findings(FIXTURE_DIR / "taint-result-with-trace.json"))
    sink_report = generate_sink_report(task, semgrep_findings=findings)
    semgrep_paths = tuple(load_semgrep_taint_paths(FIXTURE_DIR / "taint-result-with-trace.json"))

    report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=semgrep_paths,
    )

    assert len(report.paths) == 1
    path = report.paths[0]
    assert path.reachable is None
    assert path.source.name == 'request.args["next"]'
    assert path.sink.signature.name == "redirect"
    assert [step.role.value for step in path.steps] == ["source", "intermediate", "sink"]
    assert "不代表已确认可触达或可利用" in path.evidence[-1].reasoning
    assert report.unknowns == ()


def test_generate_taint_path_report_without_semgrep_paths_reports_unknown() -> None:
    task = _task()
    findings = tuple(load_semgrep_findings(FIXTURE_DIR / "taint-result-with-trace.json"))
    sink_report = generate_sink_report(task, semgrep_findings=findings)

    report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=(),
    )

    assert report.paths == ()
    assert "缺少 Semgrep taint path 候选。" in report.unknowns


def test_generate_taint_path_report_without_sink_candidates_reports_unknown() -> None:
    task = _task()
    sink_report = generate_sink_report(task)
    semgrep_paths = tuple(load_semgrep_taint_paths(FIXTURE_DIR / "taint-result-with-trace.json"))

    report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=semgrep_paths,
    )

    assert report.paths == ()
    assert "缺少 sink candidate，无法从 sink 出发生成污点路径候选。" in report.unknowns
