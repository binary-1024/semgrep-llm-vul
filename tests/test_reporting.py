from pathlib import Path

from semgrep_llm_vul import AnalysisTarget, FunctionSignature, InputMode, VulnerabilityInput
from semgrep_llm_vul.reporting import (
    sink_generation_report_to_dict,
    taint_path_generation_report_to_dict,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent


def test_sink_generation_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.KNOWN_SINK,
        sink_signature=FunctionSignature(raw="flask.redirect(location)", name="redirect"),
    )

    report = sink_generation_report_to_dict(generate_sink_report(task), task=task)

    assert report["schema_version"] == 1
    assert report["kind"] == "sink_generation_report"
    assert report["mode"] == "known_sink"
    assert report["target"]["repo_url"] == "https://github.com/example/flask-app"
    assert report["recommended"]["signature"]["name"] == "redirect"
    assert report["recommended"]["confidence"] == 0.9
    assert report["candidates"][0]["evidence"]
    assert isinstance(report["unknowns"], list)


def test_taint_path_generation_report_to_dict_has_stable_shape() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through next parameter.",
        mode=InputMode.UNKNOWN_SINK,
    )
    fixture = ROOT / "fixtures" / "semgrep" / "taint-result-with-trace.json"
    sink_report = generate_sink_report(task, semgrep_findings=tuple(load_semgrep_findings(fixture)))
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=tuple(load_semgrep_taint_paths(fixture)),
    )

    report = taint_path_generation_report_to_dict(taint_report, task=task)

    assert report["schema_version"] == 1
    assert report["kind"] == "taint_path_generation_report"
    assert report["mode"] == "unknown_sink"
    assert report["target"]["language"] == "python"
    assert report["paths"][0]["source"]["name"] == 'request.args["next"]'
    assert report["paths"][0]["sink"]["signature"]["name"] == "redirect"
    assert report["paths"][0]["steps"][0]["role"] == "source"
    assert report["paths"][0]["reachable"] is None
    assert report["paths"][0]["evidence"]
    assert isinstance(report["unknowns"], list)
