from pathlib import Path

from semgrep_llm_vul import (
    AnalysisTarget,
    CodeLocation,
    Evidence,
    FunctionSignature,
    InputMode,
    SemanticHint,
    SemanticHintKind,
    SemanticHintReport,
    VulnerabilityInput,
)
from semgrep_llm_vul.models import EvidenceKind, SourceReference
from semgrep_llm_vul.reporting import (
    semantic_hint_report_to_dict,
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


def test_semantic_hint_report_to_dict_has_stable_shape() -> None:
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
    location = CodeLocation(path="app/helpers.py", start_line=12, start_col=5)
    evidence = Evidence(
        source=SourceReference(kind=EvidenceKind.CODE_LOCATION, location=location),
        summary="Helper wraps redirect.",
        reasoning="The helper name and body both suggest redirect semantics.",
        confidence=0.7,
        reproducible_steps=("inspect app/helpers.py:12",),
    )
    report = semantic_hint_report_to_dict(
        SemanticHintReport(
            hints=(
                SemanticHint(
                    symbol="issue_redirect",
                    kind=SemanticHintKind.SINK,
                    summary="Likely redirect-style sink wrapper.",
                    reasoning="The helper forwards a user-influenced URL into redirect.",
                    confidence=0.74,
                    location=location,
                    evidence=(evidence,),
                    applicable_versions=("v1.0.0",),
                    applicable_contexts=("open_redirect", "flask_helper_wrapper"),
                    preconditions=("Need local AST or call-chain evidence.",),
                    failure_modes=("Could be a safe wrapper that validates destinations.",),
                    unknowns=("Validation logic has not been confirmed.",),
                ),
            ),
            evidence=(evidence,),
            unknowns=("LLM hints are candidates only, not final verdicts.",),
        ),
        task=task,
    )

    assert report["schema_version"] == 1
    assert report["kind"] == "semantic_hint_report"
    assert report["target"]["language"] == "python"
    assert report["hints"][0]["symbol"] == "issue_redirect"
    assert report["hints"][0]["kind"] == "sink"
    assert report["hints"][0]["location"]["path"] == "app/helpers.py"
    assert report["hints"][0]["applicable_versions"] == ["v1.0.0"]
    assert report["hints"][0]["applicable_contexts"] == [
        "open_redirect",
        "flask_helper_wrapper",
    ]
    assert report["hints"][0]["failure_modes"] == [
        "Could be a safe wrapper that validates destinations."
    ]
    assert report["unknowns"] == ["LLM hints are candidates only, not final verdicts."]
