from semgrep_llm_vul import AnalysisTarget, FunctionSignature, InputMode, VulnerabilityInput
from semgrep_llm_vul.reporting import sink_generation_report_to_dict
from semgrep_llm_vul.sink_generation import generate_sink_report


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
