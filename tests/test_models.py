import pytest

from semgrep_llm_vul import (
    AnalysisTarget,
    CodeLocation,
    Evidence,
    FunctionSignature,
    InputMode,
    SinkCandidate,
    SourceCandidate,
    TaintPath,
    TaintStep,
    VulnerabilityInput,
)
from semgrep_llm_vul.models import EvidenceKind, SourceReference


def test_known_sink_input_requires_signature() -> None:
    target = AnalysisTarget(
        repo_url="https://github.com/example/app",
        affected_version="v1.0.0",
        fixed_version="v1.0.1",
    )

    with pytest.raises(ValueError, match="sink_signature"):
        VulnerabilityInput(
            target=target,
            description="Open redirect through user-controlled next parameter.",
            mode=InputMode.KNOWN_SINK,
        )


def test_known_sink_input_accepts_signature() -> None:
    target = AnalysisTarget(
        repo_url="https://github.com/example/app",
        affected_version="v1.0.0",
        fixed_version="v1.0.1",
        language="python",
    )
    sink = FunctionSignature(
        raw="flask.redirect(location)",
        name="redirect",
        parameters=("location",),
        language="python",
    )

    task_input = VulnerabilityInput(
        target=target,
        description="Open redirect through user-controlled next parameter.",
        mode=InputMode.KNOWN_SINK,
        sink_signature=sink,
        vulnerable_snippet='return redirect(request.args["next"])',
    )

    assert task_input.sink_signature == sink
    assert task_input.target.language == "python"


def test_unknown_sink_input_can_start_from_description_only() -> None:
    target = AnalysisTarget(
        repo_url="https://github.com/example/app",
        affected_version="v1.0.0",
        fixed_version=None,
        introduced_version="v0.9.0",
    )

    task_input = VulnerabilityInput(
        target=target,
        description="A request parameter may flow into a dangerous redirect API.",
        mode=InputMode.UNKNOWN_SINK,
    )

    assert task_input.sink_signature is None
    assert task_input.target.introduced_version == "v0.9.0"


def test_evidence_confidence_must_be_in_range() -> None:
    with pytest.raises(ValueError, match="confidence"):
        Evidence(
            source=SourceReference(kind=EvidenceKind.HUMAN_INPUT),
            summary="Invalid confidence.",
            reasoning="The confidence value is outside the accepted range.",
            confidence=1.5,
        )


def test_taint_path_links_source_and_sink_with_evidence() -> None:
    location = CodeLocation(path="app/routes.py", start_line=12, start_col=16)
    evidence = Evidence(
        source=SourceReference(
            kind=EvidenceKind.CODE_LOCATION,
            location=location,
        ),
        summary="request.args reaches redirect.",
        reasoning="The same function reads the parameter and passes it to redirect.",
        confidence=0.8,
        reproducible_steps=("inspect app/routes.py:12",),
    )
    source = SourceCandidate(
        name="request.args['next']",
        location=location,
        reason="User-controlled query parameter.",
        confidence=0.8,
        evidence=(evidence,),
    )
    sink = SinkCandidate(
        signature=FunctionSignature(raw="redirect(location)", name="redirect"),
        reason="redirect can send users to attacker-controlled locations.",
        confidence=0.8,
        evidence=(evidence,),
    )

    path = TaintPath(
        source=source,
        sink=sink,
        steps=(TaintStep(location=location, symbol="redirect", evidence=(evidence,)),),
        reachable=True,
        evidence=(evidence,),
    )

    assert path.reachable is True
    assert path.steps[0].symbol == "redirect"
