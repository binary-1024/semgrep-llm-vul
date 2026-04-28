from pathlib import Path

import pytest

from semgrep_llm_vul import (
    AnalysisArtifact,
    AnalysisTarget,
    CodeLocation,
    FunctionSignature,
    InputMode,
    NormalizedFinding,
    SinkGenerationReport,
    VulnerabilityInput,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings
from semgrep_llm_vul.sink_generation import SinkGenerationError, generate_sink_report

ROOT = Path(__file__).resolve().parent.parent


def test_known_sink_generates_high_confidence_candidate() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect through user-controlled next parameter.",
        mode=InputMode.KNOWN_SINK,
        sink_signature=FunctionSignature(
            raw="flask.redirect(location)",
            name="redirect",
            language="python",
        ),
        vulnerable_snippet='return redirect(request.args["next"])',
    )

    report = generate_sink_report(task)

    assert isinstance(report, SinkGenerationReport)
    assert report.recommended is not None
    assert report.recommended.signature.raw == "flask.redirect(location)"
    assert report.recommended.confidence >= 0.9
    assert report.recommended.evidence
    assert "用户显式提供 sink signature" in report.recommended.reason


def test_unknown_sink_uses_semgrep_finding_as_candidate_evidence() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="The application may redirect users to an attacker-controlled URL.",
        mode=InputMode.UNKNOWN_SINK,
    )
    findings = tuple(load_semgrep_findings(ROOT / "fixtures" / "semgrep" / "basic-result.json"))

    report = generate_sink_report(task, semgrep_findings=findings)

    assert report.recommended is not None
    assert report.recommended.signature.name == "redirect"
    assert report.recommended.signature.location is not None
    assert report.recommended.signature.location.path == "app/routes.py"
    assert report.recommended.evidence
    assert report.recommended.evidence[-1].source.metadata["heuristic_name"] == "open_redirect"
    assert report.recommended.evidence[-1].source.metadata["heuristic_category"] == "open_redirect"
    assert "Semgrep finding 是静态候选证据" in report.recommended.evidence[-1].reasoning


def test_unknown_sink_uses_diff_artifact_candidate() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect was fixed by validating the redirect target.",
        mode=InputMode.UNKNOWN_SINK,
        artifacts=(
            AnalysisArtifact(
                kind="diff",
                path="fixtures/sink/open-redirect-fix.diff",
            ),
        ),
    )

    report = generate_sink_report(task, artifact_base=ROOT)

    assert report.recommended is not None
    assert report.recommended.signature.name == "redirect"
    assert report.recommended.signature.location is not None
    assert report.recommended.signature.location.path == "app/routes.py"
    assert report.recommended.signature.location.start_line == 9
    assert report.recommended.evidence[0].source.kind.value == "diff"
    assert {item.source.metadata["diff_side"] for item in report.recommended.evidence} == {
        "added",
        "removed",
    }
    assert {item.source.metadata["heuristic_name"] for item in report.recommended.evidence} == {
        "open_redirect",
    }
    assert {item.source.metadata["heuristic_category"] for item in report.recommended.evidence} == {
        "open_redirect",
    }
    evidence_lines = {
        item.source.location.start_line
        for item in report.recommended.evidence
        if item.source.location
    }
    assert evidence_lines == {
        9,
        12,
    }
    assert report.recommended.confidence >= 0.6


def test_combined_diff_and_semgrep_evidence_ranks_same_candidate_higher() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="Open redirect was fixed by validating the redirect target.",
        mode=InputMode.UNKNOWN_SINK,
        artifacts=(
            AnalysisArtifact(
                kind="diff",
                path="fixtures/sink/open-redirect-fix.diff",
            ),
        ),
    )
    findings = tuple(load_semgrep_findings(ROOT / "fixtures" / "semgrep" / "basic-result.json"))

    report = generate_sink_report(task, semgrep_findings=findings, artifact_base=ROOT)

    assert report.recommended is not None
    assert report.recommended.signature.name == "redirect"
    assert report.recommended.confidence > 0.9
    assert len(report.recommended.evidence) >= 2


def test_insufficient_evidence_does_not_fabricate_recommendation() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            language="python",
        ),
        description="Something may be unsafe, but no code or diff evidence is available.",
        mode=InputMode.UNKNOWN_SINK,
    )

    report = generate_sink_report(task)

    assert report.candidates == ()
    assert report.recommended is None
    assert "证据不足" in report.unknowns[-1]


def test_safe_diff_does_not_match_dangerous_call_by_substring() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            fixed_version="v1.0.1",
            language="python",
        ),
        description="The patch replaces an unsafe redirect with validation and a safe render path.",
        mode=InputMode.UNKNOWN_SINK,
        artifacts=(
            AnalysisArtifact(
                kind="diff",
                path="fixtures/sink/safe-redirect-fix.diff",
            ),
        ),
    )

    report = generate_sink_report(task, artifact_base=ROOT)

    assert report.candidates == ()
    assert report.recommended is None
    assert (
        "diff artifact fixtures/sink/safe-redirect-fix.diff 未发现可识别危险调用。"
        in report.unknowns
    )
    assert "证据不足，无法推荐 sink candidate。" in report.unknowns


def test_safe_snippet_does_not_match_dangerous_call_by_substring() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            language="python",
        ),
        description="Snippet calls a safety wrapper rather than a direct redirect sink.",
        mode=InputMode.UNKNOWN_SINK,
        vulnerable_snippet='return safe_redirect(request.args["next"])',
    )

    report = generate_sink_report(task)

    assert report.candidates == ()
    assert report.recommended is None
    assert "vulnerable_snippet 未发现可识别危险调用。" in report.unknowns
    assert "证据不足，无法推荐 sink candidate。" in report.unknowns


def test_semgrep_rule_id_does_not_fabricate_sink_without_call_evidence() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            language="python",
        ),
        description=(
            "Finding metadata mentions redirect, but matched code only calls a safe wrapper."
        ),
        mode=InputMode.UNKNOWN_SINK,
    )
    finding = NormalizedFinding(
        tool="semgrep",
        rule_id="python.flask.open-redirect",
        message="Potential redirect issue",
        severity="WARNING",
        location=CodeLocation(path="app/routes.py", start_line=10),
        language="python",
        code='return safe_redirect(request.args["next"])',
    )

    report = generate_sink_report(task, semgrep_findings=(finding,))

    assert report.candidates == ()
    assert report.recommended is None
    assert (
        "Semgrep finding python.flask.open-redirect 缺少可识别调用表达式，无法生成 sink candidate。"
        in report.unknowns
    )
    assert "证据不足，无法推荐 sink candidate。" in report.unknowns


def test_malformed_diff_artifact_raises_structured_error() -> None:
    task = VulnerabilityInput(
        target=AnalysisTarget(
            repo_url="https://github.com/example/flask-app",
            affected_version="v1.0.0",
            language="python",
        ),
        description="Open redirect was fixed by validating the redirect target.",
        mode=InputMode.UNKNOWN_SINK,
        artifacts=(AnalysisArtifact(kind="diff", path="fixtures/sink/missing.diff"),),
    )

    with pytest.raises(SinkGenerationError, match="无法读取 diff artifact"):
        generate_sink_report(task, artifact_base=ROOT)
