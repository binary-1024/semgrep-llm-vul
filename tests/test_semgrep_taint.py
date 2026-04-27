from pathlib import Path

from semgrep_llm_vul import TaintRole
from semgrep_llm_vul.semgrep import (
    load_semgrep_findings,
    load_semgrep_taint_paths,
    normalize_semgrep_taint_paths,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep"


def test_load_semgrep_taint_paths_from_trace_fixture() -> None:
    paths = load_semgrep_taint_paths(FIXTURE_DIR / "taint-result-with-trace.json")

    assert len(paths) == 1
    path = paths[0]
    assert path.reachable is None
    assert path.source.name == 'request.args["next"]'
    assert path.source.location.start_line == 14
    assert path.sink.signature.raw == "redirect(next_url)"
    assert path.sink.signature.raw != "CliLoc"
    assert path.sink.signature.language == "python"
    assert [step.role for step in path.steps] == [
        TaintRole.SOURCE,
        TaintRole.INTERMEDIATE,
        TaintRole.SINK,
    ]
    assert path.steps[1].symbol == "next_url"
    assert path.steps[0].symbol == 'request.args["next"]'
    assert path.steps[2].symbol == "redirect(next_url)"
    assert path.evidence[0].source.metadata["rule_id"] == "python.flask.open-redirect-taint"
    assert "raw_trace" in path.evidence[0].source.metadata
    assert "尚未完成可触达确认" in path.evidence[0].open_questions[1]


def test_taint_finding_without_trace_still_normalizes_as_finding() -> None:
    fixture = FIXTURE_DIR / "taint-result-without-trace.json"

    findings = load_semgrep_findings(fixture)
    paths = load_semgrep_taint_paths(fixture)

    assert len(findings) == 1
    assert findings[0].rule_id == "python.flask.open-redirect-taint"
    assert paths == []


def test_generated_semgrep_fixture_normalizes_as_finding() -> None:
    fixture = FIXTURE_DIR / "taint-result-generated.json"

    findings = load_semgrep_findings(fixture)
    paths = load_semgrep_taint_paths(fixture)

    assert len(findings) == 1
    assert findings[0].location.path == "examples/semgrep/project/app/routes.py"
    assert findings[0].severity == "WARNING"
    assert paths == []


def test_malformed_trace_does_not_create_misleading_path() -> None:
    paths = load_semgrep_taint_paths(FIXTURE_DIR / "taint-result-malformed-trace.json")

    assert paths == []


def test_normalize_semgrep_taint_paths_requires_results_list() -> None:
    try:
        normalize_semgrep_taint_paths({"results": {}})
    except Exception as exc:
        assert "results" in str(exc)
    else:
        raise AssertionError("expected invalid Semgrep JSON to fail")
