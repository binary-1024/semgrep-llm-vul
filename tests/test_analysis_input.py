from pathlib import Path

import pytest

from semgrep_llm_vul import InputMode
from semgrep_llm_vul.analysis_input import AnalysisInputError, load_analysis_input

ROOT = Path(__file__).resolve().parent.parent


def test_load_known_sink_yaml() -> None:
    task = load_analysis_input(ROOT / "examples" / "analysis" / "known-sink.yaml")

    assert task.mode is InputMode.KNOWN_SINK
    assert task.target.repo_url == "https://github.com/example/flask-app"
    assert task.target.affected_version == "v1.0.0"
    assert task.sink_signature is not None
    assert task.sink_signature.raw == "flask.redirect(location)"
    assert task.sink_signature.location is not None
    assert task.sink_signature.location.start_line == 16
    assert task.candidate_prs == ("https://github.com/example/flask-app/pull/123",)
    assert task.artifacts[0].kind == "advisory"
    assert task.artifacts[0].sensitive is False


def test_load_unknown_sink_yaml() -> None:
    task = load_analysis_input(ROOT / "examples" / "analysis" / "unknown-sink.yaml")

    assert task.mode is InputMode.UNKNOWN_SINK
    assert task.sink_signature is None
    assert "attacker-controlled URL" in task.description
    assert task.artifacts[0].path == "docs/advisory.md"


def test_load_known_sink_json() -> None:
    task = load_analysis_input(ROOT / "examples" / "analysis" / "known-sink.json")

    assert task.mode is InputMode.KNOWN_SINK
    assert task.sink_signature is not None
    assert task.sink_signature.parameters == ("location",)
    assert task.artifacts[0].uri == "https://example.com/advisories/open-redirect"


def test_known_sink_requires_signature() -> None:
    with pytest.raises(AnalysisInputError, match="sink_signature"):
        load_analysis_input(
            ROOT / "fixtures" / "analysis" / "invalid-known-sink-missing-signature.yaml"
        )


def test_unsupported_schema_version_fails() -> None:
    with pytest.raises(AnalysisInputError, match="schema_version"):
        load_analysis_input(ROOT / "fixtures" / "analysis" / "invalid-schema-version.yaml")


def test_artifact_requires_uri_or_path() -> None:
    with pytest.raises(AnalysisInputError, match="uri 或 path"):
        load_analysis_input(
            ROOT / "fixtures" / "analysis" / "invalid-artifact-missing-reference.yaml"
        )


def test_location_line_rejects_bool() -> None:
    with pytest.raises(AnalysisInputError, match="location.start_line"):
        load_analysis_input(ROOT / "fixtures" / "analysis" / "invalid-location-bool-line.yaml")
