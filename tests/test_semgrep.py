from pathlib import Path

import pytest

from semgrep_llm_vul.semgrep import (
    SemgrepParseError,
    load_semgrep_findings,
    normalize_semgrep_results,
)

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep"


def test_load_semgrep_findings_from_fixture() -> None:
    findings = load_semgrep_findings(FIXTURE_DIR / "basic-result.json")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "semgrep"
    assert finding.rule_id == "python.flask.open-redirect"
    assert finding.severity == "WARNING"
    assert finding.language == "python"
    assert finding.location.path == "app/routes.py"
    assert finding.location.start_line == 12
    assert finding.code == 'return redirect(request.args["next"])'
    assert finding.evidence[0].source.metadata["rule_id"] == "python.flask.open-redirect"


def test_normalize_semgrep_results_infers_language_from_path() -> None:
    findings = normalize_semgrep_results(
        {
            "results": [
                {
                    "check_id": "generic.dangerous-call",
                    "path": "src/main.go",
                    "start": {"line": 3, "col": 1},
                    "end": {"line": 3, "col": 10},
                    "extra": {
                        "message": "dangerous call",
                        "severity": "ERROR",
                    },
                }
            ]
        }
    )

    assert findings[0].language == "go"
    assert findings[0].location.end_col == 10


def test_normalize_semgrep_results_requires_results_list() -> None:
    with pytest.raises(SemgrepParseError, match="results"):
        normalize_semgrep_results({"results": {}})


def test_normalize_semgrep_results_requires_rule_id_and_path() -> None:
    with pytest.raises(SemgrepParseError, match="check_id"):
        normalize_semgrep_results({"results": [{"path": "app.py", "extra": {}}]})
