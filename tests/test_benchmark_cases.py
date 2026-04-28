import json
import shutil
from pathlib import Path

import pytest

from semgrep_llm_vul.benchmark_cases import evaluate_benchmark_case

ROOT = Path(__file__).resolve().parent.parent
CASES_ROOT = ROOT / "benchmarks" / "cases"
CASE_DIR = CASES_ROOT / "curated-open-redirect-safe-wrapper"


@pytest.mark.parametrize(
    ("case_id", "recommended_name"),
    [
        ("curated-open-redirect-safe-wrapper", "redirect"),
        ("curated-command-execution-system", "system"),
        ("curated-deserialization-deserialize", "deserialize"),
        ("curated-open-redirect-safe-negative", None),
    ],
)
def test_evaluate_benchmark_case_passes_curated_m1_cases(
    case_id: str,
    recommended_name: str | None,
) -> None:
    result = evaluate_benchmark_case(CASES_ROOT / case_id, repo_root=ROOT)

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == case_id
    assert result["stage"] == "M1"
    assert result["passed"] is True
    assert all(check["passed"] for check in result["checks"])
    recommended = result["sink_report"]["recommended"]
    if recommended_name is None:
        assert recommended is None
    else:
        assert recommended["signature"]["name"] == recommended_name


def test_evaluate_benchmark_case_reports_failed_expected_sink(tmp_path) -> None:
    case_dir = tmp_path / "case"
    shutil.copytree(CASE_DIR, case_dir)
    expected_path = case_dir / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    expected["sink_candidates"][0]["name"] = "missing_sink"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")

    result = evaluate_benchmark_case(case_dir, repo_root=ROOT)

    assert result["passed"] is False
    assert result["checks"][0]["name"] == "expected_sink[0]"
    assert result["checks"][0]["passed"] is False
