import json
import shutil
from pathlib import Path

from semgrep_llm_vul.benchmark_cases import evaluate_benchmark_case

ROOT = Path(__file__).resolve().parent.parent
CASE_DIR = ROOT / "benchmarks" / "cases" / "curated-open-redirect-safe-wrapper"


def test_evaluate_benchmark_case_passes_curated_m1_case() -> None:
    result = evaluate_benchmark_case(CASE_DIR, repo_root=ROOT)

    assert result["kind"] == "benchmark_case_evaluation"
    assert result["case_id"] == "curated-open-redirect-safe-wrapper"
    assert result["stage"] == "M1"
    assert result["passed"] is True
    assert all(check["passed"] for check in result["checks"])
    assert result["sink_report"]["recommended"]["signature"]["name"] == "redirect"


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
