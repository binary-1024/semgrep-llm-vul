import json
import os
from pathlib import Path

from semgrep_llm_vul.cli import main

ROOT = Path(__file__).resolve().parent.parent


def test_validate_input_cli_accepts_valid_file(capsys) -> None:
    exit_code = main(
        [
            "validate-input",
            str(ROOT / "examples" / "analysis" / "known-sink.yaml"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "valid analysis input" in captured.out
    assert "mode=known_sink" in captured.out


def test_validate_input_cli_rejects_invalid_file(capsys) -> None:
    exit_code = main(
        [
            "validate-input",
            str(
                ROOT
                / "fixtures"
                / "analysis"
                / "invalid-known-sink-missing-signature.yaml"
            ),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "invalid analysis input" in captured.err
    assert "sink_signature" in captured.err


def test_generate_sinks_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "generate-sinks",
            str(ROOT / "examples" / "analysis" / "unknown-sink.yaml"),
            "--semgrep-json",
            str(ROOT / "fixtures" / "semgrep" / "basic-result.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "sink_generation_report"
    assert report["mode"] == "unknown_sink"
    assert report["recommended"]["signature"]["name"] == "redirect"
    assert report["recommended"]["evidence"]


def test_generate_sinks_cli_returns_error_for_bad_artifact(capsys) -> None:
    exit_code = main(
        [
            "generate-sinks",
            str(ROOT / "fixtures" / "sink" / "unknown-sink-missing-diff.yaml"),
            "--artifact-base",
            str(ROOT),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "generate sinks failed" in captured.err
    assert "无法读取 diff artifact" in captured.err


def test_generate_taint_paths_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "generate-taint-paths",
            str(ROOT / "examples" / "analysis" / "unknown-sink.yaml"),
            "--semgrep-json",
            str(ROOT / "fixtures" / "semgrep" / "taint-result-with-trace.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "taint_path_generation_report"
    assert report["mode"] == "unknown_sink"
    assert report["paths"][0]["sink"]["signature"]["name"] == "redirect"
    assert report["paths"][0]["reachable"] is None
    assert report["paths"][0]["steps"]


def test_generate_taint_paths_cli_reports_missing_semgrep_paths(capsys) -> None:
    exit_code = main(
        [
            "generate-taint-paths",
            str(ROOT / "examples" / "analysis" / "unknown-sink.yaml"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["paths"] == []
    assert "缺少 sink candidate" in report["unknowns"][0]
    assert "缺少 Semgrep taint path 候选。" in report["unknowns"]


def test_confirm_reachability_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "confirm-reachability",
            str(ROOT / "examples" / "analysis" / "unknown-sink.yaml"),
            "--semgrep-json",
            str(ROOT / "fixtures" / "semgrep" / "taint-result-with-trace.json"),
            "--reachability-json",
            str(ROOT / "fixtures" / "reachability" / "open-redirect-reachable.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "reachability_report"
    assert report["assessments"][0]["reachable"] is True
    assert report["assessments"][0]["path"]["reachable"] is True
    assert report["assessments"][0]["entrypoint"]["kind"] == "flask_route"


def test_confirm_reachability_cli_can_extract_flask_source_root(capsys) -> None:
    exit_code = main(
        [
            "confirm-reachability",
            str(ROOT / "examples" / "analysis" / "unknown-sink.yaml"),
            "--semgrep-json",
            str(ROOT / "fixtures" / "semgrep" / "taint-result-with-trace.json"),
            "--source-root",
            str(ROOT / "fixtures" / "reachability" / "flask-app"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "reachability_report"
    assert report["assessments"][0]["reachable"] is True
    assert report["assessments"][0]["entrypoint"]["name"] == "GET /login"


def test_evaluate_case_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "evaluate-case",
            str(ROOT / "benchmarks" / "cases" / "curated-open-redirect-safe-wrapper"),
            "--repo-root",
            str(ROOT),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "benchmark_case_evaluation"
    assert report["case_id"] == "curated-open-redirect-safe-wrapper"
    assert report["passed"] is True


def test_evaluate_cases_cli_outputs_json_report(capsys) -> None:
    exit_code = main(
        [
            "evaluate-cases",
            str(ROOT / "benchmarks" / "cases"),
            "--repo-root",
            str(ROOT),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "benchmark_case_suite_evaluation"
    assert report["total"] == 15
    assert report["passed"] is True


def test_evaluate_cases_cli_outputs_summary_report(capsys) -> None:
    exit_code = main(
        [
            "evaluate-cases",
            str(ROOT / "benchmarks" / "cases"),
            "--repo-root",
            str(ROOT),
            "--summary-only",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["kind"] == "benchmark_case_suite_summary"
    assert report["total"] == 15
    assert report["passed"] is True
    assert all("sink_report" not in item for item in report["cases"])


def test_validate_benchmarks_cli_outputs_inventory(capsys) -> None:
    exit_code = main(
        [
            "validate-benchmarks",
            str(ROOT / "benchmarks" / "cases"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    inventory = json.loads(captured.out)
    assert inventory["kind"] == "benchmark_case_inventory"
    assert inventory["summary"]["total"] == 17
    assert inventory["summary"]["candidate"] == 15


def test_benchmark_summary_cli_outputs_short_json(capsys) -> None:
    exit_code = main(
        [
            "benchmark-summary",
            str(ROOT / "benchmarks" / "cases"),
            "--artifact-base",
            str(ROOT),
            "--repo-root",
            str(ROOT),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    summary = json.loads(captured.out)
    assert summary["kind"] == "benchmark_summary"
    assert summary["passed"] is True
    assert summary["inventory"]["summary"]["total"] == 17
    assert summary["evaluation"]["summary"]["unsupported"] == 5
    assert summary["executable_suite"]["total"] == 15
    assert "cases" not in summary


def test_benchmark_baseline_cli_outputs_markdown(capsys) -> None:
    exit_code = main(
        [
            "benchmark-baseline",
            str(ROOT / "benchmarks" / "cases"),
            "--artifact-base",
            str(ROOT),
            "--repo-root",
            str(ROOT),
            "--markdown",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "# Benchmark Baseline" in captured.out
    assert "| total | 17 |" in captured.out
    assert "`curated-open-redirect-reachability`" in captured.out


def test_benchmark_script_is_executable() -> None:
    script = ROOT / "scripts" / "benchmark"

    assert script.exists()
    assert os.access(script, os.X_OK)


def test_benchmark_summary_script_is_executable() -> None:
    script = ROOT / "scripts" / "benchmark-summary"

    assert script.exists()
    assert os.access(script, os.X_OK)
