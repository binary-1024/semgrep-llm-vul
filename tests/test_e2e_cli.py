import json
from pathlib import Path

from semgrep_llm_vul.cli import main
from tests.helpers import run_open_redirect_server

ROOT = Path(__file__).resolve().parent.parent


def _run_cli_json(capsys, argv: list[str]) -> dict:
    exit_code = main(argv)
    captured = capsys.readouterr()
    assert exit_code == 0, captured.err
    return json.loads(captured.out)


def test_e2e_cli_offline_open_redirect_flow(capsys) -> None:
    analysis_path = str(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    sink_semgrep_json = str(ROOT / "fixtures" / "semgrep" / "basic-result.json")
    taint_semgrep_json = str(
        ROOT / "fixtures" / "semgrep" / "taint-result-with-source-control-local-var-trace.json"
    )
    source_root = str(ROOT / "fixtures" / "reachability" / "flask-source-control-local-var-app")
    execution_json = str(ROOT / "fixtures" / "execution" / "open-redirect-verified.json")

    sink_report = _run_cli_json(
        capsys,
        [
            "generate-sinks",
            analysis_path,
            "--semgrep-json",
            sink_semgrep_json,
        ],
    )
    assert sink_report["kind"] == "sink_generation_report"
    assert sink_report["recommended"]["signature"]["name"] == "redirect"

    taint_report = _run_cli_json(
        capsys,
        [
            "generate-taint-paths",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
        ],
    )
    assert taint_report["kind"] == "taint_path_generation_report"
    assert taint_report["paths"][0]["sink"]["signature"]["name"] == "redirect"
    assert taint_report["paths"][0]["reachable"] is None

    reachability_report = _run_cli_json(
        capsys,
        [
            "confirm-reachability",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
            "--source-root",
            source_root,
        ],
    )
    assert reachability_report["kind"] == "reachability_report"
    assert reachability_report["assessments"][0]["reachable"] is True
    assert reachability_report["assessments"][0]["entrypoint"]["name"] == "GET /login"

    poc_report = _run_cli_json(
        capsys,
        [
            "generate-poc",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
            "--source-root",
            source_root,
        ],
    )
    assert poc_report["kind"] == "poc_generation_report"
    assert poc_report["plans"][0]["request"]["path"] == "/login"
    assert poc_report["plans"][0]["trigger_input"]["name"] == "next"
    assert poc_report["plans"][0]["execution_state"] == "not_run"

    verification_report = _run_cli_json(
        capsys,
        [
            "verify-exp",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
            "--source-root",
            source_root,
            "--execution-json",
            execution_json,
        ],
    )
    assert verification_report["kind"] == "exp_verification_report"
    assert verification_report["verifications"][0]["verdict"] == "verified"
    assert verification_report["verifications"][0]["affected"]["effect_state"] == "effect_observed"
    assert (
        verification_report["verifications"][0]["fixed"]["effect_state"]
        == "effect_not_observed"
    )


def test_e2e_cli_live_open_redirect_flow(capsys) -> None:
    analysis_path = str(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    sink_semgrep_json = str(ROOT / "fixtures" / "semgrep" / "basic-result.json")
    taint_semgrep_json = str(
        ROOT / "fixtures" / "semgrep" / "taint-result-with-source-control-local-var-trace.json"
    )
    source_root = str(ROOT / "fixtures" / "reachability" / "flask-source-control-local-var-app")

    sink_report = _run_cli_json(
        capsys,
        [
            "generate-sinks",
            analysis_path,
            "--semgrep-json",
            sink_semgrep_json,
        ],
    )
    assert sink_report["recommended"]["signature"]["name"] == "redirect"

    taint_report = _run_cli_json(
        capsys,
        [
            "generate-taint-paths",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
        ],
    )
    assert taint_report["paths"][0]["sink"]["signature"]["name"] == "redirect"

    reachability_report = _run_cli_json(
        capsys,
        [
            "confirm-reachability",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
            "--source-root",
            source_root,
        ],
    )
    assert reachability_report["assessments"][0]["reachable"] is True

    poc_report = _run_cli_json(
        capsys,
        [
            "generate-poc",
            analysis_path,
            "--semgrep-json",
            taint_semgrep_json,
            "--source-root",
            source_root,
        ],
    )
    assert poc_report["plans"][0]["request"]["path"] == "/login"

    with (
        run_open_redirect_server("affected") as affected_base_url,
        run_open_redirect_server("fixed") as fixed_base_url,
    ):
        verification_report = _run_cli_json(
            capsys,
            [
                "verify-exp",
                analysis_path,
                "--semgrep-json",
                taint_semgrep_json,
                "--source-root",
                source_root,
                "--affected-base-url",
                affected_base_url,
                "--fixed-base-url",
                fixed_base_url,
            ],
        )

    assert verification_report["kind"] == "exp_verification_report"
    assert verification_report["verifications"][0]["verdict"] == "verified"
    assert verification_report["verifications"][0]["affected"]["execution_state"] == "completed"
    assert (
        verification_report["verifications"][0]["fixed"]["effect_state"]
        == "effect_not_observed"
    )
