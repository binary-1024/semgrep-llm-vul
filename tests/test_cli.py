import json
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
