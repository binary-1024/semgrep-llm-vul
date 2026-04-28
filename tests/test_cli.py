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
