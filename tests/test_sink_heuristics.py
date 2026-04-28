import pytest

from semgrep_llm_vul.sink_heuristics import SinkHeuristic, find_sink_heuristic_matches


def test_finds_default_sink_heuristic_by_short_call_name() -> None:
    matches = find_sink_heuristic_matches("return flask.redirect(next_url)")

    assert len(matches) == 1
    assert matches[0].call_name == "flask.redirect"
    assert matches[0].heuristic.name == "open_redirect"
    assert matches[0].heuristic.category == "open_redirect"


def test_does_not_match_safe_wrapper_by_substring() -> None:
    matches = find_sink_heuristic_matches("return safe_redirect(next_url)")

    assert matches == ()


def test_respects_optional_language_scope() -> None:
    heuristic = SinkHeuristic(
        name="python_only_eval",
        call_names=("eval",),
        category="code_execution",
        languages=("python",),
    )

    assert find_sink_heuristic_matches(
        "eval(user_input)",
        language="python",
        heuristics=(heuristic,),
    )
    assert not find_sink_heuristic_matches(
        "eval(user_input)",
        language="javascript",
        heuristics=(heuristic,),
    )


def test_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        SinkHeuristic(
            name="invalid",
            call_names=("eval",),
            category="code_execution",
            confidence=1.5,
        )
