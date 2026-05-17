import pytest

from semgrep_llm_vul.exp_verification import (
    ExpVerificationReport,
    LocalExecutionError,
    collect_local_execution_records,
    collect_managed_fixture_execution_records,
    generate_exp_verification_report,
)
from tests.helpers import (
    build_open_redirect_poc_report,
    run_open_redirect_server,
    unused_loopback_base_url,
)


def test_collect_local_execution_records_returns_verified_for_loopback_targets() -> None:
    task, poc_report = build_open_redirect_poc_report()
    execution_records = collect_managed_fixture_execution_records(
        poc_report,
        fixture_name="open_redirect_pair",
    )

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=execution_records,
    )

    assert isinstance(report, ExpVerificationReport)
    verification = report.verifications[0]
    assert verification.verdict.value == "verified"
    assert verification.affected.execution_state.value == "completed"
    assert verification.affected.effect_state.value == "effect_observed"
    assert verification.fixed.execution_state.value == "completed"
    assert verification.fixed.effect_state.value == "effect_not_observed"


def test_collect_local_execution_records_marks_missing_fixed_target_as_inconclusive() -> None:
    task, poc_report = build_open_redirect_poc_report()

    with run_open_redirect_server("affected") as affected_base_url:
        execution_records = collect_local_execution_records(
            poc_report,
            affected_base_url=affected_base_url,
            fixed_base_url=unused_loopback_base_url(),
        )

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=execution_records,
    )

    verification = report.verifications[0]
    assert verification.verdict.value == "inconclusive"
    assert verification.affected.execution_state.value == "completed"
    assert verification.fixed.execution_state.value == "environment_missing"
    assert any("fixed 版本执行未完成" in item for item in verification.unknowns)


def test_collect_local_execution_records_rejects_non_loopback_targets() -> None:
    _, poc_report = build_open_redirect_poc_report()

    with pytest.raises(LocalExecutionError, match="localhost/127.0.0.1/::1"):
        collect_local_execution_records(
            poc_report,
            affected_base_url="http://example.com:8080",
        )


def test_collect_managed_fixture_execution_records_supports_meta_refresh_fixture() -> None:
    task, poc_report = build_open_redirect_poc_report()
    execution_records = collect_managed_fixture_execution_records(
        poc_report,
        fixture_name="open_redirect_meta_refresh_pair",
    )

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=execution_records,
    )

    verification = report.verifications[0]
    assert verification.verdict.value == "verified"
    assert verification.affected.status_code == 200
    assert verification.affected.effect_state.value == "effect_observed"
    assert verification.affected.response_body_excerpt is not None
    assert "meta http-equiv" in verification.affected.response_body_excerpt


def test_collect_managed_fixture_execution_records_supports_refresh_header_fixture() -> None:
    task, poc_report = build_open_redirect_poc_report()
    execution_records = collect_managed_fixture_execution_records(
        poc_report,
        fixture_name="open_redirect_refresh_header_pair",
    )

    report = generate_exp_verification_report(
        task,
        poc_report=poc_report,
        execution_records=execution_records,
    )

    verification = report.verifications[0]
    assert verification.verdict.value == "verified"
    assert verification.affected.status_code == 200
    assert verification.affected.effect_state.value == "effect_observed"
    assert (
        dict(verification.affected.response_headers)["Refresh"]
        == "0; url=https://attacker.example/poc"
    )
    assert verification.affected.response_body_excerpt == "<html><body>redirecting</body></html>"
