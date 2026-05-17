from urllib.parse import urlsplit

import pytest

from semgrep_llm_vul.managed_fixtures import (
    ManagedFixtureError,
    managed_fixture_targets,
)


def test_managed_fixture_targets_returns_loopback_pair() -> None:
    with managed_fixture_targets("open_redirect_pair") as targets:
        assert targets.name == "open_redirect_pair"
        assert targets.affected_base_url.startswith("http://127.0.0.1:")
        assert targets.fixed_base_url.startswith("http://127.0.0.1:")


def test_managed_fixture_targets_rejects_unknown_name() -> None:
    with pytest.raises(ManagedFixtureError, match="不支持的 managed fixture"):
        with managed_fixture_targets("unknown_fixture"):
            pass


def test_managed_fixture_targets_uses_fresh_ports_across_runs() -> None:
    with managed_fixture_targets("open_redirect_pair") as first:
        first_ports = {
            urlsplit(first.affected_base_url).port,
            urlsplit(first.fixed_base_url).port,
        }
    with managed_fixture_targets("open_redirect_pair") as second:
        second_ports = {
            urlsplit(second.affected_base_url).port,
            urlsplit(second.fixed_base_url).port,
        }
    assert first_ports.isdisjoint(second_ports)


def test_managed_fixture_targets_supports_meta_refresh_pair() -> None:
    with managed_fixture_targets("open_redirect_meta_refresh_pair") as targets:
        assert targets.name == "open_redirect_meta_refresh_pair"
        assert targets.affected_base_url.startswith("http://127.0.0.1:")
        assert targets.fixed_base_url.startswith("http://127.0.0.1:")


def test_managed_fixture_targets_supports_refresh_header_pair() -> None:
    with managed_fixture_targets("open_redirect_refresh_header_pair") as targets:
        assert targets.name == "open_redirect_refresh_header_pair"
        assert targets.affected_base_url.startswith("http://127.0.0.1:")
        assert targets.fixed_base_url.startswith("http://127.0.0.1:")
