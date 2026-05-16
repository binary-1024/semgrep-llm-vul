"""仓库内置的受控 managed fixture runtime。"""

from __future__ import annotations

import http.client
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

_HEALTH_PATH = "/__semgrep_llm_vul_health"


class ManagedFixtureError(ValueError):
    """受控 fixture 启停失败或输入非法。"""


@dataclass(frozen=True)
class ManagedFixtureTargets:
    """一个受控 fixture 对外暴露的 affected/fixed base URL。"""

    name: str
    affected_base_url: str
    fixed_base_url: str


@contextmanager
def managed_fixture_targets(
    name: str,
    *,
    timeout_seconds: float = 5.0,
):
    """启动仓库内置的受控 fixture 对，并在结束时清理。"""

    if timeout_seconds <= 0:
        raise ManagedFixtureError("timeout_seconds 必须为正数")

    if name != "open_redirect_pair":
        raise ManagedFixtureError(f"不支持的 managed fixture：{name}")

    with (
        _run_open_redirect_server("affected", timeout_seconds=timeout_seconds) as affected_base_url,
        _run_open_redirect_server("fixed", timeout_seconds=timeout_seconds) as fixed_base_url,
    ):
        yield ManagedFixtureTargets(
            name=name,
            affected_base_url=affected_base_url,
            fixed_base_url=fixed_base_url,
        )


@contextmanager
def _run_open_redirect_server(mode: str, *, timeout_seconds: float):
    if mode not in {"affected", "fixed"}:
        raise ManagedFixtureError(f"unsupported fixture mode: {mode}")

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path == _HEALTH_PATH:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            if parsed.path != "/login":
                self.send_response(404)
                self.end_headers()
                return
            next_url = parse_qs(parsed.query).get("next", ["/"])[0]
            location = next_url if mode == "affected" and next_url else "/"
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        _wait_until_ready(base_url, timeout_seconds=timeout_seconds)
        yield base_url
    except Exception as exc:
        raise ManagedFixtureError(
            f"{mode} managed fixture 启动失败：{exc}"
        ) from exc
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _wait_until_ready(base_url: str, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    parsed = urlsplit(base_url)
    host = parsed.hostname
    port = parsed.port
    if host is None or port is None:
        raise ManagedFixtureError(f"fixture base URL 非法：{base_url}")
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection(host, port, timeout=0.5)
            connection.request("GET", _HEALTH_PATH)
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
            last_error = ManagedFixtureError(
                f"fixture readiness 状态码异常：{response.status}"
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.01)
    raise ManagedFixtureError(
        f"fixture readiness 超时：{base_url}"
    ) from last_error
