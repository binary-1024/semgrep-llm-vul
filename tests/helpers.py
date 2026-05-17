from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from semgrep_llm_vul.analysis_input import load_analysis_input
from semgrep_llm_vul.poc_generation import generate_poc_report
from semgrep_llm_vul.reachability import (
    discover_flask_route_evidence,
    generate_reachability_report,
)
from semgrep_llm_vul.semgrep import load_semgrep_findings, load_semgrep_taint_paths
from semgrep_llm_vul.sink_generation import generate_sink_report
from semgrep_llm_vul.taint_path_generation import generate_taint_path_report

ROOT = Path(__file__).resolve().parent.parent


def build_open_redirect_poc_report():
    task = load_analysis_input(ROOT / "examples" / "analysis" / "unknown-sink.yaml")
    fixture = (
        ROOT
        / "fixtures"
        / "semgrep"
        / "taint-result-with-source-control-local-var-trace.json"
    )
    source_root = ROOT / "fixtures" / "reachability" / "flask-source-control-local-var-app"
    sink_report = generate_sink_report(
        task,
        semgrep_findings=tuple(load_semgrep_findings(fixture)),
    )
    taint_report = generate_taint_path_report(
        task,
        sink_report=sink_report,
        semgrep_taint_paths=tuple(load_semgrep_taint_paths(fixture)),
    )
    reachability_report = generate_reachability_report(
        task,
        taint_report=taint_report,
        evidence_records=discover_flask_route_evidence(
            source_root,
            taint_paths=taint_report.paths,
        ),
    )
    return task, generate_poc_report(task, reachability_report=reachability_report)


@contextmanager
def run_open_redirect_server(mode: str, *, style: str = "header_redirect"):
    if mode not in {"affected", "fixed"}:
        raise ValueError(f"unsupported mode: {mode}")
    if style not in {"header_redirect", "meta_refresh", "refresh_header"}:
        raise ValueError(f"unsupported style: {style}")

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            if parsed.path != "/login":
                self.send_response(404)
                self.end_headers()
                return
            next_url = parse_qs(parsed.query).get("next", ["/"])[0]
            if style == "header_redirect":
                location = next_url if mode == "affected" and next_url else "/"
                self.send_response(302)
                self.send_header("Location", location)
                self.end_headers()
                return
            if style == "refresh_header":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                if mode == "affected" and next_url:
                    self.send_header("Refresh", f"0; url={next_url}")
                self.end_headers()
                self.wfile.write(b"<html><body>redirecting</body></html>")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if mode == "affected" and next_url:
                body = (
                    "<html><head>"
                    f'<meta http-equiv="refresh" content="0; url={next_url}">'
                    "</head><body>redirecting</body></html>"
                )
            else:
                body = "<html><body>stay local</body></html>"
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def unused_loopback_base_url() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}"
