import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

import vllm_hust_ext.formal_lifecycle_source as source
from vllm_hust_ext.ecpa_model import canonical_bytes


def request_for(fact: str, *, pid: int | None = None) -> dict[str, object]:
    pid = os.getpid() if pid is None else pid
    return {
        "schema": source.REQUEST_SCHEMA,
        "fact": fact,
        "source_kind": source.SOURCE_KINDS[fact],
        "plan_id": "sha256:" + "1" * 64,
        "launch_id": "launch:test",
        "controller_instance": "controller:test",
        "invocation_id": "launch:test:1:challenge",
        "sequence": 1,
        "challenge": "challenge",
        "scenario": "compatible-resource-pair",
        "sut_pid": pid,
        "sut_process_identity": {
            "pid": pid,
            "start_ticks": 1,
            "argv": ["sut"],
        },
    }


def run_source(arguments: list[str], request: dict[str, object]):
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    environment = dict(os.environ)
    environment["ECPA_LIFECYCLE_FACT_FD"] = str(sender.fileno())
    process = subprocess.Popen(
        [sys.executable, "-m", "vllm_hust_ext.formal_lifecycle_source", *arguments],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        pass_fds=(sender.fileno(),),
    )
    sender.close()
    assert process.stdin is not None
    process.stdin.write(canonical_bytes(request) + b"\n")
    process.stdin.flush()
    receiver.settimeout(2)
    raw = receiver.recv(1024 * 1024)
    assert process.poll() is None
    process.stdin.write(
        canonical_bytes(
            {
                "command": "commit",
                "challenge": request["challenge"],
                "phase": request["fact"],
            }
        )
        + b"\n"
    )
    process.stdin.close()
    returncode = process.wait(timeout=2)
    stdout = process.stdout.read() if process.stdout is not None else b""
    stderr = process.stderr.read() if process.stderr is not None else b""
    receiver.close()
    return json.loads(raw), returncode, stdout, stderr


class _HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ready")

    def do_POST(self):  # noqa: N802
        length = int(self.headers["Content-Length"])
        self.server.request_body = self.rfile.read(length)  # type: ignore[attr-defined]
        payload = canonical_bytes({"choices": [{"text": "ok"}]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002
        return


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_http_readiness_and_openai_workload_sources(tmp_path, http_server):
    base = f"http://127.0.0.1:{http_server.server_port}"
    payload, returncode, stdout, readiness_audit = run_source(
        ["readiness-http", "--url", f"{base}/health", "--timeout", "1"],
        request_for("service-ready"),
    )
    request_path = tmp_path / "request.json"
    request_body = canonical_bytes({"model": "test", "prompt": "hello"}) + b"\n"
    request_path.write_bytes(request_body)
    workload = source._workload(
        SimpleNamespace(
            url=f"{base}/v1/completions",
            timeout=1.0,
            request=str(request_path),
        ),
        request_for("workload-complete"),
    )

    assert returncode == 0
    assert stdout == b""
    assert payload["value"] is True
    assert json.loads(readiness_audit)["kind"] == "http-readiness"
    assert workload is True
    assert http_server.request_body == request_body


def test_http_source_rejects_nonlocal_and_redirect_urls():
    with pytest.raises(source.LifecycleSourceError, match="local plain-HTTP"):
        source._local_http_url("https://example.com/health")
    with pytest.raises(source.LifecycleSourceError, match="local plain-HTTP"):
        source._local_http_url("http://user@127.0.0.1/health")


def test_journal_capture_requires_matching_plan_and_launch(monkeypatch, tmp_path):
    event = {
        "plan_id": "sha256:" + "1" * 64,
        "launch_id": "launch:test",
    }
    monkeypatch.setattr(
        source,
        "read_events",
        lambda root, identity: [SimpleNamespace(event=event, raw=b"event")],
    )

    assert (
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )
        is True
    )

    event["launch_id"] = "launch:other"
    with pytest.raises(source.LifecycleSourceError, match="no event"):
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )


def test_shutdown_source_observes_real_process_exit():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    request = request_for("service-shutdown", pid=process.pid)
    request["sut_process_identity"] = source._linux_process_identity(process.pid)
    timer = threading.Timer(0.05, process.terminate)
    timer.start()
    try:
        assert (
            source._shutdown(
                SimpleNamespace(timeout=1.0),
                request,
            )
            is True
        )
    finally:
        timer.cancel()
        process.wait(timeout=2)


def test_request_rejects_noncanonical_bytes(tmp_path):
    del tmp_path
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "vllm_hust_ext.formal_lifecycle_source",
            "shutdown-process",
        ],
        input=b'{"schema": "ecpa-lifecycle-fact-request/v1"}\n',
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert b"not canonical or bound" in completed.stderr
