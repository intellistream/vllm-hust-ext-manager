import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
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


class _SlowHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        try:
            for _ in range(8):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.04)
        except BrokenPipeError:
            pass

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


def test_http_readiness_and_openai_workload_sources(tmp_path, http_server, monkeypatch):
    base = f"http://127.0.0.1:{http_server.server_port}"
    payload, returncode, stdout, readiness_audit = run_source(
        ["readiness-http", "--url", f"{base}/health", "--timeout", "1"],
        request_for("service-ready"),
    )
    request_path = tmp_path / "request.json"
    request_body = canonical_bytes({"model": "test", "prompt": "hello"}) + b"\n"
    request_path.write_bytes(request_body)
    workload_audit = {}
    monkeypatch.setattr(
        source, "_audit", lambda kind, **values: workload_audit.update(values)
    )
    workload = source._workload(
        SimpleNamespace(
            url=f"{base}/v1/completions",
            timeout=1.0,
            request=str(request_path),
            request_sha256="sha256:" + hashlib.sha256(request_body).hexdigest(),
        ),
        request_for("workload-complete"),
    )

    assert returncode == 0
    assert stdout == b""
    assert payload["value"] is True
    readiness_record = json.loads(readiness_audit)
    assert readiness_record["kind"] == "http-readiness"
    assert base64.b64decode(readiness_record["response_base64"]) == b"ready"
    assert workload is True
    assert http_server.request_body == request_body
    assert base64.b64decode(workload_audit["request_base64"]) == request_body
    assert json.loads(base64.b64decode(workload_audit["response_base64"]))["choices"]


def test_http_source_ignores_proxy_environment(monkeypatch, http_server):
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{http_server.server_port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{http_server.server_port}")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")

    with pytest.raises(source.LifecycleSourceError, match="request failed"):
        source._http(
            "http://127.0.0.1:9/health",
            timeout=0.2,
            method="GET",
        )


def test_http_source_enforces_total_wall_clock_deadline():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(source.LifecycleSourceError, match="wall-clock deadline"):
            source._http(
                f"http://127.0.0.1:{server.server_port}/slow",
                timeout=0.05,
                method="GET",
            )
    finally:
        elapsed = time.monotonic() - started
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert elapsed < 0.2


def test_http_source_rejects_nonlocal_and_redirect_urls():
    with pytest.raises(source.LifecycleSourceError, match="local plain-HTTP"):
        source._local_http_url("https://example.com/health")
    with pytest.raises(source.LifecycleSourceError, match="local plain-HTTP"):
        source._local_http_url("http://user@127.0.0.1/health")
    with pytest.raises(source.LifecycleSourceError, match="local plain-HTTP"):
        source._local_http_url("http://localhost/health")


def test_journal_capture_requires_bound_dispatch_for_controller(monkeypatch, tmp_path):
    event = {
        "event_id": "event-one",
        "event": "invoked",
        "observation_kind": "scheduler_dispatch",
        "binding_status": "bound",
        "controller_instance_id": "controller:test",
        "invocation_seq": 1,
        "dispatch_id": "a" * 64,
        "plan_id": "sha256:" + "1" * 64,
        "launch_id": "launch:test",
        "process": {"assignment_source": "host"},
    }
    audit = {}
    monkeypatch.setattr(
        source,
        "read_events",
        lambda root, identity, **kwargs: [
            SimpleNamespace(
                event=event,
                raw=b"event",
                journal="one.jsonl",
                line_number=1,
            )
        ],
    )
    monkeypatch.setattr(source, "_audit", lambda kind, **values: audit.update(values))

    assert (
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )
        is True
    )
    assert audit["selected_event_ids"] == ["event-one"]
    assert base64.b64decode(audit["journal_records"][0]["raw_base64"]) == b"event"

    event["event"] = "failed"
    with pytest.raises(
        source.LifecycleSourceError, match="no bound scheduler dispatch"
    ):
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )
    event["event"] = "invoked"
    event["observation_kind"] = "loader_lifecycle"
    with pytest.raises(
        source.LifecycleSourceError, match="no bound scheduler dispatch"
    ):
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )
    event["observation_kind"] = "scheduler_dispatch"
    event["controller_instance_id"] = "controller:other"
    with pytest.raises(
        source.LifecycleSourceError, match="no bound scheduler dispatch"
    ):
        source._journal(
            SimpleNamespace(event_dir=str(tmp_path), device=1, inode=2),
            request_for("observer-captured"),
        )


def test_journal_capture_bounds_bytes_before_parsing(tmp_path):
    tmp_path.chmod(0o700)
    oversized = tmp_path / "oversized.jsonl"
    with oversized.open("wb") as stream:
        stream.write(b"x" * (source.MAX_JOURNAL_BYTES + 1))
    metadata = tmp_path.stat()

    with pytest.raises(source.HostEventSinkError, match="exceed the read limit"):
        source._journal(
            SimpleNamespace(
                event_dir=str(tmp_path.resolve()),
                device=metadata.st_dev,
                inode=metadata.st_ino,
            ),
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


def test_shutdown_source_rejects_target_gone_before_identity_binding():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    identity = source._linux_process_identity(process.pid)
    process.terminate()
    process.wait(timeout=2)
    request = request_for("service-shutdown", pid=process.pid)
    request["sut_process_identity"] = identity

    with pytest.raises(
        source.LifecycleSourceError, match="before independent identity"
    ):
        source._shutdown(SimpleNamespace(timeout=0.1), request)


def test_workload_request_must_match_registered_digest(tmp_path):
    request_path = tmp_path / "request.json"
    request_path.write_bytes(canonical_bytes({"model": "changed"}) + b"\n")

    with pytest.raises(source.LifecycleSourceError, match="registered digest"):
        source._canonical_request_file(
            str(request_path),
            "sha256:" + "0" * 64,
        )


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
