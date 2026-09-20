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
from vllm_hust_ext.quarantine_transaction import (
    finalize_quarantine_transaction,
    read_quarantine_record,
)


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
        "required_processes": [
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 7,
            },
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 1,
                "process_epoch": 7,
            },
        ],
    }


def partial_coverage_request() -> dict[str, object]:
    request = request_for("fault-injected")
    request["scenario"] = "partial-worker-coverage"
    return request


def write_fault_descriptor(tmp_path, request):
    descriptor = {
        "schema": "ecpa-evidence-quarantine-fault/v1",
        "scenario": request["scenario"],
        "target": {
            "host": "host-a",
            "role": "worker",
            "ordinal": 0,
            "process_epoch": 7,
        },
        "entry_point": {
            "group": "vllm.general_plugins",
            "name": "demo",
            "value": "demo.plugin:register",
        },
    }
    raw = canonical_bytes(descriptor) + b"\n"
    path = tmp_path / "fault.json"
    path.write_bytes(raw)
    return path, raw, descriptor


def lifecycle_event(descriptor, request, *, ordinal, journal):
    event = {
        "plan_id": request["plan_id"],
        "launch_id": request["launch_id"],
        "binding_status": "bound",
        "event": "invoked",
        "observation_kind": "loader_lifecycle",
        "controller_instance_id": None,
        "process": {
            "assignment_source": "host",
            "host": "host-a",
            "role": "worker",
            "ordinal": ordinal,
            "process_epoch": 7,
        },
        "entry_point": descriptor["entry_point"],
    }
    return SimpleNamespace(event=event, raw=b"event", journal=journal, line_number=1)


def mock_quarantine_transaction(monkeypatch):
    calls = {}
    monkeypatch.setattr(
        source,
        "acquire_quarantine_transaction_lease",
        lambda *args, **kwargs: SimpleNamespace(close=lambda: None),
    )

    def reconcile(*args, **kwargs):
        calls["reconcile"] = calls.get("reconcile", 0) + 1
        return SimpleNamespace(restored=(), finalized=())

    monkeypatch.setattr(source, "reconcile_quarantine_transactions", reconcile)
    monkeypatch.setattr(
        source,
        "snapshot_journal",
        lambda *args, **kwargs: SimpleNamespace(
            journal=args[1], raw=b"event\n", device=11, inode=12
        ),
    )

    def prepare(*args, **kwargs):
        calls["prepare"] = (args, kwargs)
        return SimpleNamespace(raw=b"intent\n", digest="sha256:" + "1" * 64)

    def applied(*args, **kwargs):
        calls["applied"] = (args, kwargs)
        return SimpleNamespace(raw=b"applied\n", digest="sha256:" + "2" * 64)

    monkeypatch.setattr(source, "prepare_quarantine_transaction", prepare)
    monkeypatch.setattr(source, "read_quarantine_record", lambda *args, **kwargs: None)

    def install_fence(*args, **kwargs):
        calls["fence"] = (args, kwargs)
        return SimpleNamespace(raw=b"fence\n", digest="sha256:" + "3" * 64)

    monkeypatch.setattr(source, "install_quarantine_source_fence", install_fence)
    monkeypatch.setattr(source, "mark_quarantine_applied", applied)
    monkeypatch.setattr(
        source, "mark_quarantine_restored", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        source, "remove_quarantine_source_fence", lambda *args, **kwargs: None
    )
    return calls


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


def test_partial_coverage_fault_quarantines_one_worker_journal(monkeypatch, tmp_path):
    transaction_calls = mock_quarantine_transaction(monkeypatch)
    request = partial_coverage_request()
    descriptor_path, descriptor_raw, descriptor = write_fault_descriptor(
        tmp_path, request
    )
    target = lifecycle_event(descriptor, request, ordinal=0, journal="target.jsonl")
    peer = lifecycle_event(descriptor, request, ordinal=1, journal="peer.jsonl")
    reads = iter(([target, peer], [peer]))
    monkeypatch.setattr(source, "read_events", lambda *args, **kwargs: next(reads))
    quarantined = SimpleNamespace(
        journal="target.jsonl",
        raw=b"event\n",
        device=11,
        inode=12,
    )
    quarantine_call = {}

    def quarantine(*args, **kwargs):
        quarantine_call.update(args=args, kwargs=kwargs)
        return quarantined

    monkeypatch.setattr(source, "quarantine_journal", quarantine)
    audit = {}
    monkeypatch.setattr(
        source,
        "_audit",
        lambda kind, **values: audit.update(kind=kind, **values),
    )
    args = SimpleNamespace(
        event_dir=str(tmp_path / "events"),
        device=1,
        inode=2,
        quarantine_dir=str(tmp_path / "quarantine"),
        quarantine_device=3,
        quarantine_inode=4,
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    prepared = source._partial_coverage_fault(args, request)
    assert prepared.value == request["scenario"]
    assert not quarantine_call
    assert transaction_calls.keys() == {"reconcile", "prepare"}
    try:
        prepared.commit()
    finally:
        prepared.release()
    assert quarantine_call["args"][2] == "target.jsonl"
    assert quarantine_call["kwargs"]["expected_root_identity"] == (1, 2)
    assert quarantine_call["kwargs"]["expected_quarantine_identity"] == (3, 4)
    assert audit["kind"] == "partial-worker-evidence-quarantine"
    assert transaction_calls.keys() == {"reconcile", "prepare", "fence", "applied"}
    assert audit["transaction_intent_sha256"] == "sha256:" + "1" * 64
    assert audit["transaction_applied_sha256"] == "sha256:" + "2" * 64
    assert base64.b64decode(audit["descriptor_base64"]) == descriptor_raw
    assert base64.b64decode(audit["quarantined_base64"]) == quarantined.raw
    assert audit["peer_slots"] == [
        {"host": "host-a", "role": "worker", "ordinal": 1, "process_epoch": 7}
    ]
    assert audit["target_records"] == [
        {
            "journal": "target.jsonl",
            "line_number": 1,
            "event_id": None,
            "process": target.event["process"],
        }
    ]
    assert base64.b64decode(audit["peer_records"][0]["raw_base64"]) == peer.raw


def test_partial_coverage_fault_persists_real_transaction_chain(monkeypatch, tmp_path):
    request = partial_coverage_request()
    descriptor_path, descriptor_raw, descriptor = write_fault_descriptor(
        tmp_path, request
    )
    target = lifecycle_event(descriptor, request, ordinal=0, journal="target.jsonl")
    peer = lifecycle_event(descriptor, request, ordinal=1, journal="peer.jsonl")
    reads = iter(([target, peer], [peer]))
    monkeypatch.setattr(source, "read_events", lambda *args, **kwargs: next(reads))
    events = tmp_path / "events"
    quarantine = tmp_path / "quarantine"
    events.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    (events / "target.jsonl").write_bytes(b"event\n")
    event_identity = (events.stat().st_dev, events.stat().st_ino)
    quarantine_identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)
    audit = {}
    monkeypatch.setattr(
        source,
        "_audit",
        lambda kind, **values: audit.update(kind=kind, **values),
    )
    args = SimpleNamespace(
        event_dir=str(events),
        device=event_identity[0],
        inode=event_identity[1],
        quarantine_dir=str(quarantine),
        quarantine_device=quarantine_identity[0],
        quarantine_inode=quarantine_identity[1],
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    prepared = source._partial_coverage_fault(args, request)
    assert not list(events.glob(".ecpa-quarantine-*.fence"))
    try:
        prepared.commit()
    finally:
        prepared.release()

    assert not (events / "target.jsonl").exists()
    assert (quarantine / "target.jsonl").read_bytes() == b"event\n"
    assert len(list(quarantine.glob("*.intent.json"))) == 1
    assert len(list(quarantine.glob("*.applied.json"))) == 1
    assert not list(quarantine.glob("*.finalized.json"))
    assert audit["transaction_id"] in next(quarantine.glob("*.intent.json")).name
    before_source = {
        path.name: (path.stat().st_ino, path.read_bytes()) for path in events.iterdir()
    }
    before_quarantine = {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in quarantine.iterdir()
    }
    with pytest.raises(source.LifecycleSourceError, match="already settled"):
        prepared.commit()
    assert before_source == {
        path.name: (path.stat().st_ino, path.read_bytes()) for path in events.iterdir()
    }
    assert before_quarantine == {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in quarantine.iterdir()
    }
    transaction_id = audit["transaction_id"]
    applied = read_quarantine_record(
        quarantine, quarantine_identity, transaction_id, "applied"
    )
    assert applied is not None
    finalize_quarantine_transaction(
        quarantine,
        quarantine_identity,
        transaction_id,
        source_root=events,
        source_identity=event_identity,
        applied_digest=applied.digest,
        fact_receipt_sha256="sha256:" + "4" * 64,
        source_process_identity={
            "pid": os.getpid(),
            "start_ticks": 1,
            "argv": ["source-test"],
            "executable_device": 1,
            "executable_inode": 1,
        },
    )
    finalized_state = {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in quarantine.iterdir()
    }
    with pytest.raises(source.LifecycleSourceError, match="already settled"):
        prepared.commit()
    assert finalized_state == {
        path.name: (path.stat().st_ino, path.read_bytes())
        for path in quarantine.iterdir()
    }


def test_partial_coverage_fault_rejects_missing_peer(monkeypatch, tmp_path):
    mock_quarantine_transaction(monkeypatch)
    request = partial_coverage_request()
    descriptor_path, descriptor_raw, descriptor = write_fault_descriptor(
        tmp_path, request
    )
    target = lifecycle_event(descriptor, request, ordinal=0, journal="target.jsonl")
    monkeypatch.setattr(source, "read_events", lambda *args, **kwargs: [target])
    args = SimpleNamespace(
        event_dir=str(tmp_path / "events"),
        device=1,
        inode=2,
        quarantine_dir=str(tmp_path / "quarantine"),
        quarantine_device=3,
        quarantine_inode=4,
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    with pytest.raises(source.LifecycleSourceError, match="another observed worker"):
        source._partial_coverage_fault(args, request)


def test_partial_coverage_fault_rejects_replacement_epoch_as_peer(
    monkeypatch, tmp_path
):
    mock_quarantine_transaction(monkeypatch)
    request = partial_coverage_request()
    request["required_processes"][1]["ordinal"] = 0
    request["required_processes"][1]["process_epoch"] = 8
    descriptor_path, descriptor_raw, _descriptor = write_fault_descriptor(
        tmp_path, request
    )
    monkeypatch.setattr(source, "read_events", lambda *args, **kwargs: [])
    args = SimpleNamespace(
        event_dir=str(tmp_path / "events"),
        device=1,
        inode=2,
        quarantine_dir=str(tmp_path / "quarantine"),
        quarantine_device=3,
        quarantine_inode=4,
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    with pytest.raises(source.LifecycleSourceError, match="frozen snapshot"):
        source._partial_coverage_fault(args, request)


def test_partial_coverage_fault_rejects_target_reappearance(monkeypatch, tmp_path):
    mock_quarantine_transaction(monkeypatch)
    request = partial_coverage_request()
    descriptor_path, descriptor_raw, descriptor = write_fault_descriptor(
        tmp_path, request
    )
    target = lifecycle_event(descriptor, request, ordinal=0, journal="target.jsonl")
    peer = lifecycle_event(descriptor, request, ordinal=1, journal="peer.jsonl")
    reads = iter(([target, peer], [target, peer]))
    monkeypatch.setattr(source, "read_events", lambda *args, **kwargs: next(reads))
    monkeypatch.setattr(
        source,
        "quarantine_journal",
        lambda *args, **kwargs: SimpleNamespace(
            journal="target.jsonl", raw=b"event\n", device=11, inode=12
        ),
    )
    args = SimpleNamespace(
        event_dir=str(tmp_path / "events"),
        device=1,
        inode=2,
        quarantine_dir=str(tmp_path / "quarantine"),
        quarantine_device=3,
        quarantine_inode=4,
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    restored = []
    monkeypatch.setattr(
        source,
        "restore_quarantined_journal",
        lambda *args, **kwargs: restored.append((args, kwargs)),
    )
    prepared = source._partial_coverage_fault(args, request)
    with pytest.raises(source.LifecycleSourceError, match="reappeared"):
        prepared.commit()
    assert len(restored) == 1


def test_partial_coverage_fault_rejects_mixed_target_journal(monkeypatch, tmp_path):
    mock_quarantine_transaction(monkeypatch)
    request = partial_coverage_request()
    descriptor_path, descriptor_raw, descriptor = write_fault_descriptor(
        tmp_path, request
    )
    target = lifecycle_event(descriptor, request, ordinal=0, journal="target.jsonl")
    mixed = lifecycle_event(descriptor, request, ordinal=1, journal="target.jsonl")
    peer = lifecycle_event(descriptor, request, ordinal=1, journal="peer.jsonl")
    monkeypatch.setattr(
        source, "read_events", lambda *args, **kwargs: [target, mixed, peer]
    )
    args = SimpleNamespace(
        event_dir=str(tmp_path / "events"),
        device=1,
        inode=2,
        quarantine_dir=str(tmp_path / "quarantine"),
        quarantine_device=3,
        quarantine_inode=4,
        descriptor=str(descriptor_path),
        descriptor_sha256="sha256:" + hashlib.sha256(descriptor_raw).hexdigest(),
    )

    with pytest.raises(source.LifecycleSourceError, match="another launch or process"):
        source._partial_coverage_fault(args, request)


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
