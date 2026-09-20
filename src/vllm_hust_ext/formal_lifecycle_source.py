"""Independent lifecycle fact sources for the formal-real evaluation path.

These commands do not consume a SUT acknowledgement as truth.  Each command
performs one external observation or control action, sends one canonical fact
over the runner-owned credentialed datagram, and remains alive until the runner
commits that exact challenge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .ecpa_model import canonical_bytes
from .host_event_sink import HostEventSinkError, read_events

FACT_SCHEMA = "ecpa-formal-lifecycle-fact/v1"
REQUEST_SCHEMA = "ecpa-lifecycle-fact-request/v1"
MAX_HTTP_BYTES = 1024 * 1024
SOURCE_KINDS = {
    "service-ready": "readiness-probe",
    "workload-complete": "workload-driver",
    "fault-injected": "fault-actuator",
    "observer-captured": "host-observer",
    "service-shutdown": "process-monitor",
}
REQUEST_FIELDS = {
    "schema",
    "fact",
    "source_kind",
    "plan_id",
    "launch_id",
    "controller_instance",
    "invocation_id",
    "sequence",
    "challenge",
    "scenario",
    "sut_pid",
    "sut_process_identity",
}


class LifecycleSourceError(ValueError):
    """A source cannot independently establish its assigned fact."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _read_request(stream: Any) -> dict[str, Any]:
    raw = stream.buffer.readline(MAX_HTTP_BYTES + 1)
    if not raw.endswith(b"\n") or len(raw) > MAX_HTTP_BYTES:
        raise LifecycleSourceError("lifecycle request is missing or oversized")
    body = raw[:-1]
    try:
        request = json.loads(body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("lifecycle request JSON is invalid") from exc
    if (
        not isinstance(request, dict)
        or set(request) != REQUEST_FIELDS
        or body != canonical_bytes(request)
        or request.get("schema") != REQUEST_SCHEMA
        or request.get("source_kind") != SOURCE_KINDS.get(request.get("fact"))
    ):
        raise LifecycleSourceError("lifecycle request is not canonical or bound")
    for field in (
        "plan_id",
        "launch_id",
        "controller_instance",
        "invocation_id",
        "challenge",
        "scenario",
    ):
        value = request.get(field)
        if not isinstance(value, str) or not value or value.strip() != value:
            raise LifecycleSourceError(f"lifecycle request {field} is invalid")
    if (
        isinstance(request.get("sequence"), bool)
        or not isinstance(request.get("sequence"), int)
        or request["sequence"] <= 0
        or isinstance(request.get("sut_pid"), bool)
        or not isinstance(request.get("sut_pid"), int)
        or request["sut_pid"] <= 0
    ):
        raise LifecycleSourceError("lifecycle request integer is invalid")
    identity = request.get("sut_process_identity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"pid", "start_ticks", "argv"}
        or identity.get("pid") != request["sut_pid"]
        or isinstance(identity.get("start_ticks"), bool)
        or not isinstance(identity.get("start_ticks"), int)
        or identity["start_ticks"] <= 0
        or not isinstance(identity.get("argv"), list)
        or not identity["argv"]
        or any(not isinstance(value, str) or not value for value in identity["argv"])
    ):
        raise LifecycleSourceError("lifecycle request process identity is invalid")
    return request


def _local_http_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise LifecycleSourceError("formal HTTP source requires a local plain-HTTP URL")
    return value


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not 0.05 <= value <= 60.0:
        raise LifecycleSourceError("formal source timeout must be within [0.05, 60]")
    return value


def _http(
    url: str,
    *,
    timeout: float,
    method: str,
    body: bytes | None = None,
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        _local_http_url(url),
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=_timeout(timeout)) as response:
            if response.geturl() != url:
                raise LifecycleSourceError("formal HTTP source followed a redirect")
            payload = response.read(MAX_HTTP_BYTES + 1)
            status = response.status
    except (OSError, urllib.error.URLError) as exc:
        raise LifecycleSourceError("formal HTTP source request failed") from exc
    if len(payload) > MAX_HTTP_BYTES:
        raise LifecycleSourceError("formal HTTP response exceeds the evidence limit")
    return status, payload


def _audit(kind: str, **values: Any) -> None:
    sys.stderr.buffer.write(
        canonical_bytes(
            {"schema": "ecpa-lifecycle-source-audit/v1", "kind": kind, **values}
        )
        + b"\n"
    )
    sys.stderr.buffer.flush()


def _readiness(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "service-ready":
        raise LifecycleSourceError("readiness source received another phase")
    status, payload = _http(args.url, timeout=args.timeout, method="GET")
    if status != args.status:
        raise LifecycleSourceError("readiness endpoint returned an unexpected status")
    _audit(
        "http-readiness",
        status=status,
        response_bytes=len(payload),
        response_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
    return True


def _canonical_request_file(path: str) -> bytes:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_HTTP_BYTES:
        raise LifecycleSourceError("workload request exceeds the evidence limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("workload request JSON is invalid") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise LifecycleSourceError("workload request file must be canonical JSON")
    return raw


def _workload(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "workload-complete":
        raise LifecycleSourceError("workload source received another phase")
    body = _canonical_request_file(args.request)
    status, payload = _http(
        args.url,
        timeout=args.timeout,
        method="POST",
        body=body,
    )
    try:
        response = json.loads(payload)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("workload response JSON is invalid") from exc
    if (
        status != 200
        or not isinstance(response, dict)
        or not isinstance(response.get("choices"), list)
        or not response["choices"]
    ):
        raise LifecycleSourceError("workload did not produce an OpenAI response")
    _audit(
        "openai-workload",
        status=status,
        request_sha256="sha256:" + hashlib.sha256(body).hexdigest(),
        response_bytes=len(payload),
        response_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
    return True


def _journal(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "observer-captured":
        raise LifecycleSourceError("journal source received another phase")
    root = Path(args.event_dir)
    records = read_events(root, (args.device, args.inode))
    selected = [
        item
        for item in records
        if item.event["plan_id"] == request["plan_id"]
        and item.event["launch_id"] == request["launch_id"]
    ]
    if not selected:
        raise LifecycleSourceError("host journal has no event for this Plan and launch")
    _audit(
        "host-journal-capture",
        event_count=len(selected),
        raw_digests=[
            "sha256:" + hashlib.sha256(item.raw).hexdigest() for item in selected
        ],
    )
    return True


def _shutdown(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "service-shutdown":
        raise LifecycleSourceError("shutdown source received another phase")
    pidfd = -1
    try:
        expected = request["sut_process_identity"]
        before = _linux_process_identity(request["sut_pid"])
        if before != expected:
            raise LifecycleSourceError("shutdown target identity differs from request")
        pidfd = os.pidfd_open(request["sut_pid"])
        try:
            after = _linux_process_identity(request["sut_pid"])
        except ProcessLookupError:
            after = before
        if after != before:
            raise LifecycleSourceError("shutdown target identity changed before wait")
        readable, _, _ = select.select([pidfd], [], [], _timeout(args.timeout))
        if not readable:
            raise LifecycleSourceError("SUT did not exit after shutdown phase")
    except ProcessLookupError:
        pass
    finally:
        if pidfd >= 0:
            os.close(pidfd)
    _audit("process-shutdown", pid=request["sut_pid"])
    return True


def _linux_process_identity(pid: int) -> dict[str, Any]:
    stat_path = Path("/proc") / str(pid) / "stat"
    command_path = Path("/proc") / str(pid) / "cmdline"
    try:
        before_raw = stat_path.read_bytes()
        close = before_raw.rfind(b")")
        if close < 0:
            raise LifecycleSourceError("shutdown target stat is malformed")
        fields = before_raw[close + 2 :].split()
        if len(fields) <= 19:
            raise LifecycleSourceError("shutdown target stat is incomplete")
        before = int(fields[19])
        argv_raw = command_path.read_bytes()
        after_raw = stat_path.read_bytes()
        after_close = after_raw.rfind(b")")
        after_fields = after_raw[after_close + 2 :].split()
        after = int(after_fields[19])
    except FileNotFoundError as exc:
        raise ProcessLookupError(pid) from exc
    except (OSError, ValueError, IndexError) as exc:
        raise LifecycleSourceError("shutdown target identity is unavailable") from exc
    if before <= 0 or before != after:
        raise LifecycleSourceError("shutdown target identity changed while reading")
    argv = [
        item.decode(errors="surrogateescape") for item in argv_raw.split(b"\0") if item
    ]
    if not argv:
        raise LifecycleSourceError("shutdown target argv is unavailable")
    return {"pid": pid, "start_ticks": before, "argv": argv}


def _send_fact(
    request: dict[str, Any],
    value: bool | str,
    *,
    stream: Any,
) -> None:
    try:
        descriptor = int(os.environ["ECPA_LIFECYCLE_FACT_FD"])
        channel = socket.socket(fileno=descriptor)
    except (KeyError, ValueError, OSError) as exc:
        raise LifecycleSourceError(
            "credentialed lifecycle channel is unavailable"
        ) from exc
    if channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
        raise LifecycleSourceError("lifecycle channel is not a datagram socket")
    payload = {
        "schema": FACT_SCHEMA,
        "fact": request["fact"],
        "source_kind": request["source_kind"],
        "plan_id": request["plan_id"],
        "launch_id": request["launch_id"],
        "controller_instance": request["controller_instance"],
        "invocation_id": request["invocation_id"],
        "sequence": request["sequence"],
        "challenge": request["challenge"],
        "monotonic_ns": time.monotonic_ns(),
        "value": value,
        "sut_process_identity": request["sut_process_identity"],
    }
    raw = canonical_bytes(payload)
    if channel.send(raw) != len(raw):
        raise LifecycleSourceError("lifecycle fact datagram was not sent completely")
    raw_commit = stream.buffer.readline(MAX_HTTP_BYTES + 1)
    if not raw_commit.endswith(b"\n") or len(raw_commit) > MAX_HTTP_BYTES:
        raise LifecycleSourceError("runner commit is missing or oversized")
    try:
        commit = json.loads(raw_commit[:-1])
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("runner commit JSON is invalid") from exc
    expected = {
        "command": "commit",
        "challenge": request["challenge"],
        "phase": request["fact"],
    }
    if commit != expected or raw_commit[:-1] != canonical_bytes(commit):
        raise LifecycleSourceError("runner commit does not bind the lifecycle fact")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecpa-formal-source")
    commands = parser.add_subparsers(dest="source", required=True)
    readiness = commands.add_parser("readiness-http")
    readiness.add_argument("--url", required=True)
    readiness.add_argument("--status", type=int, default=200)
    readiness.add_argument("--timeout", type=float, default=10.0)
    workload = commands.add_parser("workload-http")
    workload.add_argument("--url", required=True)
    workload.add_argument("--request", required=True)
    workload.add_argument("--timeout", type=float, default=60.0)
    journal = commands.add_parser("journal-capture")
    journal.add_argument("--event-dir", required=True)
    journal.add_argument("--device", required=True, type=int)
    journal.add_argument("--inode", required=True, type=int)
    shutdown = commands.add_parser("shutdown-process")
    shutdown.add_argument("--timeout", type=float, default=60.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers: dict[str, Callable[[argparse.Namespace, dict[str, Any]], bool | str]] = {
        "readiness-http": _readiness,
        "workload-http": _workload,
        "journal-capture": _journal,
        "shutdown-process": _shutdown,
    }
    try:
        request = _read_request(sys.stdin)
        value = handlers[args.source](args, request)
        _send_fact(request, value, stream=sys.stdin)
    except (HostEventSinkError, LifecycleSourceError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
