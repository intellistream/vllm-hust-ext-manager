"""Independent lifecycle fact sources for the formal-real evaluation path.

These commands do not consume a SUT acknowledgement as truth.  Each command
performs one external observation or control action, sends one canonical fact
over the runner-owned credentialed datagram, and remains alive until the runner
commits that exact challenge.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import signal
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ecpa_model import canonical_bytes
from .host_event_sink import (
    HostEventSinkError,
    quarantine_journal,
    read_events,
    restore_quarantined_journal,
)

FACT_SCHEMA = "ecpa-formal-lifecycle-fact/v1"
REQUEST_SCHEMA = "ecpa-lifecycle-fact-request/v1"
MAX_HTTP_BYTES = 128 * 1024
MAX_JOURNAL_BYTES = 512 * 1024
MAX_DESCRIPTOR_BYTES = 64 * 1024
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
    "required_processes",
}


class LifecycleSourceError(ValueError):
    """A source cannot independently establish its assigned fact."""


@dataclass(frozen=True)
class PreparedFact:
    """A fact value whose state-changing action runs only after runner commit."""

    value: bool | str
    commit: Callable[[], None]


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
    required = request.get("required_processes")
    if (
        not isinstance(required, list)
        or not required
        or any(
            not isinstance(item, dict)
            or set(item) != {"host", "role", "ordinal", "process_epoch"}
            or not isinstance(item.get("host"), str)
            or not item["host"]
            or item["host"].strip() != item["host"]
            or not isinstance(item.get("role"), str)
            or not item["role"]
            or item["role"].strip() != item["role"]
            or any(
                isinstance(item.get(field), bool)
                or not isinstance(item.get(field), int)
                or item[field] < 0
                for field in ("ordinal", "process_epoch")
            )
            for item in required
        )
    ):
        raise LifecycleSourceError("lifecycle request target snapshot is invalid")
    target_keys = [
        (item["host"], item["role"], item["ordinal"], item["process_epoch"])
        for item in required
    ]
    if len(target_keys) != len(set(target_keys)):
        raise LifecycleSourceError("lifecycle request target snapshot has duplicates")
    return request


def _local_http_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()

    def deadline_handler(signum: int, frame: Any) -> None:
        del signum, frame
        raise TimeoutError("formal HTTP source exceeded its wall-clock deadline")

    try:
        signal.signal(signal.SIGALRM, deadline_handler)
        signal.setitimer(signal.ITIMER_REAL, _timeout(timeout))
        with opener.open(request, timeout=_timeout(timeout)) as response:
            if response.geturl() != url:
                raise LifecycleSourceError("formal HTTP source followed a redirect")
            payload = response.read(MAX_HTTP_BYTES + 1)
            status = response.status
    except TimeoutError as exc:
        raise LifecycleSourceError(
            "formal HTTP source exceeded its wall-clock deadline"
        ) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise LifecycleSourceError("formal HTTP source request failed") from exc
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay > 0:
            elapsed = time.monotonic() - started
            signal.setitimer(
                signal.ITIMER_REAL,
                max(0.000001, previous_delay - elapsed),
                previous_interval,
            )
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
        response_base64=base64.b64encode(payload).decode(),
        response_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
    return True


def _canonical_request_file(path: str, expected_digest: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_HTTP_BYTES + 1)
    if len(raw) > MAX_HTTP_BYTES:
        raise LifecycleSourceError("workload request exceeds the evidence limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("workload request JSON is invalid") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise LifecycleSourceError("workload request file must be canonical JSON")
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_digest != actual_digest:
        raise LifecycleSourceError(
            "workload request differs from its registered digest"
        )
    return raw


def _canonical_descriptor_file(
    path: str, expected_digest: str
) -> tuple[bytes, dict[str, Any]]:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_DESCRIPTOR_BYTES + 1)
    if len(raw) > MAX_DESCRIPTOR_BYTES:
        raise LifecycleSourceError("fault descriptor exceeds the evidence limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise LifecycleSourceError("fault descriptor JSON is invalid") from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise LifecycleSourceError("fault descriptor must be canonical JSON")
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_digest != actual_digest:
        raise LifecycleSourceError(
            "fault descriptor differs from its registered digest"
        )
    return raw, value


def _workload(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "workload-complete":
        raise LifecycleSourceError("workload source received another phase")
    body = _canonical_request_file(args.request, args.request_sha256)
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
        request_base64=base64.b64encode(body).decode(),
        request_sha256="sha256:" + hashlib.sha256(body).hexdigest(),
        response_bytes=len(payload),
        response_base64=base64.b64encode(payload).decode(),
        response_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
    )
    return True


def _partial_coverage_fault(
    args: argparse.Namespace, request: dict[str, Any]
) -> PreparedFact:
    if request["fact"] != "fault-injected":
        raise LifecycleSourceError("partial-coverage source received another phase")
    if request["scenario"] != "partial-worker-coverage":
        raise LifecycleSourceError(
            "partial-coverage source refuses another frozen scenario"
        )
    descriptor_raw, descriptor = _canonical_descriptor_file(
        args.descriptor, args.descriptor_sha256
    )
    target = descriptor.get("target") if isinstance(descriptor, dict) else None
    entry_point = (
        descriptor.get("entry_point") if isinstance(descriptor, dict) else None
    )
    if (
        set(descriptor)
        != {
            "schema",
            "scenario",
            "target",
            "entry_point",
        }
        or descriptor.get("schema") != "ecpa-evidence-quarantine-fault/v1"
        or descriptor.get("scenario") != request["scenario"]
        or not isinstance(target, dict)
        or set(target) != {"host", "role", "ordinal", "process_epoch"}
        or target.get("role") != "worker"
        or not isinstance(target.get("host"), str)
        or not target["host"]
        or target["host"].strip() != target["host"]
        or any(
            isinstance(target.get(field), bool)
            or not isinstance(target.get(field), int)
            or target[field] < 0
            for field in ("ordinal", "process_epoch")
        )
        or not isinstance(entry_point, dict)
        or set(entry_point) != {"group", "name", "value"}
        or any(
            not isinstance(entry_point.get(field), str)
            or not entry_point[field]
            or entry_point[field].strip() != entry_point[field]
            for field in ("group", "name", "value")
        )
    ):
        raise LifecycleSourceError("fault descriptor is not bound or canonical")

    required = {
        (item["host"], item["role"], item["ordinal"], item["process_epoch"])
        for item in request["required_processes"]
    }
    target_key = tuple(
        target[field] for field in ("host", "role", "ordinal", "process_epoch")
    )
    target_slot = tuple(target[field] for field in ("host", "role", "ordinal"))
    worker_slots = {
        (host, role, ordinal)
        for host, role, ordinal, _epoch in required
        if role == "worker"
    }
    if target_key not in required or len(worker_slots) < 2:
        raise LifecycleSourceError(
            "partial-coverage target and peer must belong to the frozen snapshot"
        )

    root = Path(args.event_dir)
    source_identity = (args.device, args.inode)
    records = read_events(
        root,
        source_identity,
        max_total_bytes=MAX_JOURNAL_BYTES,
    )

    def is_effect(item: Any) -> bool:
        event = item.event
        return (
            event["plan_id"] == request["plan_id"]
            and event["launch_id"] == request["launch_id"]
            and event["binding_status"] == "bound"
            and event["event"] == "invoked"
            and event["observation_kind"] == "loader_lifecycle"
            and event["controller_instance_id"] is None
            and event["process"].get("assignment_source") == "host"
            and event["entry_point"] == entry_point
        )

    effects = [item for item in records if is_effect(item)]
    target_effects = [
        item
        for item in effects
        if all(item.event["process"].get(field) == target[field] for field in target)
    ]
    target_journals = {item.journal for item in target_effects}
    peer_slots = sorted(
        {
            (
                item.event["process"]["host"],
                item.event["process"]["role"],
                item.event["process"]["ordinal"],
                item.event["process"]["process_epoch"],
            )
            for item in effects
            if (
                item.event["process"]["host"],
                item.event["process"]["role"],
                item.event["process"]["ordinal"],
                item.event["process"]["process_epoch"],
            )
            in required
            and (
                item.event["process"]["host"],
                item.event["process"]["role"],
                item.event["process"]["ordinal"],
            )
            != target_slot
        }
    )
    if len(target_journals) != 1 or not target_effects:
        raise LifecycleSourceError(
            "fault target does not have one exact bound worker journal"
        )
    if not peer_slots:
        raise LifecycleSourceError(
            "partial-coverage fault requires another observed worker"
        )
    journal = next(iter(target_journals))
    journal_records = [item for item in records if item.journal == journal]
    if not journal_records or any(
        item.event["plan_id"] != request["plan_id"]
        or item.event["launch_id"] != request["launch_id"]
        or any(item.event["process"].get(field) != target[field] for field in target)
        for item in journal_records
    ):
        raise LifecycleSourceError(
            "fault target journal contains another launch or process"
        )
    target_journal_raw = b"".join(item.raw + b"\n" for item in journal_records)
    peer_records = [
        item
        for item in effects
        if (
            item.event["process"]["host"],
            item.event["process"]["role"],
            item.event["process"]["ordinal"],
            item.event["process"]["process_epoch"],
        )
        in set(peer_slots)
    ]
    quarantine_identity = (args.quarantine_device, args.quarantine_inode)

    def commit_fault() -> None:
        quarantined = quarantine_journal(
            root,
            Path(args.quarantine_dir),
            journal,
            expected_root_identity=source_identity,
            expected_quarantine_identity=quarantine_identity,
            max_bytes=MAX_JOURNAL_BYTES,
        )
        try:
            if quarantined.raw != target_journal_raw:
                raise LifecycleSourceError("fault target journal changed after prepare")
            remaining = read_events(
                root,
                source_identity,
                max_total_bytes=MAX_JOURNAL_BYTES,
            )
            if any(
                is_effect(item)
                and all(
                    item.event["process"].get(field) == target[field]
                    for field in target
                )
                for item in remaining
            ):
                raise LifecycleSourceError(
                    "fault target evidence reappeared after quarantine"
                )
            remaining_peer_slots = {
                (
                    item.event["process"]["host"],
                    item.event["process"]["role"],
                    item.event["process"]["ordinal"],
                    item.event["process"]["process_epoch"],
                )
                for item in remaining
                if is_effect(item) and item.event["process"]["role"] == "worker"
            }
            if not set(peer_slots).issubset(remaining_peer_slots):
                raise LifecycleSourceError("fault changed non-target worker evidence")
            _audit(
                "partial-worker-evidence-quarantine",
                scenario=request["scenario"],
                plan_id=request["plan_id"],
                launch_id=request["launch_id"],
                controller_instance=request["controller_instance"],
                lifecycle_invocation_id=request["invocation_id"],
                descriptor_base64=base64.b64encode(descriptor_raw).decode(),
                descriptor_sha256="sha256:"
                + hashlib.sha256(descriptor_raw).hexdigest(),
                target=target,
                entry_point=entry_point,
                peer_slots=[
                    {
                        "host": host,
                        "role": role,
                        "ordinal": ordinal,
                        "process_epoch": epoch,
                    }
                    for host, role, ordinal, epoch in peer_slots
                ],
                target_records=[
                    {
                        "journal": item.journal,
                        "line_number": item.line_number,
                        "event_id": item.event.get("event_id"),
                        "process": item.event["process"],
                    }
                    for item in target_effects
                ],
                peer_records=[
                    {
                        "journal": item.journal,
                        "line_number": item.line_number,
                        "event_id": item.event.get("event_id"),
                        "process": item.event["process"],
                        "raw_base64": base64.b64encode(item.raw).decode(),
                        "raw_sha256": "sha256:" + hashlib.sha256(item.raw).hexdigest(),
                    }
                    for item in peer_records
                ],
                quarantined_journal=quarantined.journal,
                quarantined_device=quarantined.device,
                quarantined_inode=quarantined.inode,
                quarantined_base64=base64.b64encode(quarantined.raw).decode(),
                quarantined_sha256="sha256:"
                + hashlib.sha256(quarantined.raw).hexdigest(),
            )
        except BaseException as exc:
            try:
                restore_quarantined_journal(
                    root,
                    Path(args.quarantine_dir),
                    quarantined,
                    expected_root_identity=source_identity,
                    expected_quarantine_identity=quarantine_identity,
                    max_bytes=MAX_JOURNAL_BYTES,
                )
            except BaseException as rollback_exc:
                raise LifecycleSourceError(
                    "partial-coverage fault failed and rollback failed"
                ) from rollback_exc
            raise exc

    return PreparedFact(request["scenario"], commit_fault)


def _journal(args: argparse.Namespace, request: dict[str, Any]) -> bool:
    if request["fact"] != "observer-captured":
        raise LifecycleSourceError("journal source received another phase")
    root = Path(args.event_dir)
    records = read_events(
        root,
        (args.device, args.inode),
        max_total_bytes=MAX_JOURNAL_BYTES,
    )
    selected = [
        item
        for item in records
        if item.event["plan_id"] == request["plan_id"]
        and item.event["launch_id"] == request["launch_id"]
        and item.event["event"] == "invoked"
        and item.event["observation_kind"] == "scheduler_dispatch"
        and item.event["binding_status"] == "bound"
        and item.event["controller_instance_id"] == request["controller_instance"]
        and item.event["process"].get("assignment_source") == "host"
    ]
    if not selected:
        raise LifecycleSourceError(
            "host journal has no bound scheduler dispatch for this Plan, "
            "launch, and controller"
        )
    _audit(
        "host-journal-capture",
        plan_id=request["plan_id"],
        launch_id=request["launch_id"],
        controller_instance=request["controller_instance"],
        lifecycle_invocation_id=request["invocation_id"],
        event_count=len(selected),
        selected_event_ids=[item.event["event_id"] for item in selected],
        journal_records=[
            {
                "journal": item.journal,
                "line_number": item.line_number,
                "event_id": item.event["event_id"],
                "event": item.event["event"],
                "observation_kind": item.event["observation_kind"],
                "controller_instance_id": item.event["controller_instance_id"],
                "invocation_seq": item.event["invocation_seq"],
                "dispatch_id": item.event["dispatch_id"],
                "raw_base64": base64.b64encode(item.raw).decode(),
                "raw_sha256": "sha256:" + hashlib.sha256(item.raw).hexdigest(),
            }
            for item in records
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
    except ProcessLookupError as exc:
        raise LifecycleSourceError(
            "shutdown target exited before independent identity binding"
        ) from exc
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
    workload.add_argument("--request-sha256", required=True)
    workload.add_argument("--timeout", type=float, default=60.0)
    fault = commands.add_parser("partial-coverage-quarantine")
    fault.add_argument("--event-dir", required=True)
    fault.add_argument("--device", required=True, type=int)
    fault.add_argument("--inode", required=True, type=int)
    fault.add_argument("--quarantine-dir", required=True)
    fault.add_argument("--quarantine-device", required=True, type=int)
    fault.add_argument("--quarantine-inode", required=True, type=int)
    fault.add_argument("--descriptor", required=True)
    fault.add_argument("--descriptor-sha256", required=True)
    journal = commands.add_parser("journal-capture")
    journal.add_argument("--event-dir", required=True)
    journal.add_argument("--device", required=True, type=int)
    journal.add_argument("--inode", required=True, type=int)
    shutdown = commands.add_parser("shutdown-process")
    shutdown.add_argument("--timeout", type=float, default=60.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers: dict[
        str,
        Callable[[argparse.Namespace, dict[str, Any]], bool | str | PreparedFact],
    ] = {
        "readiness-http": _readiness,
        "workload-http": _workload,
        "partial-coverage-quarantine": _partial_coverage_fault,
        "journal-capture": _journal,
        "shutdown-process": _shutdown,
    }
    try:
        request = _read_request(sys.stdin)
        result = handlers[args.source](args, request)
        value = result.value if isinstance(result, PreparedFact) else result
        _send_fact(request, value, stream=sys.stdin)
        if isinstance(result, PreparedFact):
            result.commit()
    except (HostEventSinkError, LifecycleSourceError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
