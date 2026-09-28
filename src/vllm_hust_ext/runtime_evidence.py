"""Process-owned runtime evidence for Manager-supervised vLLM launches."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from vllm_hust_ext.config import config_path
from vllm_hust_ext.discovery import InstalledBundle

_HOST_SCHEMA = "vllm-hust-plugin-evidence/0.1"
_SINK = "vllm_hust_ext.runtime_evidence:record_event"
_PATH_ENV = "VLLM_HUST_EXT_EVIDENCE_PATH"
_EVIDENCE_ENVIRONMENT = (
    "VLLM_ECPA_EVIDENCE_SINK",
    "VLLM_ECPA_EVIDENCE_STRICT",
    "VLLM_ECPA_PLAN_ID",
    "VLLM_ECPA_LAUNCH_ID",
    _PATH_ENV,
)
_MAX_READ_BYTES = 1024 * 1024


def evidence_path() -> Path:
    override = os.environ.get(_PATH_ENV)
    return (
        Path(override)
        if override
        else config_path().with_name("runtime-evidence.jsonl")
    )


def _require_bound_event(event: dict[str, Any]) -> None:
    if event.get("schema") != _HOST_SCHEMA:
        raise ValueError("unsupported host evidence schema")
    if event.get("binding_status") != "bound":
        raise ValueError("unbound host evidence is not accepted")
    if not isinstance(event.get("plan_id"), str) or not event["plan_id"]:
        raise ValueError("host evidence requires plan_id")
    if not isinstance(event.get("launch_id"), str) or not event["launch_id"]:
        raise ValueError("host evidence requires launch_id")
    process = event.get("process")
    if not isinstance(process, dict):
        raise ValueError("host evidence requires process identity")
    if not isinstance(process.get("host"), str) or not process["host"]:
        raise ValueError("host evidence process requires host")
    if not isinstance(process.get("pid"), int) or isinstance(process["pid"], bool):
        raise ValueError("host evidence process requires pid")
    if (
        not isinstance(process.get("start_identity"), str)
        or not process["start_identity"]
    ):
        raise ValueError("host evidence process requires start_identity")


def record_event(event: dict[str, Any]) -> None:
    """Append one validated event; called inside the supervised host process."""

    if not isinstance(event, dict):
        raise TypeError("host evidence must be an object")
    _require_bound_event(event)
    target = evidence_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n").encode()
    descriptor = os.open(target, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def launch_environment(bundles: Sequence[InstalledBundle]) -> dict[str, str]:
    """Create a fresh binding for one actual Manager-supervised launch."""

    conflicts = [name for name in _EVIDENCE_ENVIRONMENT if name in os.environ]
    if conflicts:
        raise ValueError(
            "vllm-hust-ext owns runtime evidence environment variables: "
            f"{sorted(conflicts)}"
        )
    plan_material = json.dumps(
        [
            [
                bundle.bundle_id,
                getattr(bundle.manifest, "bundle_version", "unknown"),
                str(getattr(bundle, "manifest_path", "unknown")),
            ]
            for bundle in sorted(bundles, key=lambda item: item.bundle_id)
        ],
        separators=(",", ":"),
    ).encode()
    return {
        "VLLM_ECPA_EVIDENCE_SINK": _SINK,
        "VLLM_ECPA_EVIDENCE_STRICT": "1",
        "VLLM_ECPA_PLAN_ID": hashlib.sha256(plan_material).hexdigest(),
        "VLLM_ECPA_LAUNCH_ID": str(uuid.uuid4()),
        _PATH_ENV: str(evidence_path()),
    }


def _start_identity(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        close = raw.rfind(")")
        fields_after_comm = raw[close + 1 :].split()
        start_ticks = fields_after_comm[19]
        int(start_ticks)
    except (OSError, IndexError, ValueError):
        return None
    return f"pid:{pid}:start_ticks:{start_ticks}"


def _process_is_current(process: object) -> bool:
    if not isinstance(process, dict):
        return False
    pid = process.get("pid")
    return bool(
        isinstance(pid, int)
        and not isinstance(pid, bool)
        and process.get("host") == socket.gethostname()
        and process.get("start_identity") == _start_identity(pid)
    )


def _events() -> tuple[dict[str, Any], ...]:
    target = evidence_path()
    try:
        with target.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - _MAX_READ_BYTES))
            if size > _MAX_READ_BYTES:
                stream.readline()
            lines = stream.readlines()
    except OSError:
        return ()
    events: list[dict[str, Any]] = []
    for line in lines:
        try:
            event = json.loads(line)
            _require_bound_event(event)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
        events.append(event)
    return tuple(events)


def runtime_effective_evidence(bundle: InstalledBundle) -> str | None:
    """Return evidence only for a live process that observed real runtime work."""

    entry_points = {
        (
            dict(carrier.attributes).get("group"),
            dict(carrier.attributes).get("name"),
        )
        for carrier in bundle.manifest.implementation
        if carrier.type == "python_entry_point"
    }
    for event in reversed(_events()):
        entry_point = event.get("entry_point")
        if (
            event.get("event") != "effective"
            or event.get("observation_kind") != "runtime_effective"
            or not isinstance(entry_point, dict)
            or (entry_point.get("group"), entry_point.get("name")) not in entry_points
            or not _process_is_current(event.get("process"))
        ):
            continue
        process = event["process"]
        return (
            "live host runtime observer evidence "
            f"launch_id={event['launch_id']} pid={process['pid']} "
            f"event_id={event.get('event_id', 'unknown')}"
        )
    return None
