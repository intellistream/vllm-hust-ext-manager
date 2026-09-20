"""Deployment-owned JSONL sink for vLLM-HUST host evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .host_evidence import parse_host_event

JOURNAL_ENV = "ECPA_HOST_EVENT_DIR"
FSYNC_ENV = "ECPA_HOST_EVENT_FSYNC"


class HostEventSinkError(RuntimeError):
    """The deployment-owned evidence journal is unavailable or unsafe."""


@dataclass(frozen=True)
class JournalEvent:
    """One exact line independently read from a process journal."""

    journal: str
    line_number: int
    raw: bytes
    event: dict[str, Any]


def canonical_event(event: dict[str, Any]) -> bytes:
    """Return the exact bytes persisted and later bound by attestation."""
    try:
        raw = json.dumps(
            event, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise HostEventSinkError("host event is not canonicalizable") from exc
    parse_host_event(raw)
    return raw


def _journal_root() -> Path:
    configured = os.getenv(JOURNAL_ENV)
    if not configured:
        raise HostEventSinkError(f"{JOURNAL_ENV} is required")
    root = Path(configured)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise HostEventSinkError("host event directory must be an existing real path")
    resolved = root.resolve(strict=True)
    if resolved != root:
        raise HostEventSinkError("host event directory must be canonical")
    return resolved


def _journal_name(event: dict[str, Any]) -> str:
    process = event["process"]
    material = json.dumps(
        [
            event["plan_id"],
            event["launch_id"],
            process["host"],
            process["role"],
            process["ordinal"],
            process["pid"],
            process["start_identity"],
            process["process_epoch"],
        ],
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest() + ".jsonl"


def append_event(event: dict[str, Any]) -> None:
    """Validate and append one host event to its process-specific journal."""
    raw = canonical_event(event) + b"\n"
    root = _journal_root()
    fsync = os.getenv(FSYNC_ENV, "0")
    if fsync not in {"0", "1"}:
        raise HostEventSinkError(f"{FSYNC_ENV} must be 0 or 1")
    path = root / _journal_name(event)
    flags = os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_WRONLY
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise HostEventSinkError("cannot open host event journal") from exc
    except OSError as exc:
        raise HostEventSinkError("cannot open host event journal") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise HostEventSinkError("host event journal is not an owned regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                raise HostEventSinkError("host event journal mode is not 0600")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HostEventSinkError("host event journal append made no progress")
            view = view[written:]
        if fsync == "1":
            os.fsync(descriptor)
    except OSError as exc:
        raise HostEventSinkError("cannot write or sync host event journal") from exc
    finally:
        os.close(descriptor)
    if fsync == "1" and created:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            directory = os.open(root, directory_flags)
        except OSError as exc:
            raise HostEventSinkError("cannot open host event directory") from exc
        try:
            os.fsync(directory)
        except OSError as exc:
            raise HostEventSinkError("cannot sync host event directory") from exc
        finally:
            os.close(directory)


def read_events(root: Path) -> tuple[JournalEvent, ...]:
    """Read complete regular journals without following file symlinks."""
    if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root:
        raise HostEventSinkError("host event directory must be canonical")
    records: list[JournalEvent] = []
    event_ids: set[str] = set()
    for path in sorted(root.iterdir()):
        if path.suffix != ".jsonl":
            continue
        try:
            descriptor = os.open(path, os.O_CLOEXEC | os.O_NOFOLLOW | os.O_RDONLY)
        except OSError as exc:
            raise HostEventSinkError("cannot open host event journal") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise HostEventSinkError(
                    "host event journal is not an owned regular file"
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                journal_bytes = stream.read()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if journal_bytes and not journal_bytes.endswith(b"\n"):
            raise HostEventSinkError("host event journal has a partial final record")
        for line_number, raw in enumerate(journal_bytes.splitlines(), 1):
            if not raw:
                raise HostEventSinkError("host event journal contains an empty record")
            event = parse_host_event(raw)
            if event["event_id"] in event_ids:
                raise HostEventSinkError("duplicate host event id across journals")
            event_ids.add(event["event_id"])
            records.append(JournalEvent(path.name, line_number, raw, event))
    return tuple(records)
