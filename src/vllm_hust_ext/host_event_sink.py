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
DEVICE_ENV = "ECPA_HOST_EVENT_DEVICE"
INODE_ENV = "ECPA_HOST_EVENT_INODE"


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


def _open_journal_root(
    root: Path, expected_identity: tuple[int, int] | None = None
) -> tuple[Path, int]:
    """Open and verify the directory actually used for journal I/O."""
    if not root.is_absolute() or root.is_symlink():
        raise HostEventSinkError("host event directory must be an existing real path")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise HostEventSinkError("host event directory is unavailable") from exc
    if resolved != root:
        raise HostEventSinkError("host event directory must be canonical")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise HostEventSinkError("cannot open host event directory") from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise HostEventSinkError("cannot inspect host event directory") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise HostEventSinkError("host event directory must be private and owned")
    if (
        expected_identity is not None
        and (
            metadata.st_dev,
            metadata.st_ino,
        )
        != expected_identity
    ):
        os.close(descriptor)
        raise HostEventSinkError("host event directory identity changed")
    return resolved, descriptor


def _expected_directory_identity() -> tuple[int, int] | None:
    device = os.getenv(DEVICE_ENV)
    inode = os.getenv(INODE_ENV)
    if device is None and inode is None:
        return None
    try:
        if device is None or inode is None:
            raise ValueError("incomplete identity")
        parsed = (int(device), int(inode))
        if any(value < 0 for value in parsed):
            raise ValueError("negative identity")
    except ValueError as exc:
        raise HostEventSinkError("host event directory identity is invalid") from exc
    return parsed


def _configured_journal_root() -> tuple[Path, int]:
    configured = os.getenv(JOURNAL_ENV)
    if not configured:
        raise HostEventSinkError(f"{JOURNAL_ENV} is required")
    return _open_journal_root(Path(configured), _expected_directory_identity())


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
    _root, directory = _configured_journal_root()
    try:
        fsync = os.getenv(FSYNC_ENV, "0")
        if fsync not in {"0", "1"}:
            raise HostEventSinkError(f"{FSYNC_ENV} must be 0 or 1")
        name = _journal_name(event)
        flags = os.O_APPEND | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_WRONLY
        created = False
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(name, flags, dir_fd=directory)
            except OSError as exc:
                raise HostEventSinkError("cannot open host event journal") from exc
        except OSError as exc:
            raise HostEventSinkError("cannot open host event journal") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise HostEventSinkError(
                    "host event journal is not an owned regular file"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                os.fchmod(descriptor, 0o600)
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
                    raise HostEventSinkError("host event journal mode is not 0600")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise HostEventSinkError(
                        "host event journal append made no progress"
                    )
                view = view[written:]
            if fsync == "1":
                os.fsync(descriptor)
        except OSError as exc:
            raise HostEventSinkError("cannot write or sync host event journal") from exc
        finally:
            os.close(descriptor)
        if fsync == "1" and created:
            try:
                os.fsync(directory)
            except OSError as exc:
                raise HostEventSinkError("cannot sync host event directory") from exc
    finally:
        os.close(directory)


def read_events(
    root: Path,
    expected_identity: tuple[int, int] | None = None,
    *,
    max_total_bytes: int | None = None,
) -> tuple[JournalEvent, ...]:
    """Read complete regular journals without following file symlinks."""
    if max_total_bytes is not None and (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or max_total_bytes <= 0
    ):
        raise HostEventSinkError("host event read limit must be a positive integer")
    if expected_identity is None and os.getenv(JOURNAL_ENV) == str(root):
        expected_identity = _expected_directory_identity()
    _root, directory = _open_journal_root(root, expected_identity)
    records: list[JournalEvent] = []
    event_ids: set[str] = set()
    total_bytes = 0
    try:
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".jsonl"):
                continue
            try:
                descriptor = os.open(
                    name,
                    os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_RDONLY,
                    dir_fd=directory,
                )
            except OSError as exc:
                raise HostEventSinkError("cannot open host event journal") from exc
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                ):
                    raise HostEventSinkError(
                        "host event journal is not an owned regular file"
                    )
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    if max_total_bytes is None:
                        journal_bytes = stream.read()
                    else:
                        remaining = max_total_bytes - total_bytes
                        journal_bytes = stream.read(remaining + 1)
                        if len(journal_bytes) > remaining:
                            raise HostEventSinkError(
                                "host event journals exceed the read limit"
                            )
                        total_bytes += len(journal_bytes)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if journal_bytes and not journal_bytes.endswith(b"\n"):
                raise HostEventSinkError(
                    "host event journal has a partial final record"
                )
            for line_number, raw in enumerate(journal_bytes.splitlines(), 1):
                if not raw:
                    raise HostEventSinkError(
                        "host event journal contains an empty record"
                    )
                event = parse_host_event(raw)
                if event["event_id"] in event_ids:
                    raise HostEventSinkError("duplicate host event id across journals")
                event_ids.add(event["event_id"])
                records.append(JournalEvent(name, line_number, raw, event))
    finally:
        os.close(directory)
    return tuple(records)
