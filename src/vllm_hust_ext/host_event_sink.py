"""Deployment-owned JSONL sink for vLLM-HUST host evidence."""

from __future__ import annotations

import ctypes
import fcntl
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
RENAME_NOREPLACE = 1
QUARANTINE_LOCK = ".ecpa-quarantine.lock"


class HostEventSinkError(RuntimeError):
    """The deployment-owned evidence journal is unavailable or unsafe."""


@dataclass(frozen=True)
class JournalEvent:
    """One exact line independently read from a process journal."""

    journal: str
    line_number: int
    raw: bytes
    event: dict[str, Any]


@dataclass(frozen=True)
class QuarantinedJournal:
    """One atomically withheld journal with its exact retained bytes."""

    journal: str
    raw: bytes
    device: int
    inode: int


def _rename_noreplace(
    source_directory: int,
    source: str,
    destination_directory: int,
    destination: str,
) -> None:
    """Use Linux renameat2 so a raced destination can never be overwritten."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError("renameat2 is unavailable") from exc
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_directory,
        os.fsencode(source),
        destination_directory,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


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


def _quarantine_fence_name(journal: str) -> str:
    """Return the persistent fence name protecting one quarantined journal."""
    return ".ecpa-quarantine-" + hashlib.sha256(journal.encode()).hexdigest() + ".fence"


def _acquire_quarantine_lock(
    directory: int, *, exclusive: bool, nonblocking: bool = True
) -> int:
    """Acquire the source-directory fence shared by writers and the actuator."""
    descriptor = -1
    try:
        descriptor = os.open(
            QUARANTINE_LOCK,
            os.O_CLOEXEC | os.O_NOFOLLOW | os.O_RDWR | os.O_CREAT,
            0o600,
            dir_fd=directory,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            os.close(descriptor)
            descriptor = -1
            raise HostEventSinkError("host event quarantine lock is unsafe")
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if nonblocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(descriptor, operation)
        return descriptor
    except BlockingIOError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise HostEventSinkError("host event journal is fenced for quarantine") from exc
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise HostEventSinkError("cannot acquire host event quarantine lock") from exc


def append_event(event: dict[str, Any]) -> None:
    """Validate and append one host event to its process-specific journal."""
    raw = canonical_event(event) + b"\n"
    _root, directory = _configured_journal_root()
    fence = -1
    try:
        fence = _acquire_quarantine_lock(directory, exclusive=False, nonblocking=False)
        fsync = os.getenv(FSYNC_ENV, "0")
        if fsync not in {"0", "1"}:
            raise HostEventSinkError(f"{FSYNC_ENV} must be 0 or 1")
        name = _journal_name(event)
        try:
            os.stat(
                _quarantine_fence_name(name),
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise HostEventSinkError("cannot inspect journal quarantine fence") from exc
        else:
            raise HostEventSinkError("host event journal is durably quarantined")
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
        if fence >= 0:
            os.close(fence)
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


def snapshot_journal(
    root: Path,
    journal: str,
    *,
    expected_root_identity: tuple[int, int],
    max_bytes: int,
) -> QuarantinedJournal:
    """Read one stable journal and bind its exact bytes and inode before mutation."""
    if (
        Path(journal).name != journal
        or not journal.endswith(".jsonl")
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
    ):
        raise HostEventSinkError("journal snapshot request is invalid")
    _root, directory = _open_journal_root(root, expected_root_identity)
    try:
        try:
            descriptor = os.open(
                journal,
                os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_RDONLY,
                dir_fd=directory,
            )
        except OSError as exc:
            raise HostEventSinkError("cannot open journal for snapshot") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid():
                raise HostEventSinkError(
                    "journal snapshot source is not an owned regular file"
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw = stream.read(max_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > max_bytes:
            raise HostEventSinkError("journal snapshot source exceeds the limit")
        if raw and not raw.endswith(b"\n"):
            raise HostEventSinkError("journal snapshot source is partial")
        try:
            after = os.stat(journal, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise HostEventSinkError("journal snapshot source disappeared") from exc
        if (after.st_dev, after.st_ino) != (
            before.st_dev,
            before.st_ino,
        ) or after.st_size != before.st_size:
            raise HostEventSinkError("journal snapshot source identity changed")
        return QuarantinedJournal(journal, raw, before.st_dev, before.st_ino)
    finally:
        os.close(directory)


def quarantine_journal(
    root: Path,
    quarantine_root: Path,
    journal: str,
    *,
    expected_root_identity: tuple[int, int],
    expected_quarantine_identity: tuple[int, int],
    max_bytes: int,
    expected_journal: QuarantinedJournal | None = None,
) -> QuarantinedJournal:
    """Atomically move one exact journal into a same-filesystem quarantine."""
    if (
        Path(journal).name != journal
        or not journal.endswith(".jsonl")
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
    ):
        raise HostEventSinkError("journal quarantine request is invalid")
    source_path, source_directory = _open_journal_root(root, expected_root_identity)
    try:
        quarantine_path, quarantine_directory = _open_journal_root(
            quarantine_root, expected_quarantine_identity
        )
    except BaseException:
        os.close(source_directory)
        raise
    moved = False
    try:
        source_metadata = os.fstat(source_directory)
        quarantine_metadata = os.fstat(quarantine_directory)
        if source_path == quarantine_path:
            raise HostEventSinkError("journal quarantine must use another directory")
        if source_metadata.st_dev != quarantine_metadata.st_dev:
            raise HostEventSinkError("journal quarantine must share a filesystem")
        try:
            os.stat(journal, dir_fd=quarantine_directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise HostEventSinkError(
                "cannot inspect journal quarantine target"
            ) from exc
        else:
            raise HostEventSinkError("journal quarantine target already exists")

        try:
            descriptor = os.open(
                journal,
                os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_RDONLY,
                dir_fd=source_directory,
            )
        except OSError as exc:
            raise HostEventSinkError("cannot open journal for quarantine") from exc
        try:
            file_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_uid != os.geteuid()
            ):
                raise HostEventSinkError(
                    "journal quarantine source is not an owned regular file"
                )
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw = stream.read(max_bytes + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > max_bytes:
            raise HostEventSinkError("journal quarantine source exceeds the limit")
        if raw and not raw.endswith(b"\n"):
            raise HostEventSinkError("journal quarantine source is partial")
        if expected_journal is not None and (
            expected_journal.journal != journal
            or expected_journal.raw != raw
            or expected_journal.device != file_metadata.st_dev
            or expected_journal.inode != file_metadata.st_ino
        ):
            raise HostEventSinkError(
                "journal quarantine source differs from the expected receipt"
            )
        try:
            current = os.stat(journal, dir_fd=source_directory, follow_symlinks=False)
        except OSError as exc:
            raise HostEventSinkError("journal quarantine source disappeared") from exc
        if (current.st_dev, current.st_ino) != (
            file_metadata.st_dev,
            file_metadata.st_ino,
        ) or current.st_size != file_metadata.st_size:
            raise HostEventSinkError("journal quarantine source identity changed")

        try:
            _rename_noreplace(
                source_directory,
                journal,
                quarantine_directory,
                journal,
            )
            moved = True
            os.fsync(source_directory)
            os.fsync(quarantine_directory)
            destination = os.stat(
                journal, dir_fd=quarantine_directory, follow_symlinks=False
            )
            if (destination.st_dev, destination.st_ino) != (
                file_metadata.st_dev,
                file_metadata.st_ino,
            ):
                raise HostEventSinkError("quarantined journal identity changed")
            try:
                descriptor = os.open(
                    journal,
                    os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_RDONLY,
                    dir_fd=quarantine_directory,
                )
            except OSError as exc:
                raise HostEventSinkError("cannot open quarantined journal") from exc
            try:
                retained_metadata = os.fstat(descriptor)
                if (retained_metadata.st_dev, retained_metadata.st_ino) != (
                    file_metadata.st_dev,
                    file_metadata.st_ino,
                ):
                    raise HostEventSinkError(
                        "quarantined journal changed before validation"
                    )
                with os.fdopen(descriptor, "rb") as stream:
                    descriptor = -1
                    retained = stream.read(max_bytes + 1)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            if retained != raw:
                raise HostEventSinkError("quarantined journal bytes changed")
            try:
                os.stat(journal, dir_fd=source_directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise HostEventSinkError("quarantined journal remains visible")
        except OSError as exc:
            raise HostEventSinkError("cannot atomically quarantine journal") from exc
        return QuarantinedJournal(
            journal=journal,
            raw=raw,
            device=file_metadata.st_dev,
            inode=file_metadata.st_ino,
        )
    except BaseException as original:
        if moved:
            try:
                os.stat(journal, dir_fd=source_directory, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    _rename_noreplace(
                        quarantine_directory,
                        journal,
                        source_directory,
                        journal,
                    )
                    os.fsync(source_directory)
                    os.fsync(quarantine_directory)
                except OSError as rollback_error:
                    raise HostEventSinkError(
                        "journal quarantine failed and rollback failed"
                    ) from rollback_error
            except OSError as rollback_error:
                raise HostEventSinkError(
                    "journal quarantine failed and rollback target is unsafe"
                ) from rollback_error
            else:
                raise HostEventSinkError(
                    "journal quarantine failed and rollback target exists"
                ) from original
        raise
    finally:
        os.close(source_directory)
        os.close(quarantine_directory)


def restore_quarantined_journal(
    root: Path,
    quarantine_root: Path,
    quarantined: QuarantinedJournal,
    *,
    expected_root_identity: tuple[int, int],
    expected_quarantine_identity: tuple[int, int],
    max_bytes: int,
) -> None:
    """Restore an exact quarantined journal without overwriting new evidence."""
    restored = quarantine_journal(
        quarantine_root,
        root,
        quarantined.journal,
        expected_root_identity=expected_quarantine_identity,
        expected_quarantine_identity=expected_root_identity,
        max_bytes=max_bytes,
        expected_journal=quarantined,
    )
    if (
        restored.raw != quarantined.raw
        or restored.device != quarantined.device
        or restored.inode != quarantined.inode
    ):
        raise HostEventSinkError("restored journal differs from quarantine receipt")
