"""Crash-consistent recovery for formal evidence quarantine control flow."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ecpa_model import canonical_bytes
from .host_event_sink import (
    HostEventSinkError,
    QuarantinedJournal,
    _acquire_quarantine_lock,
    _open_journal_root,
    _quarantine_fence_name,
    _rename_noreplace,
    restore_quarantined_journal,
    snapshot_journal,
)

INTENT_SCHEMA = "ecpa-quarantine-intent/v1"
APPLIED_SCHEMA = "ecpa-quarantine-applied/v1"
FINALIZED_SCHEMA = "ecpa-quarantine-finalized/v1"
RESTORED_SCHEMA = "ecpa-quarantine-restored/v1"
BLOCKED_SCHEMA = "ecpa-quarantine-blocked/v1"
FENCE_SCHEMA = "ecpa-quarantine-source-fence/v1"
MAX_TRANSACTION_RECORD_BYTES = 2 * 1024 * 1024
_DIGEST_PREFIX = "sha256:"
_INTENT_FIELDS = {
    "schema",
    "transaction_id",
    "binding",
    "source_directory",
    "quarantine_directory",
    "journal",
    "journal_device",
    "journal_inode",
    "journal_bytes",
    "journal_base64",
    "journal_sha256",
}
_APPLIED_FIELDS = {
    "schema",
    "transaction_id",
    "intent_digest",
    "journal",
    "journal_device",
    "journal_inode",
    "journal_bytes",
    "journal_sha256",
}
_TERMINAL_FIELDS = {
    "schema",
    "transaction_id",
    "intent_digest",
    "applied_digest",
    "reason",
    "finalized_digest",
}
_FINALIZED_FIELDS = {
    "schema",
    "transaction_id",
    "intent_digest",
    "applied_digest",
    "fact_receipt_sha256",
    "source_process_identity",
}
_RESTORE_REASONS = {
    "catchable-post-move-failure",
    "no-move-observed",
    "restored-after-applied",
    "restored-after-move",
}
_BLOCK_REASONS = {
    "journal-missing-from-both-roots",
    "restore-verification-failed",
    "source-changed-before-recovery",
    "source-replacement-collision",
    "source-replacement-after-finalize",
}
_FENCE_FIELDS = {
    "schema",
    "transaction_id",
    "intent_digest",
    "journal",
    "journal_device",
    "journal_inode",
    "journal_sha256",
}
_TRANSACTION_TEMP_PATTERN = re.compile(
    r"\.ecpa-transaction-[0-9a-f]{64}\."
    r"(?:intent|applied|finalized|restored|blocked)\."
    r"[1-9][0-9]*\.[0-9a-f]{32}\.tmp\Z"
)
_FENCE_TEMP_PATTERN = re.compile(
    r"\.ecpa-fence-temp-[0-9a-f]{64}\."
    r"[1-9][0-9]*\.[0-9a-f]{32}\.tmp\Z"
)


class QuarantineTransactionError(RuntimeError):
    """A durable quarantine transaction is malformed or cannot converge safely."""


@dataclass(frozen=True)
class DurableRecord:
    name: str
    raw: bytes
    digest: str
    value: dict[str, Any]


@dataclass(frozen=True)
class ReconciliationResult:
    restored: tuple[str, ...]
    finalized: tuple[str, ...]


@dataclass
class QuarantineTransactionLease:
    """Exclusive process lease spanning prepare through actuator completion."""

    root: Path
    identity: tuple[int, int]
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def acquire_quarantine_transaction_lease(
    root: Path, expected_identity: tuple[int, int]
) -> QuarantineTransactionLease:
    """Acquire the private-root transaction lease without waiting past a deadline."""
    resolved, directory = _open_journal_root(root, expected_identity)
    try:
        try:
            descriptor = _acquire_quarantine_lock(directory, exclusive=True)
        except HostEventSinkError as exc:
            raise QuarantineTransactionError(
                "another quarantine transaction is active"
            ) from exc
        os.fsync(directory)
        return QuarantineTransactionLease(resolved, expected_identity, descriptor)
    finally:
        os.close(directory)


def _require_lease(
    lease: QuarantineTransactionLease,
    root: Path,
    expected_identity: tuple[int, int],
) -> None:
    if (
        lease.descriptor < 0
        or lease.identity != expected_identity
        or root.resolve(strict=True) != lease.root
    ):
        raise QuarantineTransactionError("quarantine transaction lease is invalid")


def quarantine_transaction_id(binding: dict[str, Any]) -> str:
    """Return the stable identifier for one challenge-bound quarantine attempt."""
    return hashlib.sha256(canonical_bytes(binding)).hexdigest()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(_DIGEST_PREFIX)
        and len(value) == len(_DIGEST_PREFIX) + 64
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _directory_value(identity: tuple[int, int]) -> dict[str, int]:
    return {"device": identity[0], "inode": identity[1]}


def _record_name(transaction_id: str, stage: str) -> str:
    if (
        len(transaction_id) != 64
        or any(character not in "0123456789abcdef" for character in transaction_id)
        or stage not in {"intent", "applied", "finalized", "restored", "blocked"}
    ):
        raise QuarantineTransactionError("quarantine transaction name is invalid")
    return f"ecpa-{transaction_id}.{stage}.json"


def _read_record_from_directory(
    directory: int,
    name: str,
    *,
    required: bool,
) -> DurableRecord | None:
    try:
        descriptor = os.open(
            name,
            os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_RDONLY,
            dir_fd=directory,
        )
    except FileNotFoundError:
        if not required:
            return None
        raise QuarantineTransactionError(
            f"quarantine transaction record is missing: {name}"
        ) from None
    except OSError as exc:
        raise QuarantineTransactionError(
            f"cannot open quarantine transaction record: {name}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise QuarantineTransactionError(
                f"quarantine transaction record is unsafe: {name}"
            )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_TRANSACTION_RECORD_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_TRANSACTION_RECORD_BYTES:
        raise QuarantineTransactionError(
            f"quarantine transaction record is oversized: {name}"
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise QuarantineTransactionError(
            f"quarantine transaction record is invalid JSON: {name}"
        ) from exc
    if not isinstance(value, dict) or raw != canonical_bytes(value) + b"\n":
        raise QuarantineTransactionError(
            f"quarantine transaction record is not canonical: {name}"
        )
    return DurableRecord(name, raw, _digest(raw), value)


def read_quarantine_record(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    stage: str,
    *,
    required: bool = True,
) -> DurableRecord | None:
    """Read one canonical transaction record through a frozen directory handle."""
    _path, directory = _open_journal_root(root, expected_identity)
    try:
        return _read_record_from_directory(
            directory,
            _record_name(transaction_id, stage),
            required=required,
        )
    finally:
        os.close(directory)


def _write_record(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    stage: str,
    value: dict[str, Any],
) -> DurableRecord:
    name = _record_name(transaction_id, stage)
    raw = canonical_bytes(value) + b"\n"
    if len(raw) > MAX_TRANSACTION_RECORD_BYTES:
        raise QuarantineTransactionError(
            f"quarantine transaction record is oversized: {name}"
        )
    _path, directory = _open_journal_root(root, expected_identity)
    temporary = (
        f".ecpa-transaction-{transaction_id}.{stage}."
        f"{os.getpid()}.{secrets.token_hex(16)}.tmp"
    )
    temporary_exists = False
    try:
        existing = _read_record_from_directory(directory, name, required=False)
        if existing is not None:
            if existing.raw != raw:
                raise QuarantineTransactionError(
                    f"quarantine transaction record conflicts: {name}"
                ) from None
            return existing
        try:
            descriptor = os.open(
                temporary,
                os.O_CLOEXEC | os.O_NOFOLLOW | os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory,
            )
            temporary_exists = True
        except OSError as exc:
            raise QuarantineTransactionError(
                f"cannot create quarantine transaction temporary record: {name}"
            ) from exc
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise QuarantineTransactionError(
                        f"quarantine transaction write made no progress: {name}"
                    )
                view = view[written:]
            os.fsync(descriptor)
        except OSError as exc:
            raise QuarantineTransactionError(
                f"cannot persist quarantine transaction record: {name}"
            ) from exc
        finally:
            os.close(descriptor)
        try:
            _rename_noreplace(directory, temporary, directory, name)
            temporary_exists = False
        except FileExistsError:
            existing = _read_record_from_directory(directory, name, required=True)
            assert existing is not None
            if existing.raw != raw:
                raise QuarantineTransactionError(
                    f"quarantine transaction record conflicts: {name}"
                ) from None
            return existing
        except OSError as exc:
            raise QuarantineTransactionError(
                f"cannot publish quarantine transaction record: {name}"
            ) from exc
        os.fsync(directory)
        published = _read_record_from_directory(directory, name, required=True)
        assert published is not None
        if published.raw != raw:
            raise QuarantineTransactionError(
                f"published quarantine transaction record differs: {name}"
            )
        return published
    finally:
        if temporary_exists:
            try:
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(directory)


def _fence_value(
    transaction_id: str,
    intent_digest: str,
    snapshot: QuarantinedJournal,
) -> dict[str, Any]:
    return {
        "schema": FENCE_SCHEMA,
        "transaction_id": transaction_id,
        "intent_digest": intent_digest,
        "journal": snapshot.journal,
        "journal_device": snapshot.device,
        "journal_inode": snapshot.inode,
        "journal_sha256": _digest(snapshot.raw),
    }


def install_quarantine_source_fence(
    source_root: Path,
    source_identity: tuple[int, int],
    transaction_id: str,
    *,
    intent_digest: str,
    snapshot: QuarantinedJournal,
) -> DurableRecord:
    """Publish a durable writer fence before moving the source journal."""
    name = _quarantine_fence_name(snapshot.journal)
    value = _fence_value(transaction_id, intent_digest, snapshot)
    raw = canonical_bytes(value) + b"\n"
    _path, directory = _open_journal_root(source_root, source_identity)
    temporary = (
        f".ecpa-fence-temp-{transaction_id}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    )
    temporary_exists = False
    try:
        existing = _read_record_from_directory(directory, name, required=False)
        if existing is not None:
            if existing.raw != raw:
                raise QuarantineTransactionError(
                    "source journal has another quarantine fence"
                ) from None
            return existing
        descriptor = os.open(
            temporary,
            os.O_CLOEXEC | os.O_NOFOLLOW | os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory,
        )
        temporary_exists = True
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise QuarantineTransactionError(
                        "source fence write made no progress"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            _rename_noreplace(directory, temporary, directory, name)
            temporary_exists = False
        except FileExistsError:
            existing = _read_record_from_directory(directory, name, required=True)
            assert existing is not None
            if existing.raw != raw:
                raise QuarantineTransactionError(
                    "source journal has another quarantine fence"
                ) from None
            return existing
        os.fsync(directory)
        record = _read_record_from_directory(directory, name, required=True)
        assert record is not None
        if record.raw != raw:
            raise QuarantineTransactionError("published source fence differs")
        return record
    except OSError as exc:
        raise QuarantineTransactionError("cannot publish source journal fence") from exc
    finally:
        if temporary_exists:
            try:
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
            except OSError:
                pass
        os.close(directory)


def _read_source_fence(
    source_directory: int,
    transaction_id: str,
    intent_digest: str,
    snapshot: QuarantinedJournal,
    *,
    required: bool,
) -> DurableRecord | None:
    record = _read_record_from_directory(
        source_directory,
        _quarantine_fence_name(snapshot.journal),
        required=required,
    )
    if record is not None and (
        set(record.value) != _FENCE_FIELDS
        or record.value != _fence_value(transaction_id, intent_digest, snapshot)
    ):
        raise QuarantineTransactionError("source journal fence is inconsistent")
    return record


def _remove_source_fence(
    source_directory: int,
    transaction_id: str,
    intent_digest: str,
    snapshot: QuarantinedJournal,
) -> None:
    record = _read_source_fence(
        source_directory,
        transaction_id,
        intent_digest,
        snapshot,
        required=False,
    )
    if record is None:
        return
    try:
        os.unlink(record.name, dir_fd=source_directory)
        os.fsync(source_directory)
    except OSError as exc:
        raise QuarantineTransactionError(
            "cannot remove restored source journal fence"
        ) from exc


def remove_quarantine_source_fence(
    source_root: Path,
    source_identity: tuple[int, int],
    transaction_id: str,
    *,
    intent_digest: str,
    snapshot: QuarantinedJournal,
) -> None:
    """Remove the exact writer fence after the journal is safely restored."""
    _path, directory = _open_journal_root(source_root, source_identity)
    try:
        _remove_source_fence(directory, transaction_id, intent_digest, snapshot)
    finally:
        os.close(directory)


def prepare_quarantine_transaction(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    binding: dict[str, Any],
    source_identity: tuple[int, int],
    snapshot: QuarantinedJournal,
) -> DurableRecord:
    """Persist the exact pre-mutation bytes before authorizing a journal move."""
    value = {
        "schema": INTENT_SCHEMA,
        "transaction_id": transaction_id,
        "binding": binding,
        "source_directory": {
            "device": source_identity[0],
            "inode": source_identity[1],
        },
        "quarantine_directory": {
            "device": expected_identity[0],
            "inode": expected_identity[1],
        },
        "journal": snapshot.journal,
        "journal_device": snapshot.device,
        "journal_inode": snapshot.inode,
        "journal_bytes": len(snapshot.raw),
        "journal_base64": base64.b64encode(snapshot.raw).decode(),
        "journal_sha256": _digest(snapshot.raw),
    }
    return _write_record(root, expected_identity, transaction_id, "intent", value)


def mark_quarantine_applied(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    intent_digest: str,
    quarantined: QuarantinedJournal,
) -> DurableRecord:
    """Persist that the intent's exact inode now resides in quarantine."""
    value = {
        "schema": APPLIED_SCHEMA,
        "transaction_id": transaction_id,
        "intent_digest": intent_digest,
        "journal": quarantined.journal,
        "journal_device": quarantined.device,
        "journal_inode": quarantined.inode,
        "journal_bytes": len(quarantined.raw),
        "journal_sha256": _digest(quarantined.raw),
    }
    return _write_record(root, expected_identity, transaction_id, "applied", value)


def mark_quarantine_restored(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    intent_digest: str,
    applied_digest: str | None,
    reason: str,
) -> DurableRecord:
    """Persist an idempotent terminal recovery decision."""
    value = {
        "schema": RESTORED_SCHEMA,
        "transaction_id": transaction_id,
        "intent_digest": intent_digest,
        "applied_digest": applied_digest,
        "finalized_digest": None,
        "reason": reason,
    }
    return _write_record(root, expected_identity, transaction_id, "restored", value)


def finalize_quarantine_transaction(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    source_root: Path,
    source_identity: tuple[int, int],
    applied_digest: str,
    fact_receipt_sha256: str,
    source_process_identity: dict[str, Any],
    lease: QuarantineTransactionLease | None = None,
) -> DurableRecord:
    """Let the runner durably accept an applied action after source validation."""
    owned = lease is None
    active_lease = lease or acquire_quarantine_transaction_lease(
        source_root, source_identity
    )
    try:
        _require_lease(active_lease, source_root, source_identity)
        return _finalize_quarantine_transaction_locked(
            root,
            expected_identity,
            transaction_id,
            source_root=source_root,
            source_identity=source_identity,
            applied_digest=applied_digest,
            fact_receipt_sha256=fact_receipt_sha256,
            source_process_identity=source_process_identity,
        )
    finally:
        if owned:
            active_lease.close()


def _finalize_quarantine_transaction_locked(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    source_root: Path,
    source_identity: tuple[int, int],
    applied_digest: str,
    fact_receipt_sha256: str,
    source_process_identity: dict[str, Any],
) -> DurableRecord:
    """Finalize while the caller holds the root's transaction lease."""
    intent = read_quarantine_record(root, expected_identity, transaction_id, "intent")
    applied = read_quarantine_record(root, expected_identity, transaction_id, "applied")
    assert intent is not None and applied is not None
    snapshot = _intent_snapshot(intent, transaction_id)
    _validate_applied(applied, transaction_id, intent, snapshot)
    if (
        intent.value.get("source_directory") != _directory_value(source_identity)
        or intent.value.get("quarantine_directory")
        != _directory_value(expected_identity)
        or applied.digest != applied_digest
        or not _is_digest(fact_receipt_sha256)
        or not _valid_process_identity(source_process_identity)
        or read_quarantine_record(
            root, expected_identity, transaction_id, "restored", required=False
        )
        is not None
        or read_quarantine_record(
            root, expected_identity, transaction_id, "blocked", required=False
        )
        is not None
    ):
        raise QuarantineTransactionError(
            "quarantine transaction cannot be finalized from this state"
        )
    try:
        retained = snapshot_journal(
            root,
            snapshot.journal,
            expected_root_identity=expected_identity,
            max_bytes=max(len(snapshot.raw), 1),
        )
    except HostEventSinkError as exc:
        raise QuarantineTransactionError(
            "quarantine artifact is unavailable during finalization"
        ) from exc
    if retained != snapshot:
        raise QuarantineTransactionError(
            "quarantine artifact differs from the durable intent"
        )
    _source_path, source_directory = _open_journal_root(source_root, source_identity)
    try:
        _read_source_fence(
            source_directory,
            transaction_id,
            intent.digest,
            snapshot,
            required=True,
        )
        if _exists(source_directory, snapshot.journal):
            _mark_blocked(
                root,
                expected_identity,
                transaction_id,
                intent_digest=intent.digest,
                applied_digest=applied.digest,
                finalized_digest=None,
                reason="source-replacement-collision",
            )
            raise QuarantineTransactionError(
                "source journal reappeared before transaction finalization"
            )
    finally:
        os.close(source_directory)
    value = {
        "schema": FINALIZED_SCHEMA,
        "transaction_id": transaction_id,
        "intent_digest": intent.digest,
        "applied_digest": applied.digest,
        "fact_receipt_sha256": fact_receipt_sha256,
        "source_process_identity": source_process_identity,
    }
    return _write_record(root, expected_identity, transaction_id, "finalized", value)


def _valid_process_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {"pid", "start_ticks", "argv", "executable_device", "executable_inode"}
        and all(
            isinstance(value.get(field), int)
            and not isinstance(value.get(field), bool)
            and value[field] > 0
            for field in ("pid", "start_ticks", "executable_device", "executable_inode")
        )
        and isinstance(value.get("argv"), list)
        and bool(value["argv"])
        and all(isinstance(item, str) and item for item in value["argv"])
    )


def _intent_snapshot(intent: DurableRecord, transaction_id: str) -> QuarantinedJournal:
    value = intent.value
    try:
        raw = base64.b64decode(value["journal_base64"], validate=True)
        snapshot = QuarantinedJournal(
            value["journal"],
            raw,
            value["journal_device"],
            value["journal_inode"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise QuarantineTransactionError(
            "quarantine intent snapshot is malformed"
        ) from exc
    try:
        binding_id = quarantine_transaction_id(value.get("binding", {}))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise QuarantineTransactionError(
            "quarantine intent binding is not canonical"
        ) from exc
    if (
        set(value) != _INTENT_FIELDS
        or value.get("schema") != INTENT_SCHEMA
        or value.get("transaction_id") != transaction_id
        or intent.name != _record_name(transaction_id, "intent")
        or binding_id != transaction_id
        or not isinstance(snapshot.journal, str)
        or not snapshot.journal.endswith(".jsonl")
        or Path(snapshot.journal).name != snapshot.journal
        or isinstance(snapshot.device, bool)
        or not isinstance(snapshot.device, int)
        or snapshot.device <= 0
        or isinstance(snapshot.inode, bool)
        or not isinstance(snapshot.inode, int)
        or snapshot.inode <= 0
        or value.get("journal_bytes") != len(raw)
        or value.get("journal_sha256") != _digest(raw)
        or not isinstance(value.get("source_directory"), dict)
        or set(value["source_directory"]) != {"device", "inode"}
        or not isinstance(value.get("quarantine_directory"), dict)
        or set(value["quarantine_directory"]) != {"device", "inode"}
    ):
        raise QuarantineTransactionError("quarantine intent snapshot is inconsistent")
    return snapshot


def _validate_applied(
    applied: DurableRecord,
    transaction_id: str,
    intent: DurableRecord,
    snapshot: QuarantinedJournal,
) -> None:
    value = applied.value
    if (
        set(value) != _APPLIED_FIELDS
        or applied.name != _record_name(transaction_id, "applied")
        or value.get("schema") != APPLIED_SCHEMA
        or value.get("transaction_id") != transaction_id
        or value.get("intent_digest") != intent.digest
        or value.get("journal") != snapshot.journal
        or value.get("journal_device") != snapshot.device
        or value.get("journal_inode") != snapshot.inode
        or value.get("journal_bytes") != len(snapshot.raw)
        or value.get("journal_sha256") != _digest(snapshot.raw)
    ):
        raise QuarantineTransactionError("quarantine applied record is inconsistent")


def _validate_terminal(
    record: DurableRecord,
    transaction_id: str,
    *,
    schema: str,
    stage: str,
    intent_digest: str,
    applied_digest: str | None,
    finalized_digest: str | None,
) -> None:
    value = record.value
    if (
        set(value) != _TERMINAL_FIELDS
        or record.name != _record_name(transaction_id, stage)
        or value.get("schema") != schema
        or value.get("transaction_id") != transaction_id
        or value.get("intent_digest") != intent_digest
        or value.get("applied_digest") != applied_digest
        or value.get("finalized_digest") != finalized_digest
        or value.get("reason")
        not in (_RESTORE_REASONS if schema == RESTORED_SCHEMA else _BLOCK_REASONS)
        or (
            schema == BLOCKED_SCHEMA
            and (value.get("reason") == "source-replacement-after-finalize")
            != (finalized_digest is not None)
        )
    ):
        raise QuarantineTransactionError(
            f"{stage} quarantine transaction chain is invalid"
        )


def _validate_finalized(
    record: DurableRecord,
    transaction_id: str,
    intent_digest: str,
    applied_digest: str,
) -> None:
    value = record.value
    if (
        set(value) != _FINALIZED_FIELDS
        or record.name != _record_name(transaction_id, "finalized")
        or value.get("schema") != FINALIZED_SCHEMA
        or value.get("transaction_id") != transaction_id
        or value.get("intent_digest") != intent_digest
        or value.get("applied_digest") != applied_digest
        or not _is_digest(value.get("fact_receipt_sha256"))
        or not _valid_process_identity(value.get("source_process_identity"))
    ):
        raise QuarantineTransactionError(
            "finalized quarantine transaction chain is invalid"
        )


def _mark_blocked(
    root: Path,
    expected_identity: tuple[int, int],
    transaction_id: str,
    *,
    intent_digest: str,
    applied_digest: str | None,
    finalized_digest: str | None,
    reason: str,
) -> None:
    _write_record(
        root,
        expected_identity,
        transaction_id,
        "blocked",
        {
            "schema": BLOCKED_SCHEMA,
            "transaction_id": transaction_id,
            "intent_digest": intent_digest,
            "applied_digest": applied_digest,
            "finalized_digest": finalized_digest,
            "reason": reason,
        },
    )


def _exists(directory: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise QuarantineTransactionError(
            f"cannot inspect quarantine transaction artifact: {name}"
        ) from exc
    return True


def _is_same_append_only_journal(
    current: QuarantinedJournal, snapshot: QuarantinedJournal
) -> bool:
    return (
        current.journal == snapshot.journal
        and current.device == snapshot.device
        and current.inode == snapshot.inode
        and current.raw.startswith(snapshot.raw)
    )


def reconcile_quarantine_transactions(
    source_root: Path,
    quarantine_root: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_quarantine_identity: tuple[int, int],
    max_bytes: int,
    lease: QuarantineTransactionLease | None = None,
) -> ReconciliationResult:
    """Restore every unfinalized crash remnant or fail closed on ambiguity."""
    owned = lease is None
    active_lease = lease or acquire_quarantine_transaction_lease(
        source_root, expected_source_identity
    )
    try:
        _require_lease(active_lease, source_root, expected_source_identity)
        return _reconcile_quarantine_transactions_locked(
            source_root,
            quarantine_root,
            expected_source_identity=expected_source_identity,
            expected_quarantine_identity=expected_quarantine_identity,
            max_bytes=max_bytes,
        )
    finally:
        if owned:
            active_lease.close()


def _reconcile_quarantine_transactions_locked(
    source_root: Path,
    quarantine_root: Path,
    *,
    expected_source_identity: tuple[int, int],
    expected_quarantine_identity: tuple[int, int],
    max_bytes: int,
) -> ReconciliationResult:
    """Reconcile while the caller holds the root's transaction lease."""
    _source_path, source_directory = _open_journal_root(
        source_root, expected_source_identity
    )
    try:
        _quarantine_path, quarantine_directory = _open_journal_root(
            quarantine_root, expected_quarantine_identity
        )
    except BaseException:
        os.close(source_directory)
        raise
    try:
        source_metadata = os.fstat(source_directory)
        quarantine_metadata = os.fstat(quarantine_directory)
        if (
            source_metadata.st_dev != quarantine_metadata.st_dev
            or expected_source_identity == expected_quarantine_identity
        ):
            raise QuarantineTransactionError(
                "quarantine recovery requires distinct roots on one filesystem"
            )
        source_temporary_names = [
            name
            for name in os.listdir(source_directory)
            if name.startswith(".ecpa-fence-temp-")
        ]
        for name in source_temporary_names:
            if _FENCE_TEMP_PATTERN.fullmatch(name) is None:
                raise QuarantineTransactionError(
                    "source fence temporary name is malformed"
                )
            try:
                metadata = os.stat(name, dir_fd=source_directory, follow_symlinks=False)
            except OSError as exc:
                raise QuarantineTransactionError(
                    "cannot inspect incomplete source fence"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise QuarantineTransactionError("incomplete source fence is unsafe")
            try:
                os.unlink(name, dir_fd=source_directory)
            except OSError as exc:
                raise QuarantineTransactionError(
                    "cannot remove incomplete source fence"
                ) from exc
        if source_temporary_names:
            os.fsync(source_directory)
        directory_names = sorted(os.listdir(quarantine_directory))
        temporary_names = [
            name for name in directory_names if name.startswith(".ecpa-transaction-")
        ]
        for name in temporary_names:
            if _TRANSACTION_TEMP_PATTERN.fullmatch(name) is None:
                raise QuarantineTransactionError(
                    "transaction temporary name is malformed"
                )
            try:
                metadata = os.stat(
                    name, dir_fd=quarantine_directory, follow_symlinks=False
                )
            except OSError as exc:
                raise QuarantineTransactionError(
                    "cannot inspect incomplete transaction record"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise QuarantineTransactionError(
                    "incomplete transaction record is unsafe"
                )
            try:
                os.unlink(name, dir_fd=quarantine_directory)
            except OSError as exc:
                raise QuarantineTransactionError(
                    "cannot remove incomplete transaction record"
                ) from exc
        if temporary_names:
            os.fsync(quarantine_directory)
        directory_names = [
            name for name in directory_names if name not in set(temporary_names)
        ]
        transaction_names = [
            name
            for name in directory_names
            if name.startswith("ecpa-") and name.endswith(".json")
        ]
        valid_suffixes = tuple(
            f".{stage}.json"
            for stage in ("intent", "applied", "finalized", "restored", "blocked")
        )
        if any(not name.endswith(valid_suffixes) for name in transaction_names):
            raise QuarantineTransactionError(
                "quarantine transaction directory has an unknown record"
            )
        intent_names = [
            name for name in transaction_names if name.endswith(".intent.json")
        ]
        intent_name_set = set(intent_names)
        for name in transaction_names:
            transaction_id = name.removeprefix("ecpa-").split(".", 1)[0]
            if _record_name(transaction_id, "intent") not in intent_name_set:
                raise QuarantineTransactionError(
                    "quarantine transaction directory has an orphan record"
                )
        restored: list[str] = []
        finalized: list[str] = []
        for name in intent_names:
            transaction_id = name.removeprefix("ecpa-").removesuffix(".intent.json")
            intent = _read_record_from_directory(
                quarantine_directory, name, required=True
            )
            assert intent is not None
            snapshot = _intent_snapshot(intent, transaction_id)
            source_identity = intent.value.get("source_directory")
            quarantine_identity = intent.value.get("quarantine_directory")
            if source_identity != _directory_value(
                expected_source_identity
            ) or quarantine_identity != _directory_value(expected_quarantine_identity):
                raise QuarantineTransactionError(
                    "quarantine transaction directory identity differs"
                )
            applied = _read_record_from_directory(
                quarantine_directory,
                _record_name(transaction_id, "applied"),
                required=False,
            )
            applied_digest = applied.digest if applied is not None else None
            if applied is not None:
                _validate_applied(applied, transaction_id, intent, snapshot)
            finalized_record = _read_record_from_directory(
                quarantine_directory,
                _record_name(transaction_id, "finalized"),
                required=False,
            )
            restored_record = _read_record_from_directory(
                quarantine_directory,
                _record_name(transaction_id, "restored"),
                required=False,
            )
            blocked_record = _read_record_from_directory(
                quarantine_directory,
                _record_name(transaction_id, "blocked"),
                required=False,
            )
            if restored_record is not None and (
                finalized_record is not None or blocked_record is not None
            ):
                raise QuarantineTransactionError(
                    "quarantine transaction has conflicting terminal records"
                )
            if blocked_record is not None:
                finalized_digest = None
                if finalized_record is not None:
                    if applied is None:
                        raise QuarantineTransactionError(
                            "blocked finalized transaction has no applied record"
                        )
                    _validate_finalized(
                        finalized_record,
                        transaction_id,
                        intent.digest,
                        applied.digest,
                    )
                    finalized_digest = finalized_record.digest
                _validate_terminal(
                    blocked_record,
                    transaction_id,
                    schema=BLOCKED_SCHEMA,
                    stage="blocked",
                    intent_digest=intent.digest,
                    applied_digest=applied_digest,
                    finalized_digest=finalized_digest,
                )
                raise QuarantineTransactionError(
                    "quarantine transaction requires operator resolution: "
                    f"{transaction_id}"
                )
            if finalized_record is not None:
                if applied is None:
                    raise QuarantineTransactionError(
                        "finalized quarantine transaction chain is invalid"
                    )
                _validate_finalized(
                    finalized_record,
                    transaction_id,
                    intent.digest,
                    applied.digest,
                )
                try:
                    retained = snapshot_journal(
                        quarantine_root,
                        snapshot.journal,
                        expected_root_identity=expected_quarantine_identity,
                        max_bytes=max_bytes,
                    )
                except HostEventSinkError as exc:
                    raise QuarantineTransactionError(
                        "finalized quarantine artifact is missing or unsafe"
                    ) from exc
                if retained != snapshot:
                    raise QuarantineTransactionError(
                        "finalized quarantine artifact differs from intent"
                    )
                _read_source_fence(
                    source_directory,
                    transaction_id,
                    intent.digest,
                    snapshot,
                    required=True,
                )
                if _exists(source_directory, snapshot.journal):
                    _mark_blocked(
                        quarantine_root,
                        expected_quarantine_identity,
                        transaction_id,
                        intent_digest=intent.digest,
                        applied_digest=applied.digest,
                        finalized_digest=finalized_record.digest,
                        reason="source-replacement-after-finalize",
                    )
                    raise QuarantineTransactionError(
                        "finalized quarantine has a replacement source journal"
                    )
                finalized.append(transaction_id)
                continue
            if restored_record is not None:
                _validate_terminal(
                    restored_record,
                    transaction_id,
                    schema=RESTORED_SCHEMA,
                    stage="restored",
                    intent_digest=intent.digest,
                    applied_digest=applied_digest,
                    finalized_digest=None,
                )
                if (
                    _read_source_fence(
                        source_directory,
                        transaction_id,
                        intent.digest,
                        snapshot,
                        required=False,
                    )
                    is not None
                ):
                    raise QuarantineTransactionError(
                        "restored transaction still has a source journal fence"
                    )
                if _exists(quarantine_directory, snapshot.journal):
                    raise QuarantineTransactionError(
                        "restored quarantine transaction still has quarantined bytes"
                    )
                try:
                    restored_snapshot = snapshot_journal(
                        source_root,
                        snapshot.journal,
                        expected_root_identity=expected_source_identity,
                        max_bytes=max_bytes,
                    )
                except HostEventSinkError as exc:
                    raise QuarantineTransactionError(
                        "restored quarantine source is missing or unsafe"
                    ) from exc
                if not _is_same_append_only_journal(restored_snapshot, snapshot):
                    raise QuarantineTransactionError(
                        "restored quarantine source is not an append-only continuation"
                    )
                restored.append(transaction_id)
                continue
            source_exists = _exists(source_directory, snapshot.journal)
            quarantine_exists = _exists(quarantine_directory, snapshot.journal)
            if source_exists and quarantine_exists:
                _mark_blocked(
                    quarantine_root,
                    expected_quarantine_identity,
                    transaction_id,
                    intent_digest=intent.digest,
                    applied_digest=applied_digest,
                    finalized_digest=None,
                    reason="source-replacement-collision",
                )
                raise QuarantineTransactionError(
                    "quarantine recovery refuses to overwrite replacement evidence"
                )
            if quarantine_exists:
                _read_source_fence(
                    source_directory,
                    transaction_id,
                    intent.digest,
                    snapshot,
                    required=True,
                )
                try:
                    restore_quarantined_journal(
                        source_root,
                        quarantine_root,
                        snapshot,
                        expected_root_identity=expected_source_identity,
                        expected_quarantine_identity=expected_quarantine_identity,
                        max_bytes=max_bytes,
                    )
                except HostEventSinkError as exc:
                    _mark_blocked(
                        quarantine_root,
                        expected_quarantine_identity,
                        transaction_id,
                        intent_digest=intent.digest,
                        applied_digest=applied_digest,
                        finalized_digest=None,
                        reason="restore-verification-failed",
                    )
                    raise QuarantineTransactionError(
                        "quarantine crash recovery failed closed"
                    ) from exc
                reason = "restored-after-applied" if applied else "restored-after-move"
            elif source_exists:
                current = snapshot_journal(
                    source_root,
                    snapshot.journal,
                    expected_root_identity=expected_source_identity,
                    max_bytes=max_bytes,
                )
                if not _is_same_append_only_journal(current, snapshot):
                    _mark_blocked(
                        quarantine_root,
                        expected_quarantine_identity,
                        transaction_id,
                        intent_digest=intent.digest,
                        applied_digest=applied_digest,
                        finalized_digest=None,
                        reason="source-changed-before-recovery",
                    )
                    raise QuarantineTransactionError(
                        "quarantine intent source changed before recovery"
                    )
                reason = "no-move-observed"
            else:
                _mark_blocked(
                    quarantine_root,
                    expected_quarantine_identity,
                    transaction_id,
                    intent_digest=intent.digest,
                    applied_digest=applied_digest,
                    finalized_digest=None,
                    reason="journal-missing-from-both-roots",
                )
                raise QuarantineTransactionError(
                    "quarantine journal is missing from both roots"
                )
            _remove_source_fence(
                source_directory,
                transaction_id,
                intent.digest,
                snapshot,
            )
            mark_quarantine_restored(
                quarantine_root,
                expected_quarantine_identity,
                transaction_id,
                intent_digest=intent.digest,
                applied_digest=applied_digest,
                reason=reason,
            )
            restored.append(transaction_id)
        return ReconciliationResult(tuple(restored), tuple(finalized))
    finally:
        os.close(source_directory)
        os.close(quarantine_directory)
