import json
import os
import signal

import pytest

import vllm_hust_ext.quarantine_transaction as transaction_module
from vllm_hust_ext.ecpa_model import canonical_bytes
from vllm_hust_ext.host_event_sink import quarantine_journal, snapshot_journal
from vllm_hust_ext.quarantine_transaction import (
    QuarantineTransactionError,
    acquire_quarantine_transaction_lease,
    finalize_quarantine_transaction,
    install_quarantine_source_fence,
    mark_quarantine_applied,
    prepare_quarantine_transaction,
    quarantine_transaction_id,
    read_quarantine_record,
    reconcile_quarantine_transactions,
)

MAX_BYTES = 4096


def _roots(tmp_path):
    source = tmp_path / "events"
    quarantine = tmp_path / "quarantine"
    source.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    quarantine_identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)
    return source, quarantine, source_identity, quarantine_identity


def _prepared(tmp_path):
    source, quarantine, source_identity, quarantine_identity = _roots(tmp_path)
    journal = source / "worker.jsonl"
    journal.write_bytes(b'{"event":"invoked"}\n')
    snapshot = snapshot_journal(
        source,
        journal.name,
        expected_root_identity=source_identity,
        max_bytes=MAX_BYTES,
    )
    binding = {
        "schema": "ecpa-quarantine-transaction-binding/v1",
        "challenge": "challenge",
    }
    transaction_id = quarantine_transaction_id(binding)
    intent = prepare_quarantine_transaction(
        quarantine,
        quarantine_identity,
        transaction_id,
        binding=binding,
        source_identity=source_identity,
        snapshot=snapshot,
    )
    install_quarantine_source_fence(
        source,
        source_identity,
        transaction_id,
        intent_digest=intent.digest,
        snapshot=snapshot,
    )
    return (
        source,
        quarantine,
        source_identity,
        quarantine_identity,
        snapshot,
        transaction_id,
        intent,
    )


def _move(prepared):
    source, quarantine, source_identity, quarantine_identity, snapshot, *_ = prepared
    return quarantine_journal(
        source,
        quarantine,
        snapshot.journal,
        expected_root_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=MAX_BYTES,
        expected_journal=snapshot,
    )


def _reconcile(prepared):
    source, quarantine, source_identity, quarantine_identity, *_ = prepared
    return reconcile_quarantine_transactions(
        source,
        quarantine,
        expected_source_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=MAX_BYTES,
    )


def test_transaction_lease_serializes_sources_and_releases_on_sigkill(tmp_path):
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir(mode=0o700)
    identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)
        child_lease = acquire_quarantine_transaction_lease(quarantine, identity)
        os.write(ready_write, b"1")
        os.close(ready_write)
        signal.pause()
        child_lease.close()
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"1"
    os.close(ready_read)
    with pytest.raises(QuarantineTransactionError, match="another.*active"):
        acquire_quarantine_transaction_lease(quarantine, identity)
    os.kill(pid, signal.SIGKILL)
    _waited, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status)

    lease = acquire_quarantine_transaction_lease(quarantine, identity)
    lease.close()


def test_sigkill_during_intent_publish_discards_unpublished_temp(tmp_path):
    source, quarantine, source_identity, quarantine_identity = _roots(tmp_path)
    journal = source / "worker.jsonl"
    journal.write_bytes(b'{"event":"invoked"}\n')
    snapshot = snapshot_journal(
        source,
        journal.name,
        expected_root_identity=source_identity,
        max_bytes=MAX_BYTES,
    )
    binding = {"schema": "ecpa-quarantine-transaction-binding/v1", "challenge": "x"}
    transaction_id = quarantine_transaction_id(binding)
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)

        def stop_before_publish(*args, **kwargs):
            os.write(ready_write, b"1")
            os.close(ready_write)
            signal.pause()

        transaction_module._rename_noreplace = stop_before_publish
        prepare_quarantine_transaction(
            quarantine,
            quarantine_identity,
            transaction_id,
            binding=binding,
            source_identity=source_identity,
            snapshot=snapshot,
        )
        raise AssertionError("publish hook unexpectedly returned")
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"1"
    os.close(ready_read)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)

    result = reconcile_quarantine_transactions(
        source,
        quarantine,
        expected_source_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=MAX_BYTES,
    )
    assert result == transaction_module.ReconciliationResult((), ())
    assert not list(quarantine.glob(".ecpa-transaction-*.tmp"))
    assert journal.read_bytes() == snapshot.raw


@pytest.mark.parametrize(
    ("location", "name", "message"),
    [
        ("source", ".ecpa-fence-temp-not-generated.tmp", "name is malformed"),
        (
            "quarantine",
            ".ecpa-transaction-not-generated.tmp",
            "name is malformed",
        ),
    ],
)
def test_reconcile_preserves_malformed_reserved_temporary(
    tmp_path, location, name, message
):
    source, quarantine, source_identity, quarantine_identity = _roots(tmp_path)
    root = source if location == "source" else quarantine
    candidate = root / name
    candidate.write_bytes(b"preserve\n")
    candidate.chmod(0o600)

    with pytest.raises(QuarantineTransactionError, match=message):
        reconcile_quarantine_transactions(
            source,
            quarantine,
            expected_source_identity=source_identity,
            expected_quarantine_identity=quarantine_identity,
            max_bytes=MAX_BYTES,
        )
    assert candidate.read_bytes() == b"preserve\n"


def test_reconcile_restores_move_without_applied_record(tmp_path):
    prepared = _prepared(tmp_path)
    _move(prepared)
    result = _reconcile(prepared)
    source, quarantine, *_rest, snapshot, transaction_id, _intent = prepared

    assert result.restored == (transaction_id,)
    assert (source / snapshot.journal).read_bytes() == snapshot.raw
    assert not (quarantine / snapshot.journal).exists()
    assert _reconcile(prepared) == result

    with (source / snapshot.journal).open("ab") as stream:
        stream.write(b'{"event":"later"}\n')
        stream.flush()
        os.fsync(stream.fileno())
    assert _reconcile(prepared) == result


def test_reconcile_closes_intent_when_source_was_never_moved(tmp_path):
    prepared = _prepared(tmp_path)
    result = _reconcile(prepared)

    assert result.restored == (prepared[5],)
    assert (prepared[0] / prepared[4].journal).read_bytes() == prepared[4].raw
    assert not (prepared[1] / prepared[4].journal).exists()


def test_reconcile_restores_applied_transaction(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    *_prefix, quarantine_identity, _snapshot, transaction_id, intent = prepared
    quarantine = prepared[1]
    mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )

    result = _reconcile(prepared)
    assert result.restored == (transaction_id,)
    assert _reconcile(prepared) == result


def test_finalized_transaction_stays_quarantined_and_is_idempotent(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    (
        source,
        quarantine,
        _source_identity,
        quarantine_identity,
        snapshot,
        transaction_id,
        intent,
    ) = prepared
    applied = mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )
    identity = {
        "pid": os.getpid(),
        "start_ticks": 1,
        "argv": ["source"],
        "executable_device": 1,
        "executable_inode": 1,
    }
    finalized = finalize_quarantine_transaction(
        quarantine,
        quarantine_identity,
        transaction_id,
        source_root=source,
        source_identity=prepared[2],
        applied_digest=applied.digest,
        fact_receipt_sha256="sha256:" + "1" * 64,
        source_process_identity=identity,
    )
    repeated = finalize_quarantine_transaction(
        quarantine,
        quarantine_identity,
        transaction_id,
        source_root=source,
        source_identity=prepared[2],
        applied_digest=applied.digest,
        fact_receipt_sha256="sha256:" + "1" * 64,
        source_process_identity=identity,
    )

    assert repeated.raw == finalized.raw
    assert _reconcile(prepared).finalized == (transaction_id,)
    assert not (source / snapshot.journal).exists()
    assert (quarantine / snapshot.journal).read_bytes() == snapshot.raw


def test_finalized_record_survives_runner_sigkill(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    quarantine, quarantine_identity, transaction_id, intent = (
        prepared[1],
        prepared[3],
        prepared[5],
        prepared[6],
    )
    applied = mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )
    pid = os.fork()
    if pid == 0:
        finalize_quarantine_transaction(
            quarantine,
            quarantine_identity,
            transaction_id,
            source_root=prepared[0],
            source_identity=prepared[2],
            applied_digest=applied.digest,
            fact_receipt_sha256="sha256:" + "1" * 64,
            source_process_identity={
                "pid": os.getpid(),
                "start_ticks": 1,
                "argv": ["runner"],
                "executable_device": 1,
                "executable_inode": 1,
            },
        )
        os.kill(os.getpid(), signal.SIGKILL)
    _waited, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

    assert _reconcile(prepared).finalized == (transaction_id,)


def test_finalized_replacement_collision_becomes_explicitly_blocked(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    (
        source,
        quarantine,
        source_identity,
        quarantine_identity,
        snapshot,
        transaction_id,
        intent,
    ) = prepared
    applied = mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )
    finalize_quarantine_transaction(
        quarantine,
        quarantine_identity,
        transaction_id,
        source_root=source,
        source_identity=source_identity,
        applied_digest=applied.digest,
        fact_receipt_sha256="sha256:" + "1" * 64,
        source_process_identity={
            "pid": os.getpid(),
            "start_ticks": 1,
            "argv": ["runner"],
            "executable_device": 1,
            "executable_inode": 1,
        },
    )
    replacement = b'{"event":"replacement"}\n'
    (source / snapshot.journal).write_bytes(replacement)

    with pytest.raises(QuarantineTransactionError, match="replacement source"):
        _reconcile(prepared)
    assert (source / snapshot.journal).read_bytes() == replacement
    assert (quarantine / snapshot.journal).read_bytes() == snapshot.raw
    assert (
        read_quarantine_record(
            quarantine, quarantine_identity, transaction_id, "blocked"
        )
        is not None
    )
    with pytest.raises(QuarantineTransactionError, match="operator resolution"):
        _reconcile(prepared)


def test_runner_refuses_replacement_created_before_finalization(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    (
        source,
        quarantine,
        source_identity,
        quarantine_identity,
        snapshot,
        transaction_id,
        intent,
    ) = prepared
    applied = mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )
    replacement = b'{"event":"replacement"}\n'
    (source / snapshot.journal).write_bytes(replacement)

    with pytest.raises(QuarantineTransactionError, match="reappeared before"):
        finalize_quarantine_transaction(
            quarantine,
            quarantine_identity,
            transaction_id,
            source_root=source,
            source_identity=source_identity,
            applied_digest=applied.digest,
            fact_receipt_sha256="sha256:" + "1" * 64,
            source_process_identity={
                "pid": os.getpid(),
                "start_ticks": 1,
                "argv": ["runner"],
                "executable_device": 1,
                "executable_inode": 1,
            },
        )
    assert (source / snapshot.journal).read_bytes() == replacement
    assert (quarantine / snapshot.journal).read_bytes() == snapshot.raw


@pytest.mark.parametrize("stage", ["applied", "finalized"])
def test_sigkill_during_stage_write_recovers_from_unpublished_temp(tmp_path, stage):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    (
        source,
        quarantine,
        source_identity,
        quarantine_identity,
        _snapshot,
        transaction_id,
        intent,
    ) = prepared
    applied = None
    if stage == "finalized":
        applied = mark_quarantine_applied(
            quarantine,
            quarantine_identity,
            transaction_id,
            intent_digest=intent.digest,
            quarantined=quarantined,
        )
    ready_read, ready_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_read)

        def stop_before_publish(*args, **kwargs):
            os.write(ready_write, b"1")
            os.close(ready_write)
            signal.pause()

        transaction_module._rename_noreplace = stop_before_publish
        if stage == "applied":
            mark_quarantine_applied(
                quarantine,
                quarantine_identity,
                transaction_id,
                intent_digest=intent.digest,
                quarantined=quarantined,
            )
        else:
            assert applied is not None
            finalize_quarantine_transaction(
                quarantine,
                quarantine_identity,
                transaction_id,
                source_root=source,
                source_identity=source_identity,
                applied_digest=applied.digest,
                fact_receipt_sha256="sha256:" + "1" * 64,
                source_process_identity={
                    "pid": os.getpid(),
                    "start_ticks": 1,
                    "argv": ["runner"],
                    "executable_device": 1,
                    "executable_inode": 1,
                },
            )
        raise AssertionError("publish hook unexpectedly returned")
    os.close(ready_write)
    assert os.read(ready_read, 1) == b"1"
    os.close(ready_read)
    os.kill(pid, signal.SIGKILL)
    _waited, status = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(status)
    assert list(quarantine.glob(".ecpa-transaction-*.tmp"))

    result = _reconcile(prepared)
    assert result.restored == (transaction_id,)
    assert not list(quarantine.glob(".ecpa-transaction-*.tmp"))


def test_reconcile_collision_preserves_both_and_stays_blocked(tmp_path):
    prepared = _prepared(tmp_path)
    _move(prepared)
    source, quarantine, *_rest, snapshot, transaction_id, _intent = prepared
    replacement = b'{"event":"replacement"}\n'
    (source / snapshot.journal).write_bytes(replacement)

    with pytest.raises(QuarantineTransactionError, match="refuses to overwrite"):
        _reconcile(prepared)
    assert (source / snapshot.journal).read_bytes() == replacement
    assert (quarantine / snapshot.journal).read_bytes() == snapshot.raw
    with pytest.raises(QuarantineTransactionError, match="operator resolution"):
        _reconcile(prepared)
    assert (
        read_quarantine_record(quarantine, prepared[3], transaction_id, "blocked")
        is not None
    )


@pytest.mark.parametrize("after_applied", [False, True])
def test_reconcile_after_sigkill_at_move_boundaries(tmp_path, after_applied):
    prepared = _prepared(tmp_path)
    pid = os.fork()
    if pid == 0:
        quarantined = _move(prepared)
        if after_applied:
            quarantine = prepared[1]
            quarantine_identity = prepared[3]
            transaction_id = prepared[5]
            intent = prepared[6]
            mark_quarantine_applied(
                quarantine,
                quarantine_identity,
                transaction_id,
                intent_digest=intent.digest,
                quarantined=quarantined,
            )
        os.kill(os.getpid(), signal.SIGKILL)
    waited, status = os.waitpid(pid, 0)
    assert waited == pid
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL

    result = _reconcile(prepared)
    assert result.restored == (prepared[5],)
    assert (prepared[0] / prepared[4].journal).read_bytes() == prepared[4].raw


def test_corrupt_applied_record_fails_closed(tmp_path):
    prepared = _prepared(tmp_path)
    quarantined = _move(prepared)
    quarantine, quarantine_identity, transaction_id, intent = (
        prepared[1],
        prepared[3],
        prepared[5],
        prepared[6],
    )
    applied = mark_quarantine_applied(
        quarantine,
        quarantine_identity,
        transaction_id,
        intent_digest=intent.digest,
        quarantined=quarantined,
    )
    value = dict(applied.value)
    value["journal_inode"] += 1
    (quarantine / applied.name).write_bytes(canonical_bytes(value) + b"\n")

    with pytest.raises(QuarantineTransactionError, match="applied record"):
        _reconcile(prepared)


def test_noncanonical_record_fails_closed(tmp_path):
    prepared = _prepared(tmp_path)
    quarantine, transaction_id = prepared[1], prepared[5]
    intent_path = quarantine / f"ecpa-{transaction_id}.intent.json"
    value = json.loads(intent_path.read_bytes())
    intent_path.write_text(json.dumps(value, indent=2) + "\n")

    with pytest.raises(QuarantineTransactionError, match="not canonical"):
        _reconcile(prepared)
