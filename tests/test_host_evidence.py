import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft7Validator

import vllm_hust_ext.host_event_sink as sink
from vllm_hust_ext.attestation import (
    AttestationError,
    AttestationErrorCode,
    SignedAttestationVerifier,
    TrustEntry,
    TrustStore,
    sign,
)
from vllm_hust_ext.durable_coordinator import (
    ActivationCoordinator,
    FakeExternalServiceAdapter,
    FakeHostAdapter,
    FakeTrafficGate,
    SQLiteActivationStore,
)
from vllm_hust_ext.ecpa_model import (
    Attestation,
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
)
from vllm_hust_ext.host_event_sink import (
    DEVICE_ENV,
    INODE_ENV,
    HostEventSinkError,
    append_event,
    canonical_event,
    quarantine_journal,
    read_events,
    restore_quarantined_journal,
)
from vllm_hust_ext.host_evidence import (
    EntryPointBinding,
    HostReceipt,
    parse_host_event,
    translate_invocation,
)

PLUGIN = PluginIdentity("org.vllm-hust", "demo", "1", "a" * 64)
OBLIGATION = EvidenceObligation("worker-invoked", "worker", "invoked", (0,))
PLAN = Plan(
    (PLUGIN,),
    HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
    (),
    (OBLIGATION,),
    PredecessorSnapshot(0, None, {}),
)
BINDING = EntryPointBinding(
    "vllm.general_plugins",
    "demo",
    "demo.plugin:register",
    PLUGIN.id,
    OBLIGATION.obligation_id,
)


def computed_event_id(value):
    process = value["process"]
    entry = value["entry_point"]
    material_items = [
        process["host"],
        process["pid"],
        process["start_identity"],
        process["process_epoch"],
        process["role"],
        process["ordinal"],
        entry["group"],
        entry["name"],
        entry["value"],
        value["event"],
        value["detail"],
        value["occurrence_id"],
        value["plan_id"],
        value["launch_id"],
        value["observation_kind"],
        value["controller_instance_id"],
        value["delivery_attempt"],
        value["observed_at_ns"],
    ]
    if "assignment_source" in process:
        material_items.append(process["assignment_source"])
    material = json.dumps(
        material_items,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()


def raw_event(**changes):
    value = {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "event-1",
        "event": "invoked",
        "observation_kind": "loader_lifecycle",
        "entry_point": {
            "group": BINDING.group,
            "name": BINDING.name,
            "value": BINDING.value,
        },
        "process": {
            "host": "host-a",
            "role": "worker",
            "ordinal": 0,
            "pid": 4242,
            "start_identity": "pid:4242:start_ticks:9001",
            "process_epoch": 7,
            "assignment_source": "host",
        },
        "observed_at_ns": 1_800_000_000_000_000_000,
        "delivery_attempt": 1,
        "plan_id": PLAN.plan_id,
        "launch_id": "launch-1",
        "binding_status": "bound",
        "occurrence_id": None,
        "controller_instance_id": None,
        "invocation_seq": None,
        "dispatch_id": None,
        "plugin_id": None,
        "artifact_digest": None,
        "identity_status": "launch-bound",
        "detail": None,
    }
    value.update(changes)
    if "event_id" not in changes:
        value["event_id"] = computed_event_id(value)
    return json.dumps(value, separators=(",", ":")).encode()


def translate(raw):
    return translate_invocation(
        raw,
        plan=PLAN,
        launch_id="launch-1",
        process_epoch=7,
        binding=BINDING,
        issuer="urn:ecpa:issuer:host-a",
        kid="host-key-1",
        challenge_nonce="nonce-1",
        issued_at=1_800_000_001,
        expires_at=1_800_000_060,
    )


def scheduler_event(**changes):
    value = json.loads(raw_event())
    value.update(
        {
            "observation_kind": "scheduler_dispatch",
            "entry_point": {
                "group": "vllm.preemption_policy",
                "name": BINDING.name,
                "value": BINDING.value,
            },
            "occurrence_id": 1,
            "controller_instance_id": "controller-1",
            "invocation_seq": 1,
            "detail": "engine-core.scheduler:selected",
        }
    )
    material = json.dumps(
        [
            value["process"]["host"],
            value["process"]["start_identity"],
            value["process"]["process_epoch"],
            value["plan_id"],
            value["launch_id"],
            value["controller_instance_id"],
            value["occurrence_id"],
        ],
        separators=(",", ":"),
    ).encode()
    value["dispatch_id"] = hashlib.sha256(material).hexdigest()
    value.update(changes)
    if "event_id" not in changes:
        value["event_id"] = computed_event_id(value)
    return json.dumps(value, separators=(",", ":")).encode()


def test_exact_raw_bytes_are_preserved_and_bound_to_plan():
    raw = raw_event()
    receipt = translate(raw)
    assert receipt.raw == raw
    assert receipt.statement.plugin_id == PLUGIN.id
    assert receipt.statement.artifact_digest == "sha256:" + "a" * 64
    assert receipt.statement.process.epoch == 7
    assert receipt.statement.evidence_digest == (
        "sha256:" + hashlib.sha256(raw).hexdigest()
    )


@pytest.mark.parametrize("assignment_source", [None, "environment"])
def test_non_host_assigned_identity_is_auditable_but_not_formal(assignment_source):
    value = json.loads(raw_event())
    if assignment_source is None:
        value["process"].pop("assignment_source")
    else:
        value["process"]["assignment_source"] = assignment_source
    value["event_id"] = computed_event_id(value)
    raw = json.dumps(value, separators=(",", ":")).encode()
    parsed_source = parse_host_event(raw)["process"].get("assignment_source")
    assert parsed_source == assignment_source
    with pytest.raises(AttestationError, match="host-assigned") as caught:
        translate(raw)
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


@pytest.mark.parametrize("invalid_source", [None, "plugin-self-report"])
def test_assignment_source_schema_and_parser_reject_invalid_values(invalid_source):
    value = json.loads(raw_event())
    value["process"]["assignment_source"] = invalid_source
    schema = json.loads(
        open("spec/0.1/host-plugin-evidence.schema.json").read()  # noqa: SIM115
    )
    assert list(Draft7Validator(schema).iter_errors(value))
    with pytest.raises(AttestationError, match="assignment_source"):
        parse_host_event(json.dumps(value, separators=(",", ":")).encode())


def test_assignment_source_is_bound_into_event_id():
    value = json.loads(raw_event())
    original_event_id = value["event_id"]
    value["process"]["assignment_source"] = "environment"
    assert value["event_id"] == original_event_id
    with pytest.raises(AttestationError, match="event_id"):
        parse_host_event(json.dumps(value, separators=(",", ":")).encode())


def test_current_vllm_scheduler_dispatch_is_causally_validated():
    raw = scheduler_event()
    event = parse_host_event(raw)
    assert event["observation_kind"] == "scheduler_dispatch"
    scheduler_binding = replace(BINDING, group="vllm.preemption_policy")
    receipt = translate_invocation(
        raw,
        plan=PLAN,
        launch_id="launch-1",
        process_epoch=7,
        binding=scheduler_binding,
        issuer="urn:ecpa:issuer:host-a",
        kid="host-key-1",
        challenge_nonce="nonce-1",
        issued_at=1_800_000_001,
        expires_at=1_800_000_060,
    )
    assert receipt.statement.event == "invoked"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "0" * 64),
        ("dispatch_id", "0" * 64),
        ("invocation_seq", 2),
        ("occurrence_id", 2),
        ("binding_status", "unbound"),
    ],
)
def test_scheduler_dispatch_causal_mutations_are_rejected(field, value):
    with pytest.raises(AttestationError):
        parse_host_event(scheduler_event(**{field: value}))


def test_unbound_event_cannot_translate_to_invocation_evidence():
    value = json.loads(raw_event())
    value.update({"plan_id": None, "launch_id": None, "binding_status": "unbound"})
    value["event_id"] = computed_event_id(value)
    with pytest.raises(AttestationError, match="unbound"):
        translate(json.dumps(value, separators=(",", ":")).encode())


@pytest.mark.parametrize(
    "raw",
    [
        raw_event(event="resolved"),
        raw_event(plan_id="wrong-plan"),
        raw_event(launch_id="wrong-launch"),
        raw_event(
            process={
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "pid": 4242,
                "start_identity": "pid:4242:start_ticks:9001",
                "process_epoch": 8,
                "assignment_source": "host",
            }
        ),
    ],
)
def test_non_invocation_or_binding_mismatch_is_rejected(raw):
    with pytest.raises(AttestationError):
        translate(raw)


def test_strict_parser_rejects_duplicate_or_fabricated_identity():
    duplicate = raw_event().replace(
        b'"event":"invoked"',
        b'"event":"invoked","event":"resolved"',
    )
    with pytest.raises(AttestationError) as caught:
        parse_host_event(duplicate)
    assert caught.value.code is AttestationErrorCode.DUPLICATE_KEY

    value = json.loads(raw_event())
    value["artifact_digest"] = "sha256:" + "b" * 64
    with pytest.raises(AttestationError) as caught:
        parse_host_event(json.dumps(value).encode())
    assert caught.value.code is AttestationErrorCode.INVALID_STATEMENT


def test_binding_must_name_a_plugin_in_plan():
    missing = replace(BINDING, plugin_id="plugin:sha256:" + "f" * 64)
    with pytest.raises(AttestationError) as caught:
        translate_invocation(
            raw_event(),
            plan=PLAN,
            launch_id="launch-1",
            process_epoch=7,
            binding=missing,
            issuer="urn:ecpa:issuer:host-a",
            kid="host-key-1",
            challenge_nonce="nonce-1",
            issued_at=1_800_000_001,
            expires_at=1_800_000_060,
        )
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


def test_raw_event_is_not_a_signed_or_logical_attestation():
    receipt = translate(raw_event())
    assert isinstance(receipt, HostReceipt)
    assert not hasattr(receipt, "signature")
    assert not hasattr(receipt.statement, "nonce")


@pytest.mark.parametrize(
    ("mutation", "valid"),
    [
        ({"plan_id": None}, False),
        ({"launch_id": None}, False),
        ({"plan_id": None, "launch_id": None, "binding_status": "unbound"}, True),
        ({"detail": "load failure"}, True),
        ({"detail": None}, True),
        ({"detail": "有效"}, True),
        ({"plan_id": False}, False),
        ({"launch_id": 1}, False),
        ({"detail": {}}, False),
        ({"delivery_attempt": True}, False),
        ({"delivery_attempt": 0}, False),
        ({"observation_kind": "unknown"}, False),
        ({"binding_status": "unbound"}, False),
        ({"occurrence_id": 1}, False),
        ({"controller_instance_id": "controller"}, False),
        ({"invocation_seq": 1}, False),
        ({"dispatch_id": "0" * 64}, False),
        ({"extra": "field"}, False),
    ],
)
def test_schema_and_manual_parser_have_matching_boundary_semantics(mutation, valid):
    value = json.loads(raw_event())
    value.update(mutation)
    if "event_id" not in mutation:
        value["event_id"] = computed_event_id(value)
    schema = json.loads(
        open("spec/0.1/host-plugin-evidence.schema.json").read()  # noqa: SIM115
    )
    schema_valid = not list(Draft7Validator(schema).iter_errors(value))
    try:
        parse_host_event(json.dumps(value).encode())
        parser_valid = True
    except AttestationError:
        parser_valid = False
    assert schema_valid is valid
    assert parser_valid is valid


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"x","schema":"y"}',
        b"\xff",
        raw_event().replace(b'"demo"', b'"\\ud800"'),
        raw_event().replace(b'"detail":null', b'"detail":null,"nested":1'),
        raw_event().replace(b',"detail":null', b""),
        raw_event().replace(
            b'"value":"demo.plugin:register"', b'"value":"x","extra":1'
        ),
    ],
)
def test_strict_wire_rejects_duplicate_malformed_unicode_and_extra_fields(raw):
    with pytest.raises(AttestationError):
        parse_host_event(raw)


def test_unavailable_or_pid_mismatched_start_identity_is_rejected():
    for start_identity in ("unavailable", "pid:999:start_ticks:9001"):
        value = json.loads(raw_event())
        value["process"]["start_identity"] = start_identity
        with pytest.raises(AttestationError):
            parse_host_event(json.dumps(value).encode())


@pytest.mark.parametrize("field", ["group", "name", "value"])
def test_each_entry_point_binding_field_is_enforced(field):
    value = json.loads(raw_event())
    value["entry_point"][field] += "-tampered"
    value["event_id"] = computed_event_id(value)
    with pytest.raises(AttestationError) as caught:
        translate(json.dumps(value, separators=(",", ":")).encode())
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


def test_translate_sign_and_coordinator_chain_requires_detached_envelope(tmp_path):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    receipt = translate(raw_event())
    process = ProcessIdentity("host-a", "worker", 0, "pid:4242:start_ticks:9001", 7)
    logical = Attestation(
        PLAN.plan_id,
        "launch-1",
        process,
        OBLIGATION.obligation_id,
        "invoked",
        "nonce-1",
        1_800_000_001,
        1_800_000_060,
        PLUGIN.id,
        "host-runtime",
        receipt.statement.issuer,
        receipt.statement.kid,
        receipt.statement.observed_at,
        receipt.statement.evidence_digest,
        receipt.statement.artifact_digest,
    )
    trust = TrustStore(
        [
            TrustEntry(
                receipt.statement.issuer,
                receipt.statement.kid,
                key.public_key(),
                frozenset({"host-runtime"}),
            )
        ]
    )
    with pytest.raises(AttestationError, match="missing signed envelope"):
        SignedAttestationVerifier({}, trust).verify(logical, 1_800_000_001, PLAN)

    verifier = SignedAttestationVerifier(
        {"nonce-1": sign(receipt.statement, key)}, trust
    )
    store = SQLiteActivationStore(tmp_path / "host-evidence.db")
    coordinator = ActivationCoordinator(
        store,
        FakeHostAdapter((process,)),
        verifier,
        FakeTrafficGate(),
        FakeExternalServiceAdapter(),
        clock=lambda: 1_800_000_001,
    )
    plan_id = coordinator.plan(PLAN)
    coordinator.prepare(plan_id)
    coordinator.launch(plan_id, "launch-1")
    coordinator.observe(plan_id, logical, 1_800_000_001)
    assert coordinator.commit(plan_id, 0) == 1
    store.close()


def test_raw_byte_tamper_changes_digest_and_breaks_signed_binding():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    original = translate(raw_event())
    changed_raw = raw_event(detail="same semantics, different bytes")
    changed = translate(changed_raw)
    assert original.statement.evidence_digest != changed.statement.evidence_digest
    process = ProcessIdentity("host-a", "worker", 0, "pid:4242:start_ticks:9001", 7)
    logical = Attestation(
        PLAN.plan_id,
        "launch-1",
        process,
        OBLIGATION.obligation_id,
        "invoked",
        "nonce-1",
        1_800_000_001,
        1_800_000_060,
        PLUGIN.id,
        "host-runtime",
        original.statement.issuer,
        original.statement.kid,
        original.statement.observed_at,
        changed.statement.evidence_digest,
        original.statement.artifact_digest,
    )
    trust = TrustStore(
        [
            TrustEntry(
                original.statement.issuer,
                original.statement.kid,
                key.public_key(),
                frozenset({"host-runtime"}),
            )
        ]
    )
    verifier = SignedAttestationVerifier(
        {"nonce-1": sign(original.statement, key)}, trust
    )
    with pytest.raises(AttestationError) as caught:
        verifier.verify(logical, 1_800_000_001, PLAN)
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


def test_deployment_sink_preserves_canonical_exact_bytes(tmp_path, monkeypatch):
    journal = tmp_path.resolve()
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    first = json.loads(raw_event())
    second = json.loads(
        raw_event(delivery_attempt=2, observed_at_ns=1_800_000_000_000_000_001)
    )
    append_event(first)
    path = next(journal.glob("*.jsonl"))
    path.chmod(0o644)
    append_event(second)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    records = read_events(journal)
    assert [record.raw for record in records] == [
        canonical_event(first),
        canonical_event(second),
    ]
    assert len({record.journal for record in records}) == 1
    assert [record.line_number for record in records] == [1, 2]


def test_quarantine_atomically_retains_exact_journal(tmp_path, monkeypatch):
    journal = (tmp_path / "events").resolve()
    quarantine = (tmp_path / "quarantine").resolve()
    journal.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    event = json.loads(raw_event())
    append_event(event)
    path = next(journal.glob("*.jsonl"))
    raw = path.read_bytes()
    source_identity = (journal.stat().st_dev, journal.stat().st_ino)
    quarantine_identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)

    retained = quarantine_journal(
        journal,
        quarantine,
        path.name,
        expected_root_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=len(raw),
    )

    assert not path.exists()
    quarantined_path = quarantine / path.name
    assert quarantined_path.read_bytes() == raw == retained.raw
    assert (retained.device, retained.inode) == (
        quarantined_path.stat().st_dev,
        quarantined_path.stat().st_ino,
    )
    assert read_events(quarantine, quarantine_identity)[0].event == event


def test_quarantine_collision_fails_without_moving_source(tmp_path, monkeypatch):
    journal = (tmp_path / "events").resolve()
    quarantine = (tmp_path / "quarantine").resolve()
    journal.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    append_event(json.loads(raw_event()))
    path = next(journal.glob("*.jsonl"))
    raw = path.read_bytes()
    (quarantine / path.name).write_bytes(b"do-not-overwrite\n")

    with pytest.raises(HostEventSinkError, match="already exists"):
        quarantine_journal(
            journal,
            quarantine,
            path.name,
            expected_root_identity=(journal.stat().st_dev, journal.stat().st_ino),
            expected_quarantine_identity=(
                quarantine.stat().st_dev,
                quarantine.stat().st_ino,
            ),
            max_bytes=len(raw),
        )

    assert path.read_bytes() == raw
    assert (quarantine / path.name).read_bytes() == b"do-not-overwrite\n"


def test_quarantine_raced_collision_cannot_overwrite(tmp_path, monkeypatch):
    journal = (tmp_path / "events").resolve()
    quarantine = (tmp_path / "quarantine").resolve()
    journal.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    append_event(json.loads(raw_event()))
    path = next(journal.glob("*.jsonl"))
    raw = path.read_bytes()
    original_rename = sink._rename_noreplace

    def race_destination(source_directory, source, destination_directory, destination):
        descriptor = os.open(
            destination,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
            dir_fd=destination_directory,
        )
        try:
            os.write(descriptor, b"raced-destination\n")
        finally:
            os.close(descriptor)
        original_rename(
            source_directory,
            source,
            destination_directory,
            destination,
        )

    monkeypatch.setattr(sink, "_rename_noreplace", race_destination)
    with pytest.raises(HostEventSinkError, match="atomically quarantine"):
        quarantine_journal(
            journal,
            quarantine,
            path.name,
            expected_root_identity=(journal.stat().st_dev, journal.stat().st_ino),
            expected_quarantine_identity=(
                quarantine.stat().st_dev,
                quarantine.stat().st_ino,
            ),
            max_bytes=len(raw),
        )

    assert path.read_bytes() == raw
    assert (quarantine / path.name).read_bytes() == b"raced-destination\n"


def test_quarantine_receipt_restores_exact_journal(tmp_path, monkeypatch):
    journal = (tmp_path / "events").resolve()
    quarantine = (tmp_path / "quarantine").resolve()
    journal.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    append_event(json.loads(raw_event()))
    path = next(journal.glob("*.jsonl"))
    raw = path.read_bytes()
    source_identity = (journal.stat().st_dev, journal.stat().st_ino)
    quarantine_identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)
    retained = quarantine_journal(
        journal,
        quarantine,
        path.name,
        expected_root_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=len(raw),
    )

    restore_quarantined_journal(
        journal,
        quarantine,
        retained,
        expected_root_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=len(raw),
    )

    assert path.read_bytes() == raw
    assert not (quarantine / path.name).exists()


def test_restore_rejects_changed_quarantine_before_move(tmp_path, monkeypatch):
    journal = (tmp_path / "events").resolve()
    quarantine = (tmp_path / "quarantine").resolve()
    journal.mkdir(mode=0o700)
    quarantine.mkdir(mode=0o700)
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    append_event(json.loads(raw_event()))
    path = next(journal.glob("*.jsonl"))
    source_identity = (journal.stat().st_dev, journal.stat().st_ino)
    quarantine_identity = (quarantine.stat().st_dev, quarantine.stat().st_ino)
    retained = quarantine_journal(
        journal,
        quarantine,
        path.name,
        expected_root_identity=source_identity,
        expected_quarantine_identity=quarantine_identity,
        max_bytes=4096,
    )
    quarantined_path = quarantine / path.name
    quarantined_path.write_bytes(retained.raw + b"changed\n")

    with pytest.raises(HostEventSinkError, match="expected receipt"):
        restore_quarantined_journal(
            journal,
            quarantine,
            retained,
            expected_root_identity=source_identity,
            expected_quarantine_identity=quarantine_identity,
            max_bytes=4096,
        )

    assert not path.exists()
    assert quarantined_path.read_bytes() == retained.raw + b"changed\n"


def test_deployment_sink_and_reader_reject_symlink_or_partial_journal(
    tmp_path, monkeypatch
):
    journal = tmp_path.resolve()
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    event = json.loads(raw_event())
    append_event(event)
    path = next(journal.glob("*.jsonl"))
    outside = tmp_path / "outside.bin"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(HostEventSinkError, match="open"):
        append_event(event)
    with pytest.raises(HostEventSinkError, match="open"):
        read_events(journal)
    path.unlink()
    path.write_bytes(canonical_event(event))
    with pytest.raises(HostEventSinkError, match="partial"):
        read_events(journal)


def test_sink_and_reader_recheck_directory_permissions_at_use_time(
    tmp_path, monkeypatch
):
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o700)
    metadata = journal.stat()
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    monkeypatch.setenv(DEVICE_ENV, str(metadata.st_dev))
    monkeypatch.setenv(INODE_ENV, str(metadata.st_ino))
    journal.chmod(0o770)

    with pytest.raises(HostEventSinkError, match="private and owned"):
        append_event(json.loads(raw_event()))
    with pytest.raises(HostEventSinkError, match="private and owned"):
        read_events(journal)


def test_sink_and_reader_reject_directory_replacement_after_binding(
    tmp_path, monkeypatch
):
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o700)
    metadata = journal.stat()
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    monkeypatch.setenv(DEVICE_ENV, str(metadata.st_dev))
    monkeypatch.setenv(INODE_ENV, str(metadata.st_ino))
    journal.rename(tmp_path / "original-events")
    journal.mkdir(mode=0o700)

    with pytest.raises(HostEventSinkError, match="identity changed"):
        append_event(json.loads(raw_event()))
    with pytest.raises(HostEventSinkError, match="identity changed"):
        read_events(journal)
    assert not list(journal.iterdir())


def test_sink_and_reader_reject_fifo_without_blocking(tmp_path, monkeypatch):
    journal = tmp_path.resolve()
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(journal))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "0")
    event = json.loads(raw_event())
    append_event(event)
    path = next(journal.glob("*.jsonl"))
    path.unlink()
    os.mkfifo(path, 0o600)
    environment = os.environ.copy()
    environment["ECPA_TEST_HOST_EVENT"] = json.dumps(event, separators=(",", ":"))

    writer = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, os; "
                "from vllm_hust_ext.host_event_sink import append_event; "
                "append_event(json.loads(os.environ['ECPA_TEST_HOST_EVENT']))"
            ),
        ],
        capture_output=True,
        env=environment,
        text=True,
        timeout=2,
    )
    assert writer.returncode != 0
    assert "HostEventSinkError" in writer.stderr

    reader = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os; from pathlib import Path; "
                "from vllm_hust_ext.host_event_sink import read_events; "
                "read_events(Path(os.environ['ECPA_HOST_EVENT_DIR']))"
            ),
        ],
        capture_output=True,
        env=environment,
        text=True,
        timeout=2,
    )
    assert reader.returncode != 0
    assert "HostEventSinkError" in reader.stderr


def test_sink_rejects_invalid_durability_mode_before_writing(tmp_path, monkeypatch):
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(tmp_path.resolve()))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "sometimes")
    with pytest.raises(HostEventSinkError, match="must be 0 or 1"):
        append_event(json.loads(raw_event()))
    assert not list(tmp_path.glob("*.jsonl"))


def test_fsync_mode_syncs_new_file_and_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("ECPA_HOST_EVENT_DIR", str(tmp_path.resolve()))
    monkeypatch.setenv("ECPA_HOST_EVENT_FSYNC", "1")
    synced = []

    def record_fsync(descriptor):
        mode = os.fstat(descriptor).st_mode
        synced.append(
            "file"
            if stat.S_ISREG(mode)
            else "directory"
            if stat.S_ISDIR(mode)
            else "other"
        )

    monkeypatch.setattr(os, "fsync", record_fsync)
    append_event(json.loads(raw_event()))
    assert synced == ["file", "directory"]
