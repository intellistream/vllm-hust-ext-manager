import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft7Validator

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


def raw_event(**changes):
    value = {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "event-1",
        "event": "invoked",
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
        },
        "observed_at_ns": 1_800_000_000_000_000_000,
        "delivery_attempt": 1,
        "plan_id": PLAN.plan_id,
        "launch_id": "launch-1",
        "plugin_id": None,
        "artifact_digest": None,
        "identity_status": "absent; bind from the ECPA Plan at trusted ingestion",
        "detail": None,
    }
    value.update(changes)
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
        ({"plan_id": None}, True),
        ({"launch_id": None}, True),
        ({"detail": "load failure"}, True),
        ({"detail": None}, True),
        ({"detail": "有效"}, True),
        ({"plan_id": False}, False),
        ({"launch_id": 1}, False),
        ({"detail": {}}, False),
        ({"delivery_attempt": True}, False),
        ({"delivery_attempt": 0}, False),
        ({"extra": "field"}, False),
    ],
)
def test_schema_and_manual_parser_have_matching_boundary_semantics(mutation, valid):
    value = json.loads(raw_event())
    value.update(mutation)
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
