import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vllm_hust_ext.attestation import (
    AttestationError,
    AttestationErrorCode,
    AttestationStatement,
    ProcessStatement,
    SignedAttestationVerifier,
    TrustStore,
    canonicalize,
    sign,
    verify,
)
from vllm_hust_ext.attestation.model import PROFILE, SCHEMA
from vllm_hust_ext.durable_coordinator import (
    ActivationCoordinator,
    FakeExternalServiceAdapter,
    FakeHostAdapter,
    FakeTrafficGate,
    SQLiteActivationStore,
)
from vllm_hust_ext.ecpa_model import (
    Attestation,
    ContractError,
    ErrorCode,
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
    ResourceClaim,
)

NOW = 1_800_000_000
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PLUGIN = PluginIdentity("org.vllm-hust", "signed", "1", "a" * 64)
PROCESS = ProcessIdentity("host-a", "worker", 0, "start-0", 7)
OBLIGATION = EvidenceObligation("workers-invoked", "worker", "invoked", (0,))


def statement(**changes):
    values = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "issuer": "urn:ecpa:issuer:host-a",
        "kid": "test-key-1",
        "subject": "host-runtime",
        "plan_id": "plan-1",
        "launch_id": "launch-1",
        "plugin_id": PLUGIN.id,
        "artifact_digest": "sha256:" + "b" * 64,
        "process": ProcessStatement("host-a", "worker", 0, "start-0", 7),
        "obligation": OBLIGATION.obligation_id,
        "event": OBLIGATION.event,
        "observed_at": NOW - 2,
        "issued_at": NOW - 1,
        "expires_at": NOW + 60,
        "challenge_nonce": "nonce-1",
        "evidence_digest": "sha256:" + "c" * 64,
        "critical_claims": (),
    }
    values.update(changes)
    return AttestationStatement(**values)


def trust_store():
    return TrustStore({"test-key-1": KEY.public_key()})


def test_sign_verify_and_unicode_is_not_normalized():
    decomposed = statement(issuer="urn:ecpa:issuer:e\u0301")
    composed = replace(decomposed, issuer="urn:ecpa:issuer:é")
    envelope = sign(decomposed, KEY)
    assert verify(envelope, trust_store(), NOW) == decomposed
    assert canonicalize(decomposed.to_dict()) != canonicalize(composed.to_dict())


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b'{"a":1,"a":2}', AttestationErrorCode.DUPLICATE_KEY),
        (b'{"x":NaN}', AttestationErrorCode.UNSUPPORTED_VALUE),
        (b'{"x":Infinity}', AttestationErrorCode.UNSUPPORTED_VALUE),
        (b'{"x":1.5}', AttestationErrorCode.UNSUPPORTED_VALUE),
        (b"{", AttestationErrorCode.MALFORMED_JSON),
    ],
)
def test_malformed_values_fail_closed(raw, code):
    from vllm_hust_ext.attestation.profile import parse_strict

    with pytest.raises(AttestationError) as caught:
        value = parse_strict(raw)
        canonicalize(value)
    assert caught.value.code is code


def test_two_key_rotation_and_wrong_kid():
    second = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    store = TrustStore(
        {"test-key-1": KEY.public_key(), "test-key-2": second.public_key()}
    )
    item = statement(kid="test-key-2")
    assert verify(sign(item, second), store, NOW) == item
    with pytest.raises(AttestationError) as caught:
        verify(sign(item, second), trust_store(), NOW)
    assert caught.value.code is AttestationErrorCode.UNKNOWN_KEY


def test_signed_adapter_binds_before_coordinator_and_store_fences_replay(tmp_path):
    plan = Plan(
        (PLUGIN,),
        HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
        (ResourceClaim("urn:ecpa:resource:org.vllm-hust.signed", PLUGIN.id),),
        (OBLIGATION,),
        PredecessorSnapshot(0, "old", {"route": "old"}),
    )
    item = Attestation(
        plan.plan_id,
        "launch-1",
        PROCESS,
        OBLIGATION.obligation_id,
        OBLIGATION.event,
        "nonce-1",
        NOW - 1,
        NOW + 60,
        PLUGIN.id,
    )
    signed_statement = statement(plan_id=plan.plan_id)
    verifier = SignedAttestationVerifier(
        {item.nonce: sign(signed_statement, KEY)},
        trust_store(),
        {PLUGIN.id: "sha256:" + "b" * 64},
    )
    store = SQLiteActivationStore(tmp_path / "signed.db")
    coordinator = ActivationCoordinator(
        store,
        FakeHostAdapter((PROCESS,)),
        verifier,
        FakeTrafficGate(),
        FakeExternalServiceAdapter(),
        clock=lambda: NOW,
    )
    plan_id = coordinator.plan(plan)
    coordinator.prepare(plan_id)
    coordinator.launch(plan_id, "launch-1")
    coordinator.observe(plan_id, item, NOW)
    with pytest.raises(ContractError) as caught:
        coordinator.observe(plan_id, item, NOW)
    assert caught.value.code is ErrorCode.REPLAYED_NONCE
    assert coordinator.commit(plan_id, 0) == 1
    store.close()


def test_signature_does_not_override_binding_or_coverage(tmp_path):
    item = statement(plan_id="wrong-plan")
    verifier = SignedAttestationVerifier(
        {item.challenge_nonce: sign(item, KEY)},
        trust_store(),
        {PLUGIN.id: "sha256:" + "b" * 64},
    )
    logical = Attestation(
        "right-plan",
        item.launch_id,
        PROCESS,
        item.obligation,
        item.event,
        item.challenge_nonce,
        item.issued_at,
        item.expires_at,
        item.plugin_id,
    )
    with pytest.raises(AttestationError) as caught:
        verifier.verify(logical, NOW)
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


def test_statement_json_shape_is_stable():
    assert json.loads(canonicalize(statement().to_dict()))["schema"] == SCHEMA
