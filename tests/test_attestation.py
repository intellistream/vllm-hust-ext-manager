import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vllm_hust_ext.attestation import (
    AttestationError,
    AttestationErrorCode,
    AttestationStatement,
    ProcessStatement,
    SignedAttestationVerifier,
    SignedEnvelope,
    TrustEntry,
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
    State,
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
        "artifact_digest": "sha256:" + "a" * 64,
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
    return TrustStore(
        [
            TrustEntry(
                "urn:ecpa:issuer:host-a",
                "test-key-1",
                KEY.public_key(),
                frozenset({"host-runtime"}),
            )
        ]
    )


def test_sign_verify_and_unicode_is_not_normalized():
    decomposed = statement(issuer="urn:ecpa:issuer:e\u0301")
    composed = replace(decomposed, issuer="urn:ecpa:issuer:é")
    envelope = sign(decomposed, KEY)
    store = TrustStore(
        [
            TrustEntry(
                decomposed.issuer,
                decomposed.kid,
                KEY.public_key(),
                frozenset({"host-runtime"}),
            )
        ]
    )
    assert verify(envelope, store, NOW) == decomposed
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
        [
            TrustEntry(
                "urn:ecpa:issuer:host-a",
                "test-key-1",
                KEY.public_key(),
                frozenset({"host-runtime"}),
            ),
            TrustEntry(
                "urn:ecpa:issuer:host-a",
                "test-key-2",
                second.public_key(),
                frozenset({"host-runtime"}),
            ),
        ]
    )
    item = statement(kid="test-key-2")
    assert verify(sign(item, second), store, NOW) == item
    with pytest.raises(AttestationError) as caught:
        verify(sign(item, second), trust_store(), NOW)
    assert caught.value.code is AttestationErrorCode.UNKNOWN_KEY


@pytest.mark.parametrize(
    "entry",
    [
        TrustEntry("", "kid", KEY.public_key(), frozenset({"host-runtime"})),
        TrustEntry("issuer", "", KEY.public_key(), frozenset({"host-runtime"})),
        TrustEntry("issuer", "kid", KEY.public_key(), frozenset()),
        TrustEntry("issuer", "kid", KEY.public_key(), frozenset({""})),
        TrustEntry(
            "issuer", "kid", KEY.public_key(), frozenset({"host-runtime"}), 2, 1
        ),
    ],
)
def test_trust_store_rejects_invalid_entries_with_stable_code(entry):
    with pytest.raises(AttestationError) as caught:
        TrustStore([entry])
    assert caught.value.code is AttestationErrorCode.TRUST_STORE_CONFIG


def test_trust_store_rejects_duplicate_identity_and_wrong_entry_type():
    entry = TrustEntry("issuer", "kid", KEY.public_key(), frozenset({"host-runtime"}))
    for entries in ([entry, entry], [object()]):
        with pytest.raises(AttestationError) as caught:
            TrustStore(entries)
        assert caught.value.code is AttestationErrorCode.TRUST_STORE_CONFIG


def test_signed_adapter_binds_before_coordinator_and_store_fences_replay(tmp_path):
    plan = Plan(
        (PLUGIN,),
        HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
        (ResourceClaim("urn:ecpa:resource:org.vllm-hust.signed", PLUGIN.id),),
        (OBLIGATION,),
        PredecessorSnapshot(0, "old", {"route": "old"}),
    )
    signed_statement = statement(plan_id=plan.plan_id)
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
        "host-runtime",
        signed_statement.issuer,
        signed_statement.kid,
        signed_statement.observed_at,
        signed_statement.evidence_digest,
        signed_statement.artifact_digest,
    )
    verifier = SignedAttestationVerifier(
        {item.nonce: sign(signed_statement, KEY)},
        trust_store(),
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
    row = store.connection.execute(
        "SELECT issuer,kid,observed_at,evidence_digest,artifact_digest "
        "FROM evidence WHERE nonce=?",
        (item.nonce,),
    ).fetchone()
    assert tuple(row) == (
        signed_statement.issuer,
        signed_statement.kid,
        signed_statement.observed_at,
        signed_statement.evidence_digest,
        signed_statement.artifact_digest,
    )
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
        "host-runtime",
        item.issuer,
        item.kid,
        item.observed_at,
        item.evidence_digest,
        item.artifact_digest,
    )
    with pytest.raises(AttestationError) as caught:
        verifier.verify(logical, NOW, type("Plan", (), {"plugins": (PLUGIN,)})())
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH


@pytest.mark.parametrize(
    "mutation",
    [
        "issuer",
        "kid",
        "observed_at",
        "evidence_digest",
        "artifact_digest",
        "plan_artifact_source",
    ],
)
def test_each_persisted_binding_mutation_is_rejected_without_insert(tmp_path, mutation):
    plan = Plan(
        (PLUGIN,),
        HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
        (ResourceClaim("urn:ecpa:resource:org.vllm-hust.signed", PLUGIN.id),),
        (OBLIGATION,),
        PredecessorSnapshot(0, "old", {"route": "old"}),
    )
    signed = statement(plan_id=plan.plan_id, challenge_nonce=f"nonce-{mutation}")
    logical = Attestation(
        plan.plan_id,
        signed.launch_id,
        PROCESS,
        signed.obligation,
        signed.event,
        signed.challenge_nonce,
        signed.issued_at,
        signed.expires_at,
        signed.plugin_id,
        signed.subject,
        signed.issuer,
        signed.kid,
        signed.observed_at,
        signed.evidence_digest,
        signed.artifact_digest,
    )
    if mutation == "plan_artifact_source":
        signed = replace(signed, artifact_digest="sha256:" + "d" * 64)
        logical = replace(logical, artifact_digest=signed.artifact_digest)
    else:
        replacements = {
            "issuer": {"issuer": "urn:ecpa:issuer:other"},
            "kid": {"kid": "other-kid"},
            "observed_at": {"observed_at": signed.observed_at - 1},
            "evidence_digest": {"evidence_digest": "sha256:" + "d" * 64},
            "artifact_digest": {"artifact_digest": "sha256:" + "d" * 64},
        }
        logical = replace(logical, **replacements[mutation])
    verifier = SignedAttestationVerifier(
        {logical.nonce: sign(signed, KEY)}, trust_store()
    )
    store = SQLiteActivationStore(tmp_path / f"binding-{mutation}.db")
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
    coordinator.launch(plan_id, signed.launch_id)
    with pytest.raises(AttestationError) as caught:
        coordinator.observe(plan_id, logical, NOW)
    assert caught.value.code is AttestationErrorCode.BINDING_MISMATCH
    assert store.connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0
    store.close()


def test_statement_json_shape_is_stable():
    assert json.loads(canonicalize(statement().to_dict()))["schema"] == SCHEMA


def test_shared_raw_envelope_corpus():
    from scripts.check_attestation_vectors import main

    main()


def test_schema_invalid_signed_receipt_cannot_become_effective(tmp_path):
    vectors = json.loads(
        (Path(__file__).parents[1] / "spec/0.1/attestation-vectors.json").read_text()
    )
    vector = next(
        item for item in vectors["cases"] if item["id"] == "negative-empty-issuer"
    )
    payload = base64.urlsafe_b64decode(
        vector["payload_b64"] + "=" * (-len(vector["payload_b64"]) % 4)
    )
    envelope = SignedEnvelope(payload, vector["detached_jws"])
    plan = Plan(
        (PLUGIN,),
        HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
        (ResourceClaim("urn:ecpa:resource:org.vllm-hust.signed", PLUGIN.id),),
        (OBLIGATION,),
        PredecessorSnapshot(0, "old", {"route": "old"}),
    )
    logical = Attestation(
        plan.plan_id,
        "launch-1",
        PROCESS,
        OBLIGATION.obligation_id,
        OBLIGATION.event,
        "nonce-1",
        NOW - 1,
        NOW + 60,
        PLUGIN.id,
        "host-runtime",
        "",
        "test-key-1",
        NOW - 2,
        "sha256:" + "4" * 64,
        "sha256:" + "3" * 64,
    )
    store = SQLiteActivationStore(tmp_path / "invalid.db")
    coordinator = ActivationCoordinator(
        store,
        FakeHostAdapter((PROCESS,)),
        SignedAttestationVerifier({logical.nonce: envelope}, trust_store()),
        FakeTrafficGate(),
        FakeExternalServiceAdapter(),
        clock=lambda: NOW,
    )
    plan_id = coordinator.plan(plan)
    coordinator.prepare(plan_id)
    coordinator.launch(plan_id, "launch-1")
    with pytest.raises(AttestationError) as caught:
        coordinator.observe(plan_id, logical, NOW)
    assert caught.value.code is AttestationErrorCode.INVALID_STATEMENT
    assert coordinator.status(plan_id)["state"] == State.OBSERVING.value
    assert store.connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 0
    store.close()
