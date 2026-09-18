import hashlib
import json
from dataclasses import replace

import pytest

from vllm_hust_ext.attestation import AttestationError, AttestationErrorCode
from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.host_evidence import (
    EntryPointBinding,
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
        raw_event(process={
            "host": "host-a",
            "role": "worker",
            "ordinal": 0,
            "pid": 4242,
            "start_identity": "pid:4242:start_ticks:9001",
            "process_epoch": 8,
        }),
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
    assert not hasattr(receipt, "signature")
    assert not hasattr(receipt.statement, "nonce")
