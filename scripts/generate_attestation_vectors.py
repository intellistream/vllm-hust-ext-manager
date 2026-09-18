#!/usr/bin/env python3
"""Generate deterministic TEST ONLY ECPA attestation conformance vectors."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vllm_hust_ext.attestation.model import (
    PROFILE,
    SCHEMA,
    AttestationStatement,
    ProcessStatement,
)
from vllm_hust_ext.attestation.profile import TYPE, canonicalize, sign

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/0.1/attestation-vectors.json"
NOW = 1_800_000_000
SEEDS = {"test-key-1": bytes(range(32)), "test-key-2": bytes(range(32, 64))}


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def raw_sign(payload: bytes, header: dict, key: Ed25519PrivateKey) -> str:
    encoded = b64(canonicalize(header))
    signing_input = f"{encoded}.{b64(payload)}".encode()
    return f"{encoded}..{b64(key.sign(signing_input))}"


def statement(**changes):
    values = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "issuer": "urn:ecpa:issuer:vllm-hust-host-a",
        "kid": "test-key-1",
        "subject": "host-runtime",
        "plan_id": "plan:sha256:" + "1" * 64,
        "launch_id": "launch-1",
        "plugin_id": "plugin:sha256:" + "2" * 64,
        "artifact_digest": "sha256:" + "3" * 64,
        "process": ProcessStatement("host-a", "worker", 0, "start-0", 7),
        "obligation": "workers-invoked",
        "event": "invoked",
        "observed_at": NOW - 2,
        "issued_at": NOW - 1,
        "expires_at": NOW + 60,
        "challenge_nonce": "nonce-1",
        "evidence_digest": "sha256:" + "4" * 64,
        "critical_claims": (),
    }
    values.update(changes)
    return AttestationStatement(**values)


def binding(item: AttestationStatement) -> dict:
    return {
        "plan_id": item.plan_id,
        "launch_id": item.launch_id,
        "plugin_id": item.plugin_id,
        "artifact_digest": item.artifact_digest,
        "process_epoch": item.process.epoch,
        "challenge_nonce": item.challenge_nonce,
    }


def case(case_id, category, item, key, expected="OK", expected_binding=None):
    envelope = sign(item, key)
    return {
        "id": case_id,
        "category": category,
        "payload_b64": b64(envelope.payload),
        "detached_jws": envelope.detached_jws,
        "now": NOW,
        "expected": expected,
        "binding": expected_binding,
    }


def main() -> None:
    keys = {
        kid: Ed25519PrivateKey.from_private_bytes(seed) for kid, seed in SEEDS.items()
    }
    base = statement()
    cases = [
        case(
            "positive-ascii",
            "positive",
            base,
            keys[base.kid],
            expected_binding=binding(base),
        ),
        case(
            "positive-unicode-decomposed",
            "positive",
            statement(
                issuer="urn:ecpa:issuer:host-e\u0301", challenge_nonce="nonce-unicode"
            ),
            keys["test-key-1"],
            expected_binding=None,
        ),
        case(
            "positive-safe-integer-max",
            "positive",
            statement(
                process=ProcessStatement(
                    "host-a", "worker", 9007199254740991, "start-max", 7
                )
            ),
            keys["test-key-1"],
        ),
        case(
            "positive-safe-integer-min",
            "positive",
            statement(observed_at=0, issued_at=0, expires_at=NOW + 60),
            keys["test-key-1"],
        ),
        case(
            "positive-key-rotation",
            "positive",
            statement(kid="test-key-2", challenge_nonce="nonce-key-2"),
            keys["test-key-2"],
        ),
    ]

    # Reordered source objects normalize to the same JCS payload.
    reordered_statement = statement(challenge_nonce="nonce-reordered")
    reordered = dict(reversed(list(reordered_statement.to_dict().items())))
    reordered_payload = canonicalize(reordered)
    reordered_jws = raw_sign(
        reordered_payload,
        {
            "alg": "EdDSA",
            "crit": ["ecpa_profile"],
            "ecpa_profile": PROFILE,
            "kid": base.kid,
            "typ": TYPE,
        },
        keys[base.kid],
    )
    cases.append(
        {
            "id": "positive-reordered-input",
            "category": "positive",
            "payload_b64": b64(reordered_payload),
            "detached_jws": reordered_jws,
            "now": NOW,
            "expected": "OK",
            "binding": binding(reordered_statement),
        }
    )

    valid = sign(base, keys[base.kid])
    tampered = bytearray(valid.payload)
    tampered[tampered.index(b"invoked")] = ord("I")
    cases.append(
        {
            "id": "negative-payload-tamper",
            "category": "tamper",
            "payload_b64": b64(bytes(tampered)),
            "detached_jws": valid.detached_jws,
            "now": NOW,
            "expected": "ATTESTATION_INVALID_SIGNATURE",
            "binding": None,
        }
    )
    sig_parts = valid.detached_jws.split(".")
    sig = bytearray(base64.urlsafe_b64decode(sig_parts[2] + "=="))
    sig[0] ^= 1
    cases.append(
        {
            "id": "negative-signature-tamper",
            "category": "tamper",
            "payload_b64": b64(valid.payload),
            "detached_jws": f"{sig_parts[0]}..{b64(bytes(sig))}",
            "now": NOW,
            "expected": "ATTESTATION_INVALID_SIGNATURE",
            "binding": None,
        }
    )

    headers = [
        (
            "negative-wrong-alg",
            "header",
            {"alg": "HS256"},
            "ATTESTATION_WRONG_ALGORITHM",
        ),
        (
            "negative-wrong-profile-header",
            "header",
            {"ecpa_profile": "other"},
            "ATTESTATION_WRONG_PROFILE",
        ),
        ("negative-wrong-type", "header", {"typ": "JWT"}, "ATTESTATION_WRONG_TYPE"),
        (
            "negative-unknown-critical-header",
            "header",
            {"crit": ["ecpa_profile", "unknown"], "unknown": True},
            "ATTESTATION_UNKNOWN_CRITICAL_HEADER",
        ),
    ]
    base_header = {
        "alg": "EdDSA",
        "crit": ["ecpa_profile"],
        "ecpa_profile": PROFILE,
        "kid": base.kid,
        "typ": TYPE,
    }
    unknown_key_statement = statement(
        kid="unknown", challenge_nonce="nonce-unknown-key"
    )
    unknown_payload = canonicalize(unknown_key_statement.to_dict())
    unknown_header = {**base_header, "kid": "unknown"}
    cases.append(
        {
            "id": "negative-wrong-kid",
            "category": "key",
            "payload_b64": b64(unknown_payload),
            "detached_jws": raw_sign(unknown_payload, unknown_header, keys[base.kid]),
            "now": NOW,
            "expected": "ATTESTATION_UNKNOWN_KEY",
            "binding": None,
        }
    )
    for case_id, category, changes, expected in headers:
        header = {**base_header, **changes}
        cases.append(
            {
                "id": case_id,
                "category": category,
                "payload_b64": b64(valid.payload),
                "detached_jws": raw_sign(valid.payload, header, keys[base.kid]),
                "now": NOW,
                "expected": expected,
                "binding": None,
            }
        )

    cases.extend(
        [
            case(
                "negative-unknown-critical-claim",
                "claim",
                statement(critical_claims=("future_claim",)),
                keys["test-key-1"],
                "ATTESTATION_UNKNOWN_CRITICAL_CLAIM",
            ),
            case(
                "negative-expired",
                "freshness",
                statement(expires_at=NOW - 1),
                keys["test-key-1"],
                "ATTESTATION_EXPIRED",
            ),
            case(
                "negative-future",
                "freshness",
                statement(observed_at=NOW + 10, issued_at=NOW + 10),
                keys["test-key-1"],
                "ATTESTATION_NOT_YET_VALID",
            ),
        ]
    )
    for field, changed in [
        ("plan_id", "plan:other"),
        ("launch_id", "launch-other"),
        ("plugin_id", "plugin:other"),
        ("artifact_digest", "sha256:" + "9" * 64),
    ]:
        item = statement(**{field: changed}, challenge_nonce=f"nonce-mismatch-{field}")
        cases.append(
            case(
                f"negative-{field.replace('_', '-')}-mismatch",
                "binding",
                item,
                keys["test-key-1"],
                "ATTESTATION_BINDING_MISMATCH",
                binding(base),
            )
        )
    epoch_item = statement(
        process=ProcessStatement("host-a", "worker", 0, "start-0", 8),
        challenge_nonce="nonce-mismatch-epoch",
    )
    cases.append(
        case(
            "negative-process-epoch-mismatch",
            "binding",
            epoch_item,
            keys["test-key-1"],
            "ATTESTATION_BINDING_MISMATCH",
            binding(base),
        )
    )

    replay = statement(challenge_nonce="nonce-replay")
    cases.append(
        case(
            "positive-replay-first",
            "replay",
            replay,
            keys["test-key-1"],
            "OK",
            binding(replay),
        )
    )
    cases.append(
        case(
            "negative-nonce-replay",
            "replay",
            replay,
            keys["test-key-1"],
            "REPLAYED_NONCE",
            binding(replay),
        )
    )

    malformed = [
        ("negative-malformed-json", b"{"),
        ("negative-duplicate-key", b'{"a":1,"a":2}'),
        ("negative-nan", b'{"x":NaN}'),
        ("negative-float", b'{"x":1.5}'),
    ]
    for case_id, payload in malformed:
        header = base_header
        expected = {
            "negative-malformed-json": "ATTESTATION_MALFORMED_JSON",
            "negative-duplicate-key": "ATTESTATION_DUPLICATE_KEY",
            "negative-nan": "ATTESTATION_UNSUPPORTED_VALUE",
            "negative-float": "ATTESTATION_UNSUPPORTED_VALUE",
        }[case_id]
        cases.append(
            {
                "id": case_id,
                "category": "json",
                "payload_b64": b64(payload),
                "detached_jws": raw_sign(payload, header, keys[base.kid]),
                "now": NOW,
                "expected": expected,
                "binding": None,
            }
        )
    noncanonical = json.dumps(base.to_dict(), ensure_ascii=False, indent=1).encode()
    cases.append(
        {
            "id": "negative-noncanonical",
            "category": "canonicalization",
            "payload_b64": b64(noncanonical),
            "detached_jws": raw_sign(noncanonical, base_header, keys[base.kid]),
            "now": NOW,
            "expected": "ATTESTATION_NONCANONICAL_PAYLOAD",
            "binding": None,
        }
    )

    public_keys = []
    for kid, key in keys.items():
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_keys.append({"kid": kid, "public_key_b64": b64(public)})
    output = {
        "schema": "ecpa-attestation-vectors/0.1",
        "test_only": True,
        "keys": public_keys,
        "cases": cases,
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(f"wrote {len(cases)} vectors to {OUTPUT}")


if __name__ == "__main__":
    main()
