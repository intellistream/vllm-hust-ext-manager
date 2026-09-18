#!/usr/bin/env python3
"""Check ECPA attestation vectors with the Python implementation."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vllm_hust_ext.attestation import (
    AttestationError,
    SignedEnvelope,
    TrustEntry,
    TrustStore,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec/0.1/attestation-vectors.json"


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> None:
    data = json.loads(VECTORS.read_text())
    store = TrustStore(
        [
            TrustEntry(
                item["issuer"],
                item["kid"],
                Ed25519PublicKey.from_public_bytes(decode(item["public_key_b64"])),
                frozenset(item["subjects"]),
                item["not_before"],
                item["not_after"],
                item["enabled"],
            )
            for item in data["keys"]
        ]
    )
    seen: set[str] = set()
    failures = []
    for item in data["cases"]:
        envelope = SignedEnvelope(decode(item["payload_b64"]), item["detached_jws"])
        try:
            statement = verify(envelope, store, item["now"])
            expected_binding = item.get("binding")
            if expected_binding:
                actual = {
                    "plan_id": statement.plan_id,
                    "launch_id": statement.launch_id,
                    "plugin_id": statement.plugin_id,
                    "artifact_digest": statement.artifact_digest,
                    "process_epoch": statement.process.epoch,
                    "challenge_nonce": statement.challenge_nonce,
                }
                if actual != expected_binding:
                    outcome = "ATTESTATION_BINDING_MISMATCH"
                elif statement.challenge_nonce in seen:
                    outcome = "REPLAYED_NONCE"
                else:
                    seen.add(statement.challenge_nonce)
                    outcome = "OK"
            else:
                outcome = "OK"
        except AttestationError as exc:
            outcome = exc.code.value
        if outcome != item["expected"]:
            failures.append((item["id"], item["expected"], outcome))
    if failures:
        raise SystemExit(f"vector failures: {failures}")
    print(f"Python attestation conformance: {len(data['cases'])} vectors passed")


if __name__ == "__main__":
    main()
