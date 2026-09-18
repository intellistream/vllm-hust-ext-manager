#!/usr/bin/env python3
"""Local microbenchmark scaffold; output is not a paper performance result."""

from __future__ import annotations

import json
import platform
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vllm_hust_ext.attestation import (
    AttestationStatement,
    ProcessStatement,
    TrustStore,
    canonicalize,
    sign,
    verify,
)
from vllm_hust_ext.attestation.model import PROFILE, SCHEMA

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/0.1/benchmarks/attestation-local-20260918.json"
NOW = 1_800_000_000


def measure(operation, iterations=100):
    values = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        operation()
        values.append(time.perf_counter_ns() - start)
    return {
        "iterations": iterations,
        "raw_ns": values,
        "median_ns": int(statistics.median(values)),
    }


def main() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    item = AttestationStatement(
        SCHEMA,
        PROFILE,
        "urn:ecpa:issuer:benchmark",
        "test-key-1",
        "host-runtime",
        "plan:benchmark",
        "launch-benchmark",
        "plugin:benchmark",
        "sha256:" + "a" * 64,
        ProcessStatement("host-a", "worker", 0, "start-0", 1),
        "workers-invoked",
        "invoked",
        NOW - 2,
        NOW - 1,
        NOW + 60,
        "nonce-benchmark",
        "sha256:" + "b" * 64,
    )
    envelope = sign(item, key)
    store = TrustStore({"test-key-1": key.public_key()})
    result = {
        "schema": "ecpa-attestation-microbenchmark/0.1",
        "formal_paper_result": False,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "payload_bytes": len(envelope.payload),
        "operations": {
            "canonicalize": measure(lambda: canonicalize(item.to_dict())),
            "sign": measure(lambda: sign(item, key)),
            "verify": measure(lambda: verify(envelope, store, NOW)),
        },
        "production_conclusion": None,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    print(OUTPUT)


if __name__ == "__main__":
    main()
