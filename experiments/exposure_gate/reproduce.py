#!/usr/bin/env python3
"""Reproduce the deterministic reference trace; not a performance result."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from vllm_hust_ext.exposure_gate import (
    AdmissionRequest,
    AdmissionResult,
    DeterministicTrafficAdapter,
    ReferenceExposureGate,
    evaluate_trace,
    export_trace,
)

NOW = 1_800_000_000
PREDECESSOR = {
    "generation": 0,
    "plan_id": "old",
    "rendered_inputs": {"route": "old"},
}
PROOF = {
    "signed_receipts_verified": True,
    "required_process_coverage": True,
    "lease_valid": True,
    "generation_cas": True,
    "lease_token": "lease-1",
}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ecpa-exposure-") as directory:
        path = Path(directory) / "gate.db"
        adapter = DeterministicTrafficAdapter(0, PREDECESSOR)
        gate = ReferenceExposureGate(path, adapter, clock=lambda: NOW)
        gate.stage({"plan_id": "candidate"}, PREDECESSOR)
        gate.observe(AdmissionRequest("request-old", NOW))
        gate.close(1)
        gate.open(1, PROOF)
        gate.observe(
            AdmissionRequest("request-new", NOW + 1),
            AdmissionResult(NOW + 2, result="ok"),
        )
        gate.observe(
            AdmissionRequest("request-old", NOW),
            AdmissionResult(NOW + 3, result="ok"),
        )
        gate.drain(1)
        print(json.dumps(evaluate_trace(path), sort_keys=True, separators=(",", ":")))
        for row in export_trace(path):
            print(json.dumps(row, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
