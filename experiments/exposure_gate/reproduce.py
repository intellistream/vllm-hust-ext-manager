#!/usr/bin/env python3
"""Execute every deterministic reference scenario and generate artifacts."""

from __future__ import annotations

import argparse
import json
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from vllm_hust_ext.exposure_gate import (
    AdmissionRequest,
    AdmissionResult,
    BehavioralOracleResult,
    DeterministicTrafficAdapter,
    GateError,
    InjectedCrash,
    LeaseAuthority,
    LeaseGrant,
    OpenProof,
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
GRANT = LeaseGrant("manager", 1, NOW + 60)
PROOF = OpenProof(
    "candidate",
    1,
    1,
    "sha256:" + "1" * 64,
    "sha256:" + "2" * 64,
    GRANT,
)


def gate_at(path: Path, **options: Any) -> tuple[ReferenceExposureGate, Any]:
    adapter = DeterministicTrafficAdapter(
        0, PREDECESSOR, authority=LeaseAuthority(GRANT), **options
    )
    return ReferenceExposureGate(path, adapter, clock=lambda: NOW), adapter


def prepare(gate: ReferenceExposureGate) -> None:
    gate.stage({"plan_id": "candidate"}, PREDECESSOR)
    gate.close(1)


def execute(scenario: str, path: Path) -> tuple[str, dict[str, Any] | None]:
    options: dict[str, Any] = {}
    if scenario == "rollback-behavioral":
        options["behavioral_restore"] = True
    if scenario == "rollback-failure":
        options["rollback_fails"] = True
    gate, adapter = gate_at(path, **options)
    if scenario == "happy-open-drain":
        gate.stage({"plan_id": "candidate"}, PREDECESSOR)
        gate.observe(AdmissionRequest("request-old", NOW))
        gate.close(1)
    else:
        prepare(gate)
    detail: dict[str, Any] | None = None
    try:
        if scenario == "happy-open-drain":
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
            detail = evaluate_trace(path)
            return detail["verdict"], detail
        if scenario == "crash-after-open-intent":
            gate.faults.add("open.after_intent")
            with suppress(InjectedCrash):
                gate.open(1, PROOF)
            return gate.reconcile().value, None
        if scenario == "crash-after-open-side-effect":
            adapter.faults.add("open.after")
            with suppress(InjectedCrash):
                gate.open(1, PROOF)
            return gate.reconcile().value, {
                "reconciled_by": "actual-generation-and-route-fence-query"
            }
        if scenario == "stale-generation-cas":
            gate.open(2, PROOF)
        elif scenario == "lease-loss":
            adapter.authority.grant = LeaseGrant("other", 2, NOW + 60)
            gate.open(1, PROOF)
        elif scenario == "partial-worker-evidence-2-of-4":
            gate.open(
                1,
                OpenProof(
                    "candidate",
                    1,
                    0,
                    PROOF.evidence_digest,
                    PROOF.coverage_digest,
                    GRANT,
                ),
            )
        elif scenario == "old-epoch-or-replay":
            gate.open(
                1,
                OpenProof(
                    "wrong-plan",
                    1,
                    1,
                    PROOF.evidence_digest,
                    PROOF.coverage_digest,
                    GRANT,
                ),
            )
        elif scenario.startswith("rollback-"):
            gate.open(1, PROOF)
            oracle = None
            if scenario == "rollback-behavioral":
                oracle = BehavioralOracleResult(
                    True, "sha256:" + "3" * 64, "reference-oracle"
                )
            return gate.rollback(1, oracle).value, None
        else:
            raise ValueError(f"unknown scenario: {scenario}")
    except GateError:
        return "REJECT", None
    raise AssertionError(f"scenario did not return: {scenario}")


def generate(output: Path) -> dict[str, Any]:
    definition = json.loads(
        Path("experiments/exposure_gate/scenarios.json").read_text()
    )
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    happy_trace: list[dict[str, Any]] = []
    oracle = None
    with tempfile.TemporaryDirectory(prefix="ecpa-exposure-cases-") as directory:
        root = Path(directory)
        for item in definition["scenarios"]:
            path = root / f"{item['id']}.db"
            observed, detail = execute(item["id"], path)
            row = {
                "classification": "synthetic/reference",
                "expected": item["expected"],
                "observed": observed,
                "scenario": item["id"],
            }
            if detail and "reconciled_by" in detail:
                row.update(detail)
            rows.append(row)
            if item["id"] == "happy-open-drain":
                happy_trace = export_trace(path)
                oracle = detail
    if any(row["expected"] != row["observed"] for row in rows):
        raise SystemExit("scenario verdict mismatch")
    trace_text = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in happy_trace
    )
    matrix_text = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )
    summary = {
        "schema": "ecpa-exposure-results/0.2",
        "classification": "synthetic/reference",
        "formal_paper_result": False,
        "seed": definition["seed"],
        "clock": definition["clock"],
        "oracle": oracle,
        "fault_matrix": {row["scenario"]: row["observed"] for row in rows},
    }
    (output / "reference-trace.jsonl").write_text(trace_text)
    (output / "fault-matrix.jsonl").write_text(matrix_text)
    (output / "result-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output is None:
        with tempfile.TemporaryDirectory(prefix="ecpa-exposure-") as directory:
            print(json.dumps(generate(Path(directory)), sort_keys=True))
    else:
        generate(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
