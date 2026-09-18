#!/usr/bin/env python3
"""Execute every deterministic reference scenario and generate artifacts."""

from __future__ import annotations

import argparse
import json
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vllm_hust_ext.attestation import (
    AttestationStatement,
    ProcessStatement,
    SignedAttestationVerifier,
    TrustEntry,
    TrustStore,
    sign,
)
from vllm_hust_ext.attestation.model import PROFILE, SCHEMA
from vllm_hust_ext.durable_coordinator import (
    ActivationCoordinator,
    FakeExternalServiceAdapter,
    FakeHostAdapter,
    SQLiteActivationStore,
)
from vllm_hust_ext.ecpa_model import (
    Attestation,
    ContractError,
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
)
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


def coordinator_rejection(scenario: str, root: Path) -> str:
    root.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    plugin = PluginIdentity("org.vllm-hust", "scenario", "1", "a" * 64)
    obligation = EvidenceObligation("workers", "worker", "invoked", (0, 1, 2, 3))
    predecessor = PredecessorSnapshot(0, "old", {"route": "old"})
    plan = Plan(
        (plugin,),
        HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
        (),
        (obligation,),
        predecessor,
    )
    processes = tuple(
        ProcessIdentity("host-a", "worker", ordinal, f"start-{ordinal}", 7)
        for ordinal in range(4)
    )
    envelopes = {}
    attestations = []
    for process in processes:
        nonce = f"scenario-{process.ordinal}"
        statement = AttestationStatement(
            SCHEMA,
            PROFILE,
            "urn:ecpa:issuer:scenario",
            "key-1",
            "host-runtime",
            plan.plan_id,
            "launch-1",
            plugin.id,
            "sha256:" + plugin.artifact_sha256,
            ProcessStatement(
                process.host,
                process.role,
                process.ordinal,
                process.start_id,
                process.epoch,
            ),
            obligation.obligation_id,
            obligation.event,
            NOW - 2,
            NOW - 1,
            NOW + 60,
            nonce,
            "sha256:" + f"{process.ordinal + 1:064x}",
        )
        envelopes[nonce] = sign(statement, key)
        attestations.append(
            Attestation(
                plan.plan_id,
                "launch-1",
                process,
                obligation.obligation_id,
                obligation.event,
                nonce,
                NOW - 1,
                NOW + 60,
                plugin.id,
                "host-runtime",
                statement.issuer,
                statement.kid,
                statement.observed_at,
                statement.evidence_digest,
                statement.artifact_digest,
            )
        )
    old_process = ProcessIdentity("host-a", "worker", 0, "old-start", 6)
    old_statement = AttestationStatement(
        SCHEMA,
        PROFILE,
        "urn:ecpa:issuer:scenario",
        "key-1",
        "host-runtime",
        plan.plan_id,
        "launch-1",
        plugin.id,
        "sha256:" + plugin.artifact_sha256,
        ProcessStatement("host-a", "worker", 0, "old-start", 6),
        obligation.obligation_id,
        obligation.event,
        NOW - 2,
        NOW - 1,
        NOW + 60,
        "old-epoch",
        "sha256:" + "f" * 64,
    )
    envelopes["old-epoch"] = sign(old_statement, key)
    old_attestation = Attestation(
        plan.plan_id,
        "launch-1",
        old_process,
        obligation.obligation_id,
        obligation.event,
        "old-epoch",
        NOW - 1,
        NOW + 60,
        plugin.id,
        "host-runtime",
        old_statement.issuer,
        old_statement.kid,
        old_statement.observed_at,
        old_statement.evidence_digest,
        old_statement.artifact_digest,
    )
    verifier = SignedAttestationVerifier(
        envelopes,
        TrustStore(
            [
                TrustEntry(
                    "urn:ecpa:issuer:scenario",
                    "key-1",
                    key.public_key(),
                    frozenset({"host-runtime"}),
                )
            ]
        ),
    )
    adapter = DeterministicTrafficAdapter(0, predecessor.__dict__)
    gate = ReferenceExposureGate(root / "gate.db", adapter, clock=lambda: NOW)
    coordinator = ActivationCoordinator(
        SQLiteActivationStore(root / "coordinator.db"),
        FakeHostAdapter(processes),
        verifier,
        gate,
        FakeExternalServiceAdapter(),
        clock=lambda: NOW,
    )
    plan_id = coordinator.plan(plan)
    coordinator.prepare(plan_id)
    coordinator.launch(plan_id, "launch-1")
    try:
        if scenario == "partial-worker-evidence-2-of-4":
            for item in attestations[:2]:
                coordinator.observe(plan_id, item, NOW)
            coordinator.commit(plan_id, 0)
        elif scenario == "stale-generation-cas":
            for item in attestations:
                coordinator.observe(plan_id, item, NOW)
            with coordinator.store.connection:
                coordinator.store.connection.execute(
                    "UPDATE meta SET generation=1 WHERE singleton=1"
                )
            coordinator.commit(plan_id, 0)
        elif scenario == "old-epoch-or-replay":
            old_epoch_rejected = False
            try:
                coordinator.observe(plan_id, old_attestation, NOW)
            except ContractError:
                old_epoch_rejected = True
            coordinator.observe(plan_id, attestations[0], NOW)
            replay_rejected = False
            try:
                coordinator.observe(plan_id, attestations[0], NOW)
            except ContractError:
                replay_rejected = True
            if old_epoch_rejected and replay_rejected and adapter.route.generation == 0:
                return "REJECT"
            raise AssertionError("old epoch or nonce replay was accepted")
        else:
            raise ValueError(scenario)
    except ContractError:
        if adapter.route.generation == 0:
            return "REJECT"
        raise
    raise AssertionError(f"coordinator scenario unexpectedly opened: {scenario}")


def execute(scenario: str, path: Path) -> tuple[str, dict[str, Any] | None]:
    if scenario in {
        "stale-generation-cas",
        "partial-worker-evidence-2-of-4",
        "old-epoch-or-replay",
    }:
        path.parent.mkdir(parents=True, exist_ok=True)
        root = path.parent / f"{scenario}-coordinator"
        observed = coordinator_rejection(scenario, root)
        return observed, {"oracle": evaluate_trace(root / "gate.db")}
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
        if scenario == "lease-loss":
            adapter.authority.grant = LeaseGrant("other", 2, NOW + 60)
            gate.open(1, PROOF)
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
            scenario_oracle = (
                detail["oracle"]
                if detail is not None and "oracle" in detail
                else evaluate_trace(path)
            )
            row = {
                "classification": "synthetic/reference",
                "expected": item["expected"],
                "observed": observed,
                "scenario": item["id"],
                "oracle_verdict": scenario_oracle["verdict"],
                "oracle_errors": scenario_oracle["errors"],
            }
            if detail and "reconciled_by" in detail:
                row.update(detail)
            rows.append(row)
            if item["id"] == "happy-open-drain":
                happy_trace = export_trace(path)
                oracle = scenario_oracle
    if any(
        row["expected"] != row["observed"] or row["oracle_verdict"] != "PASS"
        for row in rows
    ):
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
