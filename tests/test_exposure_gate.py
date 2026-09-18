import importlib.util
import json
from dataclasses import asdict
from pathlib import Path

import pytest
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
    ErrorCode,
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
    State,
)
from vllm_hust_ext.exposure_gate import (
    AdmissionRequest,
    AdmissionResult,
    BehavioralOracleResult,
    DeterministicTrafficAdapter,
    GateError,
    GateState,
    InjectedCrash,
    LeaseAuthority,
    LeaseGrant,
    OpenProof,
    ReferenceExposureGate,
    RollbackClass,
    evaluate_trace,
    export_trace,
)

NOW = 1_800_000_000
PREDECESSOR = {"generation": 0, "plan_id": "old", "rendered_inputs": {"route": "old"}}
GRANT = LeaseGrant("manager", 1, NOW + 60)
PROOF = OpenProof("candidate", 1, 1, "sha256:" + "1" * 64, "sha256:" + "2" * 64, GRANT)


def make_gate(tmp_path, **adapter_options):
    adapter = DeterministicTrafficAdapter(
        0, PREDECESSOR, authority=LeaseAuthority(GRANT), **adapter_options
    )
    gate = ReferenceExposureGate(tmp_path / "gate.db", adapter, clock=lambda: NOW)
    return gate, adapter


def stage_closed(gate):
    assert gate.stage({"plan_id": "candidate"}, PREDECESSOR) == 1
    gate.close(1)


def test_predecessor_continuity_candidate_zero_then_atomic_open_and_drain(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    gate.stage({"plan_id": "candidate"}, PREDECESSOR)
    assert gate.observe(AdmissionRequest("old-inflight", NOW)) == 0
    gate.close(1)
    assert gate.observe(AdmissionRequest("old-during-prepare", NOW + 1)) == 0
    assert (
        gate.connection.execute(
            "SELECT COUNT(*) FROM admission WHERE chosen_generation=1"
        ).fetchone()[0]
        == 0
    )

    fence = gate.open(1, PROOF)
    assert fence.startswith("gate-1-")
    assert gate.observe(AdmissionRequest("new", NOW + 2)) == 1
    assert gate.drain(1) is False
    gate.observe(
        AdmissionRequest("old-inflight", NOW),
        AdmissionResult(NOW + 3, result="ok"),
    )
    gate.observe(
        AdmissionRequest("old-during-prepare", NOW + 1),
        AdmissionResult(NOW + 4, result="ok"),
    )
    assert gate.drain(1) is True
    verdict = evaluate_trace(tmp_path / "gate.db")
    assert verdict["verdict"] == "PASS"
    assert verdict["admission_count"] == 3


def test_checked_reference_trace_matches_exported_logical_rows(tmp_path):
    gate, _adapter = make_gate(tmp_path)
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
    expected = [
        json.loads(line)
        for line in Path("experiments/exposure_gate/artifacts/reference-trace.jsonl")
        .read_text()
        .splitlines()
    ]
    assert export_trace(tmp_path / "gate.db") == expected


def test_checked_scenario_matrix_and_summary_are_complete():
    root = Path("experiments/exposure_gate")
    scenarios = json.loads((root / "scenarios.json").read_text())
    matrix = [
        json.loads(line)
        for line in (root / "artifacts/fault-matrix.jsonl").read_text().splitlines()
    ]
    summary = json.loads((root / "artifacts/result-summary.json").read_text())
    scenario_ids = {item["id"] for item in scenarios["scenarios"]}
    assert {item["scenario"] for item in matrix} == scenario_ids
    assert all(item["observed"] == item["expected"] for item in matrix)
    assert summary["classification"] == "synthetic/reference"
    assert summary["formal_paper_result"] is False


def test_checked_artifacts_are_exact_runner_output(tmp_path):
    module_path = Path("experiments/exposure_gate/reproduce.py")
    spec = importlib.util.spec_from_file_location("exposure_reproduce", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    generated = tmp_path / "generated"
    module.generate(generated)
    checked = Path("experiments/exposure_gate/artifacts")
    for name in (
        "reference-trace.jsonl",
        "fault-matrix.jsonl",
        "result-summary.json",
    ):
        assert (generated / name).read_bytes() == (checked / name).read_bytes()


def test_incomplete_proof_stale_generation_and_lease_loss_never_open(tmp_path):
    gate, adapter = make_gate(tmp_path)
    stage_closed(gate)
    partial = OpenProof(
        "candidate", 1, 0, "sha256:" + "1" * 64, "sha256:" + "2" * 64, GRANT
    )
    with pytest.raises(GateError, match="no durable evidence"):
        gate.open(1, partial)
    with pytest.raises(GateError, match="stale generation"):
        gate.open(2, PROOF)
    adapter.authority.grant = LeaseGrant("other", 2, NOW + 60)
    with pytest.raises(GateError, match="lease lost"):
        gate.open(1, PROOF)
    assert adapter.route.generation == 0


def test_stage_close_open_and_drain_are_idempotent(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    assert gate.stage({"plan_id": "candidate"}, PREDECESSOR) == 1
    assert gate.stage({"plan_id": "candidate"}, PREDECESSOR) == 1
    gate.close(1)
    gate.close(1)
    fence = gate.open(1, PROOF)
    assert gate.open(1, PROOF) == fence
    assert gate.drain(1) is True
    assert gate.drain(1) is True
    with pytest.raises(GateError, match="stale generation close"):
        gate.close(999)
    with pytest.raises(GateError, match="stale generation open"):
        gate.open(999, PROOF)


def test_stage_rejects_wrong_predecessor_fence_and_snapshot(tmp_path):
    gate, adapter = make_gate(tmp_path)
    adapter.route = adapter.route.__class__(0, "wrong-fence", PREDECESSOR)
    with pytest.raises(GateError, match="generation/fence/snapshot"):
        gate.stage({"plan_id": "candidate"}, PREDECESSOR)

    gate.close_store()
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    second, adapter = make_gate(second_dir)
    adapter.route = adapter.route.__class__(0, "fence-0", {"wrong": True})
    with pytest.raises(GateError, match="generation/fence/snapshot"):
        second.stage({"plan_id": "candidate"}, PREDECESSOR)


def test_open_intent_without_side_effect_recovers_failed_safe(tmp_path):
    gate, adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.faults.add("open.after_intent")
    with pytest.raises(InjectedCrash):
        gate.open(1, PROOF)
    assert GateState(gate._row()["state"]) is GateState.OPENING
    gate.close_store()
    restarted = ReferenceExposureGate(tmp_path / "gate.db", adapter, clock=lambda: NOW)
    assert restarted.reconcile() is GateState.FAILED_SAFE
    assert adapter.route.generation is None


def test_crash_before_open_intent_keeps_predecessor_and_closed_candidate(tmp_path):
    gate, adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.faults.add("open.before_intent")
    with pytest.raises(InjectedCrash):
        gate.open(1, PROOF)
    assert GateState(gate._row()["state"]) is GateState.CANDIDATE_CLOSED
    assert adapter.route.generation == 0
    assert (
        gate.connection.execute(
            "SELECT COUNT(*) FROM gate_transition WHERE operation='open'"
        ).fetchone()[0]
        == 0
    )


def test_open_side_effect_without_receipt_reconciles_actual_fence(tmp_path):
    gate, adapter = make_gate(tmp_path, faults={"open.after"})
    stage_closed(gate)
    with pytest.raises(InjectedCrash):
        gate.open(1, PROOF)
    assert adapter.route.generation == 1
    gate.close_store()
    restarted = ReferenceExposureGate(tmp_path / "gate.db", adapter, clock=lambda: NOW)
    assert restarted.reconcile() is GateState.CANDIDATE_OPEN
    assert restarted.observe(AdmissionRequest("after-recovery", NOW + 1)) == 1


def test_rollback_restore_without_receipt_reconciles_strong(tmp_path):
    gate, adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.open(1, PROOF)
    gate.faults.add("rollback.after_effect")
    with pytest.raises(InjectedCrash):
        gate.rollback(1)
    gate.close_store()
    restarted = ReferenceExposureGate(tmp_path / "gate.db", adapter, clock=lambda: NOW)
    assert restarted.reconcile() is GateState.ROLLED_BACK


def test_rollback_wrong_generation_never_classifies_strong(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.open(1, PROOF)
    with pytest.raises(GateError, match="stale generation rollback"):
        gate.rollback(99)


def test_failed_closure_is_honestly_safety_unknown(tmp_path):
    gate, adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.open(1, PROOF)
    adapter.faults.add("close_all")
    outcome = gate.fail_close(1, "compensation failed")
    assert outcome.classification is RollbackClass.SAFETY_UNKNOWN
    assert GateState(gate._row()["state"]) is GateState.SAFETY_UNKNOWN
    assert adapter.route.generation == 1
    with pytest.raises(GateError):
        gate.observe(AdmissionRequest("blocked", NOW + 1))


def test_rollback_restore_and_closure_failure_is_safety_unknown(tmp_path):
    gate, adapter = make_gate(tmp_path, rollback_fails=True)
    stage_closed(gate)
    gate.open(1, PROOF)
    adapter.faults.add("close_all")
    assert gate.rollback(1) is RollbackClass.SAFETY_UNKNOWN
    assert GateState(gate._row()["state"]) is GateState.SAFETY_UNKNOWN
    assert adapter.route.generation == 1


@pytest.mark.parametrize(
    ("options", "behavioral_oracle", "expected", "route"),
    [
        ({}, None, RollbackClass.RESTORED_STRONG, 0),
        (
            {"behavioral_restore": True},
            BehavioralOracleResult(True, "sha256:" + "3" * 64, "test-oracle"),
            RollbackClass.BEHAVIORAL,
            0,
        ),
        ({"rollback_fails": True}, None, RollbackClass.FAILED_SAFE, None),
    ],
)
def test_rollback_classification_is_automatic(
    tmp_path, options, behavioral_oracle, expected, route
):
    gate, adapter = make_gate(tmp_path, **options)
    stage_closed(gate)
    gate.open(1, PROOF)
    assert gate.rollback(1, behavioral_oracle) is expected
    assert adapter.route.generation == route


def test_unknown_actual_route_is_rejected_and_request_is_immutable(tmp_path):
    gate, adapter = make_gate(tmp_path)
    gate.stage({"plan_id": "candidate"}, PREDECESSOR)
    request = AdmissionRequest("request-1", NOW)
    assert gate.observe(request) == 0
    gate.observe(request, AdmissionResult(NOW + 1, result="ok"))
    with pytest.raises(GateError, match="immutable"):
        gate.observe(request, AdmissionResult(NOW + 2, abort="changed"))
    adapter.route = adapter.route.__class__(99, "unknown", None)
    with pytest.raises(GateError, match="unknown route"):
        gate.observe(AdmissionRequest("request-2", NOW + 3))


@pytest.mark.parametrize(
    "result",
    [
        AdmissionResult(NOW - 1, result="early"),
        AdmissionResult(NOW + 1),
        AdmissionResult(NOW + 1, result="ok", abort="also-abort"),
    ],
)
def test_invalid_finish_cannot_complete_or_unblock_drain(tmp_path, result):
    gate, _adapter = make_gate(tmp_path)
    gate.stage({"plan_id": "candidate"}, PREDECESSOR)
    request = AdmissionRequest("old", NOW)
    gate.observe(request)
    gate.close(1)
    gate.open(1, PROOF)
    with pytest.raises(GateError):
        gate.observe(request, result)
    assert gate.drain(1) is False


def test_oracle_fails_closed_for_missing_trace(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    assert evaluate_trace(tmp_path / "gate.db")["verdict"] == "FAIL"
    gate.close_store()


def test_unknown_schema_version_is_rejected(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    gate.stage({"plan_id": "candidate"}, PREDECESSOR)
    with gate.connection:
        gate.connection.execute("UPDATE gate_state SET schema_version=999")
    with pytest.raises(GateError, match="unknown gate schema version"):
        gate.close(1)


def test_oracle_independently_rejects_tampered_generation_and_fence(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.open(1, PROOF)
    gate.observe(AdmissionRequest("candidate", NOW))
    with gate.connection:
        gate.connection.execute(
            "UPDATE admission SET route_epoch='wrong-fence' "
            "WHERE request_id='candidate'"
        )
    verdict = evaluate_trace(tmp_path / "gate.db")
    assert verdict["verdict"] == "FAIL"
    assert verdict["errors"] == ["candidate fence mismatch: candidate"]


def test_oracle_rejects_sequence_gap_missing_intent_and_unknown_transition(tmp_path):
    gate, _adapter = make_gate(tmp_path)
    stage_closed(gate)
    gate.open(1, PROOF)
    with gate.connection:
        gate.connection.execute("DELETE FROM gate_transition WHERE seq=4")
        gate.connection.execute(
            "UPDATE gate_transition SET from_state='UNKNOWN' WHERE seq=5"
        )
    verdict = evaluate_trace(tmp_path / "gate.db")
    assert verdict["verdict"] == "FAIL"
    assert any("sequence gap" in error for error in verdict["errors"])
    assert any("receipt without intent" in error for error in verdict["errors"])


def test_signed_receipt_coverage_is_wired_to_coordinator_open(tmp_path):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    plugin = PluginIdentity("org.vllm-hust", "demo", "1", "a" * 64)
    obligation = EvidenceObligation(
        "workers-invoked", "worker", "invoked", (0, 1, 2, 3)
    )
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
    logical: list[Attestation] = []
    envelopes = {}
    for process in processes:
        nonce = f"nonce-{process.ordinal}"
        statement = AttestationStatement(
            SCHEMA,
            PROFILE,
            "urn:ecpa:issuer:host-a",
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
        logical.append(
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
    verifier = SignedAttestationVerifier(
        envelopes,
        TrustStore(
            [
                TrustEntry(
                    "urn:ecpa:issuer:host-a",
                    "key-1",
                    key.public_key(),
                    frozenset({"host-runtime"}),
                )
            ]
        ),
    )
    adapter = DeterministicTrafficAdapter(0, asdict(predecessor))
    gate = ReferenceExposureGate(tmp_path / "integrated.db", adapter, clock=lambda: NOW)
    coordinator = ActivationCoordinator(
        SQLiteActivationStore(tmp_path / "coordinator.db"),
        FakeHostAdapter(processes),
        verifier,
        gate,
        FakeExternalServiceAdapter(),
        clock=lambda: NOW,
    )
    empty_plan = Plan(
        (plugin,),
        plan.host,
        (),
        (),
        predecessor,
    )
    with pytest.raises(ContractError) as empty_error:
        coordinator.plan(empty_plan)
    assert empty_error.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
    assert (
        coordinator.store.connection.execute(
            "SELECT COUNT(*) FROM activation WHERE plan_id=?", (empty_plan.plan_id,)
        ).fetchone()[0]
        == 0
    )
    plan_id = coordinator.plan(plan)
    coordinator.prepare(plan_id)
    coordinator.launch(plan_id, "launch-1")
    for item in logical[:2]:
        coordinator.observe(plan_id, item, NOW)
    with pytest.raises(ContractError) as caught:
        coordinator.commit(plan_id, 0)
    assert caught.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
    assert adapter.route.generation == 0
    for item in logical[2:]:
        coordinator.observe(plan_id, item, NOW)
    assert coordinator.commit(plan_id, 0) == 1
    assert adapter.route.generation == 1
    assert coordinator._row(plan_id)["state"] == State.EFFECTIVE.value
    coordinator.host.rollback_succeeds = False
    assert coordinator.rollback(plan_id, "host failure") is State.FAILED_SAFE
    assert adapter.route.generation is None
    traffic_receipt = coordinator.store.connection.execute(
        "SELECT detail_json FROM journal WHERE operation='rollback.traffic'"
    ).fetchone()[0]
    assert json.loads(traffic_receipt)["outcome"] == RollbackClass.FAILED_SAFE.value
