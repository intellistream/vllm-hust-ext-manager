import pytest

from vllm_hust_ext.durable_coordinator import (
    ActivationCoordinator,
    FakeEvidenceIssuer,
    FakeEvidenceVerifier,
    FakeExternalServiceAdapter,
    FakeHostAdapter,
    FakeTrafficGate,
    FaultInjector,
    SQLiteActivationStore,
)
from vllm_hust_ext.ecpa_model import (
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

NOW = 100
PLUGIN = PluginIdentity("org.vllm-hust", "demo", "1", "a" * 64)
OBLIGATION = EvidenceObligation("workers-loaded", "worker", "loaded", (0, 1))


def process(ordinal: int, epoch: int = 1) -> ProcessIdentity:
    return ProcessIdentity("host-a", "worker", ordinal, f"start-{ordinal}", epoch)


def plan(generation: int = 0, fallback: bool = False) -> Plan:
    return Plan(
        (PLUGIN,),
        HostCompatibility("vllm", "0.28", "fake", "1"),
        (ResourceClaim("urn:ecpa:resource:org.vllm-hust.demo", PLUGIN.id),),
        (OBLIGATION,),
        PredecessorSnapshot(generation, "predecessor", {"route": "old"}),
        fallback,
    )


def coordinator(
    path,
    *,
    inventory=None,
    faults=(),
    rollback_succeeds=True,
    lease_valid=True,
    traffic=None,
):
    if inventory is None:
        inventory = (process(0), process(1))
    store = SQLiteActivationStore(path)
    host = FakeHostAdapter(tuple(inventory), rollback_succeeds=rollback_succeeds)
    gate = traffic or FakeTrafficGate()
    service = FakeExternalServiceAdapter(lease_valid)
    manager = ActivationCoordinator(
        store,
        host,
        FakeEvidenceVerifier(),
        gate,
        service,
        FaultInjector(set(faults)),
        clock=lambda: NOW,
    )
    return manager, store, host, gate, service


def prepare_and_launch(manager, activation_plan=None):
    activation_plan = activation_plan or plan()
    plan_id = manager.plan(activation_plan)
    manager.prepare(plan_id)
    manager.launch(plan_id, "launch-1")
    return activation_plan, plan_id


def attest_all(manager, activation_plan, plan_id, epoch=1):
    issuer = FakeEvidenceIssuer()
    for ordinal in OBLIGATION.required_ordinals:
        item = issuer.issue(
            activation_plan,
            "launch-1",
            process(ordinal, epoch),
            OBLIGATION,
            f"nonce-{epoch}-{ordinal}",
            NOW,
        )
        manager.observe(plan_id, item, NOW)


def test_successful_activation_is_durable_and_gated(tmp_path):
    path = tmp_path / "coordinator.db"
    manager, store, _, gate, _ = coordinator(path)
    activation_plan, plan_id = prepare_and_launch(manager)
    assert gate.active_plan_id == "predecessor"
    attest_all(manager, activation_plan, plan_id)
    assert manager.commit(plan_id, 0) == 1
    assert gate.active_plan_id == plan_id
    assert manager.status(plan_id)["state"] == State.EFFECTIVE.value
    assert store.connection.execute("SELECT count(*) FROM journal").fetchone()[0] > 0
    store.close()


@pytest.mark.parametrize(
    ("fault", "side_effect"),
    [("prepare.after_wal", False), ("prepare.after_side_effect", True)],
)
def test_prepare_crash_recovers_without_effective(tmp_path, fault, side_effect):
    path = tmp_path / f"{fault}.db"
    manager, store, host, gate, _ = coordinator(path, faults=(fault,))
    plan_id = manager.plan(plan())
    with pytest.raises(RuntimeError, match="injected fault"):
        manager.prepare(plan_id)
    assert host.prepared is side_effect
    store.close()

    restarted, restarted_store, _, restarted_gate, _ = coordinator(path, traffic=gate)
    assert restarted.recover(plan_id) is State.RECONCILE
    assert restarted_gate.active_plan_id == "predecessor"
    assert restarted.status(plan_id)["state"] != State.EFFECTIVE.value
    restarted_store.close()


def test_commit_side_effect_without_receipt_restores_predecessor_on_restart(tmp_path):
    path = tmp_path / "commit-crash.db"
    manager, store, _, gate, _ = coordinator(path, faults=("commit.after_side_effect",))
    activation_plan, plan_id = prepare_and_launch(manager)
    attest_all(manager, activation_plan, plan_id)
    with pytest.raises(RuntimeError, match="injected fault"):
        manager.commit(plan_id, 0)
    assert gate.active_plan_id == plan_id
    store.close()

    restarted, restarted_store, _, _, _ = coordinator(path, traffic=gate)
    assert restarted.recover(plan_id) is State.RECONCILE
    assert gate.active_plan_id == "predecessor"
    assert restarted.status(plan_id)["state"] != State.EFFECTIVE.value
    restarted_store.close()


def test_partial_worker_inventory_cannot_commit(tmp_path):
    manager, store, _, gate, _ = coordinator(
        tmp_path / "partial.db", inventory=(process(0),)
    )
    activation_plan, plan_id = prepare_and_launch(manager)
    issuer = FakeEvidenceIssuer()
    manager.observe(
        plan_id,
        issuer.issue(
            activation_plan,
            "launch-1",
            process(0),
            OBLIGATION,
            "partial",
            NOW,
        ),
        NOW,
    )
    with pytest.raises(ContractError) as error:
        manager.commit(plan_id, 0)
    assert error.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
    assert gate.active_plan_id == "predecessor"
    store.close()


def test_epoch_change_invalidates_all_prior_evidence(tmp_path):
    manager, store, _, _, _ = coordinator(tmp_path / "epoch.db")
    activation_plan, plan_id = prepare_and_launch(manager)
    attest_all(manager, activation_plan, plan_id)
    manager.refresh_inventory(plan_id, (process(0, 2), process(1, 2)))
    with pytest.raises(ContractError) as error:
        manager.commit(plan_id, 0)
    assert error.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
    attest_all(manager, activation_plan, plan_id, epoch=2)
    assert manager.commit(plan_id, 0) == 1
    store.close()


def test_nonce_unique_constraint_survives_restart(tmp_path):
    path = tmp_path / "nonce.db"
    manager, store, _, _, _ = coordinator(path)
    activation_plan, plan_id = prepare_and_launch(manager)
    issuer = FakeEvidenceIssuer()
    item = issuer.issue(
        activation_plan,
        "launch-1",
        process(0),
        OBLIGATION,
        "durable-nonce",
        NOW,
    )
    manager.observe(plan_id, item, NOW)
    store.close()
    restarted, restarted_store, _, _, _ = coordinator(path)
    with pytest.raises(ContractError) as error:
        restarted.observe(plan_id, item, NOW)
    assert error.value.code is ErrorCode.REPLAYED_NONCE
    restarted_store.close()


def test_restart_requires_fresh_reobservation(tmp_path):
    path = tmp_path / "restart.db"
    manager, store, _, _, _ = coordinator(path)
    activation_plan, plan_id = prepare_and_launch(manager)
    attest_all(manager, activation_plan, plan_id)
    store.close()

    restarted, restarted_store, _, gate, _ = coordinator(path)
    assert restarted.recover(plan_id) is State.RECONCILE
    restarted.resume_observing(plan_id)
    with pytest.raises(ContractError) as error:
        restarted.commit(plan_id, 0)
    assert error.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
    assert gate.active_plan_id == "predecessor"
    restarted_store.close()


def test_stale_generation_cas_is_atomic(tmp_path):
    manager, store, _, gate, _ = coordinator(tmp_path / "cas.db")
    activation_plan = plan(generation=0)
    _, plan_id = prepare_and_launch(manager, activation_plan)
    attest_all(manager, activation_plan, plan_id)
    with store.connection:
        store.connection.execute("UPDATE meta SET generation=1 WHERE singleton=1")
    with pytest.raises(ContractError) as error:
        manager.commit(plan_id, 0)
    assert error.value.code is ErrorCode.CAS_MISMATCH
    assert manager.status(plan_id)["state"] == State.OBSERVING.value
    assert gate.active_plan_id == "predecessor"
    store.close()


def test_external_lease_loss_rolls_back_without_proven_fallback(tmp_path):
    manager, store, _, gate, service = coordinator(tmp_path / "lease.db")
    activation_plan, plan_id = prepare_and_launch(manager)
    attest_all(manager, activation_plan, plan_id)
    service.valid = False
    with pytest.raises(ContractError) as error:
        manager.commit(plan_id, 0)
    assert error.value.code is ErrorCode.EXTERNAL_LEASE_INVALID
    assert manager.status(plan_id)["state"] == State.ROLLED_BACK.value
    assert gate.active_plan_id == "predecessor"
    store.close()


def test_rollback_compensation_failure_enters_failed_safe(tmp_path):
    manager, store, _, _, _ = coordinator(
        tmp_path / "rollback.db", rollback_succeeds=False
    )
    _, plan_id = prepare_and_launch(manager)
    with pytest.raises(ContractError) as error:
        manager.rollback(plan_id, "injected compensation failure")
    assert error.value.code is ErrorCode.ROLLBACK_FAILED
    assert manager.status(plan_id)["state"] == State.FAILED_SAFE.value
    outcome = store.connection.execute(
        "SELECT success FROM rollback_outcome WHERE plan_id=?", (plan_id,)
    ).fetchone()
    assert outcome[0] == 0
    store.close()


def test_invalid_transition_has_stable_error(tmp_path):
    manager, store, _, _, _ = coordinator(tmp_path / "transition.db")
    plan_id = manager.plan(plan())
    with pytest.raises(ContractError) as error:
        manager.launch(plan_id, "too-early")
    assert error.value.code is ErrorCode.INVALID_TRANSITION
    assert "Planned -> Launching" in error.value.detail
    store.close()
