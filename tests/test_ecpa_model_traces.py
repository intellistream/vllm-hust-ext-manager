import pytest

from vllm_hust_ext.ecpa_model import (
    Attestation,
    ContractError,
    ErrorCode,
    EvidenceObligation,
    HostCompatibility,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
    ReferenceModel,
    ResourceClaim,
    State,
)

PLUGIN = PluginIdentity("org.vllm-hust", "p", "1", "a" * 64)
HOST = HostCompatibility("vllm", "0.11", "reference", "1")
PRED = PredecessorSnapshot(7, "old", {"enabled": "old"})
OB = EvidenceObligation("workers-loaded", "worker", "loaded", (0, 1, 2, 3))
CLAIM = ResourceClaim("urn:ecpa:resource:org.vllm-hust.kv-connector", PLUGIN.id)


def proc(i, epoch=1):
    return ProcessIdentity("h", "worker", i, f"s{i}", epoch)


def att(p, nonce, m=None, artifact=PLUGIN.id):
    plan_id = m.plan.plan_id if m else model().plan.plan_id
    return Attestation(
        plan_id, "L1", p, OB.obligation_id, "loaded", nonce, 10, 20, artifact
    )


def model(fallback=False):
    m = ReferenceModel(7)
    m.state = State.RESOLVED
    m.make_plan([PLUGIN], HOST, [CLAIM], [OB], PRED, fallback)
    m.prepare()
    m.launch("L1", [proc(i) for i in range(4)])
    return m


def test_mooncake_wrong_namespace_fails_resolve():
    m = ReferenceModel()
    with pytest.raises(ContractError) as e:
        m.resolve(["vllm_hust.extension_bundles"], "vllm.extension_bundles")
    assert e.value.code is ErrorCode.UNKNOWN_RESOURCE


def test_two_connector_owners_are_explanatory_unsat():
    m = ReferenceModel()
    m.state = State.RESOLVED
    other = ResourceClaim(CLAIM.uri, "plugin:other")
    with pytest.raises(ContractError) as e:
        m.make_plan([PLUGIN], HOST, [CLAIM, other], [OB], PRED)
    assert e.value.code is ErrorCode.RESOURCE_CONFLICT and "vs" in e.value.detail


def test_partial_launch_never_effective_epoch_fences_old_evidence_and_rolls_back():
    m = model()
    m.attest(att(proc(0), "n0", m), 15)
    m.attest(att(proc(1), "n1", m), 15)
    with pytest.raises(ContractError) as e:
        m.commit(7)
    assert (
        e.value.code is ErrorCode.MISSING_PROCESS_EVIDENCE
        and m.state is State.OBSERVING
    )
    m.inventory = (proc(0, 2), proc(1, 2), proc(2, 2), proc(3, 2))
    with pytest.raises(ContractError) as e:
        m.attest(att(proc(2, 1), "old", m), 15)
    assert e.value.code is ErrorCode.STALE_EVIDENCE
    m.rollback("partial launch")
    assert m.state is State.ROLLED_BACK and m.generation == 7


def test_external_lease_needs_proven_fallback_or_rollback():
    m = model(False)
    m.external_lease_lost()
    assert m.state is State.ROLLED_BACK
    m = model(True)
    m.external_lease_lost()
    assert m.state is State.RECONCILE


def test_manager_crash_requires_reobservation_not_evidence_replay():
    m = model()
    m.attest(att(proc(0), "n0", m), 15)
    m.recover_after_crash()
    assert (
        not m.accepted
        and m.state is State.RECONCILE
        and m.store.records[-1]["kind"] == "reobserve-required"
    )
    with pytest.raises(ContractError) as e:
        m.attest(att(proc(0), "n0", m), 15)
    assert e.value.code is ErrorCode.REPLAYED_NONCE


def test_nonce_replay_is_rejected():
    m = model()
    m.attest(att(proc(0), "n0", m), 15)
    with pytest.raises(ContractError) as e:
        m.attest(att(proc(0), "n0", m), 15)
    assert e.value.code is ErrorCode.REPLAYED_NONCE


def test_split_brain_generation_cas_rejected():
    m = model()
    for i in range(4):
        m.attest(att(proc(i), f"n{i}", m), 15)
    with pytest.raises(ContractError) as e:
        m.commit(6)
    assert e.value.code is ErrorCode.CAS_MISMATCH and m.generation == 7


def test_missing_required_inventory_never_counts_as_coverage():
    m = model()
    m.inventory = (proc(0), proc(1))
    for i in range(2):
        m.attest(att(proc(i), f"n{i}", m), 15)
    assert not m.evidence_complete()


@pytest.mark.parametrize("mutation", ["plan", "artifact"])
def test_attestation_is_bound_to_plan_and_artifact(mutation):
    m = model()
    item = att(proc(0), "n0", m)
    if mutation == "plan":
        item = Attestation(
            "plan:sha256:bad",
            item.launch_id,
            item.process,
            item.obligation_id,
            item.event,
            item.nonce,
            item.issued_at,
            item.expires_at,
            item.artifact_id,
        )
    else:
        item = Attestation(
            item.plan_id,
            item.launch_id,
            item.process,
            item.obligation_id,
            item.event,
            item.nonce,
            item.issued_at,
            item.expires_at,
            "plugin:sha256:bad",
        )
    with pytest.raises(ContractError) as e:
        m.attest(item, 15)
    assert e.value.code is ErrorCode.STALE_EVIDENCE


def test_rollback_failure_enters_failed_safe():
    m = model()
    with pytest.raises(ContractError) as e:
        m.rollback("restore failed", succeeds=False)
    assert e.value.code is ErrorCode.ROLLBACK_FAILED and m.state is State.FAILED_SAFE


def test_illegal_prepare_launch_and_commit_transitions_are_rejected():
    m = ReferenceModel()
    for operation in (m.prepare, lambda: m.launch("L", ()), lambda: m.commit(0)):
        with pytest.raises(ContractError) as e:
            operation()
        assert e.value.code is ErrorCode.INVALID_TRANSITION
