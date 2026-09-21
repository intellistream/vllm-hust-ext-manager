from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "experiments/transaction_model/explore.py"
ARTIFACT_PATH = ROOT / "experiments/transaction_model/artifacts/result-summary.json"


def load_model():
    spec = importlib.util.spec_from_file_location("transaction_model", MODEL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_finite_transaction_model_reaches_fixed_point_without_counterexample() -> None:
    model = load_model()
    result = model.explore()

    assert result["classification"] == "exhaustive-finite-abstract-model"
    assert result["formal_real_result"] is False
    assert result["fixed_point_reached"] is True
    assert result["reachable_states"] > 10
    assert result["valid_edges"] > result["reachable_states"]
    assert result["rejected_state_action_pairs"] > result["valid_edges"]
    assert result["counterexamples"] == []


def test_checked_transaction_model_artifact_is_exact() -> None:
    model = load_model()
    assert ARTIFACT_PATH.read_text() == model.canonical(model.explore())


def test_candidate_effect_before_receipt_cannot_admit() -> None:
    model = load_model()
    state = model.initial_state()
    for action in (
        "stage",
        "observe-complete",
        "close-candidate",
        "open-intent",
        "open-effect",
    ):
        state = model.transition(state, action)

    assert state.route is model.Route.CANDIDATE
    assert state.open_receipt is False
    assert model.can_admit(state) is False
    with pytest.raises(model.RejectedTransition):
        model.transition(state, "admit-request")


def test_crash_reconciliation_requires_current_proof_and_lease() -> None:
    model = load_model()
    state = model.initial_state()
    for action in (
        "stage",
        "observe-complete",
        "close-candidate",
        "open-intent",
        "open-effect",
        "crash",
        "lose-lease",
    ):
        state = model.transition(state, action)

    assert state.phase is model.Phase.SAFETY_UNKNOWN
    assert state.route is model.Route.UNKNOWN
    assert model.can_admit(state) is False


def test_lease_renewal_invalidates_old_proof() -> None:
    model = load_model()
    state = model.initial_state()
    for action in (
        "stage",
        "observe-complete",
        "close-candidate",
        "lose-lease",
        "renew-lease",
    ):
        state = model.transition(state, action)

    assert state.lease_valid is True
    assert state.proof_complete is False
    with pytest.raises(model.RejectedTransition):
        model.transition(state, "open-intent")


def test_open_effect_rechecks_lease_after_intent() -> None:
    model = load_model()
    state = model.initial_state()
    for action in (
        "stage",
        "observe-complete",
        "close-candidate",
        "open-intent",
        "lose-lease",
    ):
        state = model.transition(state, action)

    with pytest.raises(model.RejectedTransition):
        model.transition(state, "open-effect")


@pytest.mark.parametrize(
    "actions",
    (
        ("stage",),
        ("stage", "close-candidate"),
        ("stage", "observe-complete", "close-candidate", "open-intent"),
        (
            "stage",
            "observe-complete",
            "close-candidate",
            "open-intent",
            "open-effect",
        ),
    ),
)
def test_strong_rollback_is_legal_before_commit(actions: tuple[str, ...]) -> None:
    model = load_model()
    state = model.initial_state()
    for action in actions:
        state = model.transition(state, action)

    state = model.transition(state, "rollback-strong")

    assert state.phase is model.Phase.ROLLED_BACK
    assert state.route is model.Route.PREDECESSOR
    assert state.generation == 0
    assert model.can_admit(state) is False


def test_artifact_cannot_be_relabelled_formal_real() -> None:
    artifact = json.loads(ARTIFACT_PATH.read_text())
    artifact["formal_real_result"] = True

    assert artifact != load_model().explore()
