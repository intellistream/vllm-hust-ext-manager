#!/usr/bin/env python3
"""Exhaust the finite ECPA exposure-transaction abstraction."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import deque
from contextlib import suppress
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class Phase(str, Enum):
    PREDECESSOR_OPEN = "predecessor-open"
    CANDIDATE_STAGED = "candidate-staged"
    CANDIDATE_CLOSED = "candidate-closed"
    OPENING = "opening"
    CANDIDATE_OPEN = "candidate-open"
    DRAINING = "draining"
    RECOVERING = "recovering"
    ROLLED_BACK = "rolled-back"
    FAILED_SAFE = "failed-safe"
    SAFETY_UNKNOWN = "safety-unknown"


class Route(str, Enum):
    PREDECESSOR = "predecessor"
    CANDIDATE = "candidate"
    CLOSED = "closed"
    UNKNOWN = "unknown"


class RejectedTransition(ValueError):
    pass


@dataclass(frozen=True, order=True)
class State:
    phase: Phase
    route: Route
    proof_complete: bool
    lease_valid: bool
    generation: int
    open_intent: bool
    open_receipt: bool


ACTIONS = (
    "stage",
    "observe-complete",
    "close-candidate",
    "open-intent",
    "open-effect",
    "open-receipt",
    "admit-request",
    "start-drain",
    "finish-drain",
    "lose-lease",
    "renew-lease",
    "crash",
    "reconcile",
    "rollback-strong",
    "rollback-failed-closed",
    "rollback-failed-unknown",
)

INVARIANTS = (
    "candidate-admission-requires-proof-lease-generation-and-receipt",
    "candidate-side-effect-before-receipt-never-enables-admission",
    "pre-exposure-phases-preserve-the-predecessor-route",
    "failed-safe-closes-all-routes",
    "safety-unknown-enables-no-admission",
    "strong-rollback-restores-only-the-predecessor",
    "one-route-per-state",
)

ASSUMPTIONS = (
    "one controller serializes durable state transitions",
    "route observations distinguish predecessor, candidate, closed, and unknown",
    "proof completeness and lease validity are evaluated by their declared authorities",
    "rollback-strong requires an independently verified predecessor restore",
)


def initial_state() -> State:
    return State(
        Phase.PREDECESSOR_OPEN,
        Route.PREDECESSOR,
        False,
        True,
        0,
        False,
        False,
    )


def replace(state: State, **changes: object) -> State:
    values = asdict(state)
    values.update(changes)
    return State(**values)


def can_admit(state: State) -> bool:
    if state.route is Route.PREDECESSOR:
        return state.phase in {
            Phase.PREDECESSOR_OPEN,
            Phase.CANDIDATE_STAGED,
            Phase.CANDIDATE_CLOSED,
        }
    return (
        state.route is Route.CANDIDATE
        and state.phase in {Phase.CANDIDATE_OPEN, Phase.DRAINING}
        and state.proof_complete
        and state.lease_valid
        and state.generation == 1
        and state.open_receipt
    )


def transition(state: State, action: str) -> State:
    if action == "stage" and state.phase is Phase.PREDECESSOR_OPEN:
        return replace(state, phase=Phase.CANDIDATE_STAGED)
    if (
        action == "observe-complete"
        and state.phase in {Phase.CANDIDATE_STAGED, Phase.CANDIDATE_CLOSED}
        and state.lease_valid
    ):
        return replace(state, proof_complete=True)
    if action == "close-candidate" and state.phase is Phase.CANDIDATE_STAGED:
        return replace(state, phase=Phase.CANDIDATE_CLOSED)
    if (
        action == "open-intent"
        and state.phase is Phase.CANDIDATE_CLOSED
        and state.proof_complete
        and state.lease_valid
    ):
        return replace(state, phase=Phase.OPENING, open_intent=True)
    if (
        action == "open-effect"
        and state.phase is Phase.OPENING
        and state.route is Route.PREDECESSOR
        and state.open_intent
        and state.proof_complete
        and state.lease_valid
    ):
        return replace(state, route=Route.CANDIDATE)
    if (
        action == "open-receipt"
        and state.phase is Phase.OPENING
        and state.route is Route.CANDIDATE
        and state.proof_complete
        and state.lease_valid
        and state.open_intent
    ):
        return replace(
            state,
            phase=Phase.CANDIDATE_OPEN,
            generation=1,
            open_receipt=True,
        )
    if action == "admit-request" and can_admit(state):
        return state
    if action == "start-drain" and state.phase is Phase.CANDIDATE_OPEN:
        return replace(state, phase=Phase.DRAINING)
    if action == "finish-drain" and state.phase is Phase.DRAINING:
        return replace(state, phase=Phase.CANDIDATE_OPEN)
    if action == "lose-lease" and state.lease_valid:
        if state.route is Route.CANDIDATE:
            return replace(
                state,
                phase=Phase.SAFETY_UNKNOWN,
                route=Route.UNKNOWN,
                lease_valid=False,
            )
        return replace(state, lease_valid=False)
    if (
        action == "renew-lease"
        and not state.lease_valid
        and state.phase
        in {
            Phase.PREDECESSOR_OPEN,
            Phase.CANDIDATE_STAGED,
            Phase.CANDIDATE_CLOSED,
        }
    ):
        return replace(state, lease_valid=True, proof_complete=False)
    if action == "crash" and state.phase in {
        Phase.OPENING,
        Phase.CANDIDATE_OPEN,
        Phase.DRAINING,
    }:
        return replace(state, phase=Phase.RECOVERING)
    if action == "reconcile" and state.phase is Phase.RECOVERING:
        if state.route is Route.UNKNOWN:
            return replace(state, phase=Phase.SAFETY_UNKNOWN)
        if (
            state.route is Route.CANDIDATE
            and state.proof_complete
            and state.lease_valid
        ):
            return replace(
                state,
                phase=Phase.CANDIDATE_OPEN,
                generation=1,
                open_receipt=True,
            )
        return replace(state, phase=Phase.FAILED_SAFE, route=Route.CLOSED)
    rollback_phases = {
        Phase.CANDIDATE_STAGED,
        Phase.CANDIDATE_CLOSED,
        Phase.OPENING,
        Phase.CANDIDATE_OPEN,
        Phase.DRAINING,
    }
    if action == "rollback-strong" and state.phase in rollback_phases:
        return State(
            Phase.ROLLED_BACK,
            Route.PREDECESSOR,
            state.proof_complete,
            state.lease_valid,
            0,
            False,
            False,
        )
    if action == "rollback-failed-closed" and state.phase in rollback_phases:
        return replace(state, phase=Phase.FAILED_SAFE, route=Route.CLOSED)
    if action == "rollback-failed-unknown" and state.phase in rollback_phases:
        return replace(state, phase=Phase.SAFETY_UNKNOWN, route=Route.UNKNOWN)
    raise RejectedTransition(f"{action} is invalid from {state.phase.value}")


def invariant_errors(state: State) -> list[str]:
    errors = []
    if (
        state.route is Route.CANDIDATE
        and state.open_receipt
        and not (state.proof_complete and state.generation == 1 and state.open_intent)
    ):
        errors.append("candidate receipt lacks proof, generation, or intent")
    if (
        state.route is Route.CANDIDATE
        and not state.open_receipt
        and (
            not state.proof_complete
            or not state.lease_valid
            or state.phase not in {Phase.OPENING, Phase.RECOVERING}
            or can_admit(state)
        )
    ):
        errors.append("candidate side effect before receipt enables admission")
    if state.phase in {
        Phase.PREDECESSOR_OPEN,
        Phase.CANDIDATE_STAGED,
        Phase.CANDIDATE_CLOSED,
    } and (state.route is not Route.PREDECESSOR or state.generation != 0):
        errors.append("pre-exposure phase lost predecessor route")
    if state.phase is Phase.FAILED_SAFE and (
        state.route is not Route.CLOSED or can_admit(state)
    ):
        errors.append("failed-safe state did not close admissions")
    if state.phase is Phase.SAFETY_UNKNOWN and can_admit(state):
        errors.append("safety-unknown state admitted a request")
    if state.phase is Phase.ROLLED_BACK and (
        state.route is not Route.PREDECESSOR
        or state.generation != 0
        or state.open_intent
        or state.open_receipt
    ):
        errors.append("strong rollback did not restore predecessor identity")
    if (
        can_admit(state)
        and state.route is Route.CANDIDATE
        and not (state.proof_complete and state.lease_valid and state.open_receipt)
    ):
        errors.append("candidate admission lacks current authority")
    return errors


def state_object(state: State) -> dict[str, object]:
    value = asdict(state)
    value["phase"] = state.phase.value
    value["route"] = state.route.value
    return value


def explore() -> dict[str, object]:
    initial = initial_state()
    queue = deque([(initial, 0)])
    distances = {initial: 0}
    edges = set()
    rejected = set()
    counterexamples = []
    while queue:
        state, depth = queue.popleft()
        for action in ACTIONS:
            try:
                target = transition(state, action)
            except RejectedTransition:
                rejected.add((state, action))
                continue
            errors = invariant_errors(target)
            if errors:
                counterexamples.append(
                    {
                        "action": action,
                        "errors": errors,
                        "source": state_object(state),
                        "target": state_object(target),
                    }
                )
            edges.add((state, action, target))
            if target not in distances:
                distances[target] = depth + 1
                queue.append((target, depth + 1))
    state_rows = sorted(
        (state_object(state) for state in distances),
        key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")),
    )
    edge_rows = sorted(
        (
            {
                "action": action,
                "source": state_object(source),
                "target": state_object(target),
            }
            for source, action, target in edges
        ),
        key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")),
    )
    return {
        "schema": "ecpa-bounded-transaction-model/v1",
        "implementation_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "classification": "exhaustive-finite-abstract-model",
        "formal_real_result": False,
        "fixed_point_reached": True,
        "actions": len(ACTIONS),
        "reachable_states": len(distances),
        "reachable_states_sha256": hashlib.sha256(
            canonical(state_rows).encode()
        ).hexdigest(),
        "valid_edges": len(edges),
        "valid_edges_sha256": hashlib.sha256(canonical(edge_rows).encode()).hexdigest(),
        "rejected_state_action_pairs": len(rejected),
        "maximum_shortest_trace_length": max(distances.values()),
        "invariants": list(INVARIANTS),
        "assumptions": list(ASSUMPTIONS),
        "counterexamples": counterexamples,
    }


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".transaction-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/transaction_model/artifacts/result-summary.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = explore()
    if result["counterexamples"]:
        raise SystemExit("transaction model has invariant counterexamples")
    content = canonical(result)
    if args.check:
        if not args.output.is_file() or args.output.read_text() != content:
            raise SystemExit("transaction model artifact is stale")
    else:
        write_atomic(args.output, content)
    print(
        "transaction model valid: "
        f"{result['reachable_states']} states, {result['valid_edges']} edges, "
        f"{len(result['counterexamples'])} counterexamples"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
