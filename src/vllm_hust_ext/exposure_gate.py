"""Single-host durable reference ExposureGate and independent trace oracle."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class GateState(str, Enum):
    PREDECESSOR_OPEN = "PREDECESSOR_OPEN"
    CANDIDATE_STAGED = "CANDIDATE_STAGED"
    CANDIDATE_CLOSED = "CANDIDATE_CLOSED"
    OPENING = "OPENING"
    CANDIDATE_OPEN = "CANDIDATE_OPEN"
    DRAINING = "DRAINING"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED_SAFE = "FAILED_SAFE"


class RollbackClass(str, Enum):
    RESTORED_STRONG = "RESTORED_STRONG"
    BEHAVIORAL = "BEHAVIORAL"
    FAILED_SAFE = "FAILED_SAFE"


class GateError(RuntimeError):
    pass


class InjectedCrash(GateError):
    pass


@dataclass(frozen=True)
class AdmissionRequest:
    request_id: str
    admitted_at: int


@dataclass(frozen=True)
class AdmissionResult:
    finished_at: int
    result: str | None = None
    abort: str | None = None


@dataclass(frozen=True)
class RouteState:
    generation: int | None
    fence: str
    snapshot: dict[str, Any] | None


class DeterministicTrafficAdapter:
    """In-process scheduler admission model with deterministic fault points."""

    def __init__(
        self,
        predecessor_generation: int,
        predecessor_snapshot: dict[str, Any],
        *,
        lease_token: str = "lease-1",
        faults: set[str] | None = None,
        behavioral_restore: bool = False,
        rollback_fails: bool = False,
    ):
        self.route = RouteState(
            predecessor_generation,
            f"fence-{predecessor_generation}",
            predecessor_snapshot,
        )
        self.lease_token = lease_token
        self.faults = set() if faults is None else faults
        self.behavioral_restore = behavioral_restore
        self.rollback_fails = rollback_fails

    def _hit(self, point: str) -> None:
        if point in self.faults:
            self.faults.remove(point)
            raise InjectedCrash(point)

    def close(self, generation: int) -> None:
        self._hit("close")

    def open(self, generation: int, fence: str, snapshot: dict[str, Any]) -> None:
        self._hit("open.before")
        self.route = RouteState(generation, fence, snapshot)
        self._hit("open.after")

    def close_all(self) -> None:
        self.route = RouteState(None, "closed", None)

    def restore(
        self, generation: int, fence: str, snapshot: dict[str, Any]
    ) -> RouteState:
        if self.rollback_fails:
            raise GateError("rollback failed")
        restored = dict(snapshot)
        if self.behavioral_restore:
            restored = {"behaviorally_equivalent": True}
        self.route = RouteState(generation, fence, restored)
        return self.route

    def lease_valid(self, token: str) -> bool:
        return token == self.lease_token


class ReferenceExposureGate:
    """Durable reference gate; not a proxy or Kubernetes readiness check."""

    _ALLOWED = {
        GateState.PREDECESSOR_OPEN: {GateState.CANDIDATE_STAGED},
        GateState.CANDIDATE_STAGED: {
            GateState.CANDIDATE_CLOSED,
            GateState.ROLLED_BACK,
        },
        GateState.CANDIDATE_CLOSED: {GateState.OPENING, GateState.ROLLED_BACK},
        GateState.OPENING: {
            GateState.CANDIDATE_OPEN,
            GateState.FAILED_SAFE,
        },
        GateState.CANDIDATE_OPEN: {
            GateState.DRAINING,
            GateState.ROLLED_BACK,
            GateState.FAILED_SAFE,
        },
        GateState.DRAINING: {
            GateState.CANDIDATE_OPEN,
            GateState.ROLLED_BACK,
            GateState.FAILED_SAFE,
        },
        GateState.ROLLED_BACK: set(),
        GateState.FAILED_SAFE: set(),
    }

    def __init__(
        self,
        path: str | Path,
        traffic: DeterministicTrafficAdapter,
        *,
        clock: Callable[[], int],
        lease_token: str = "lease-1",
        faults: set[str] | None = None,
    ):
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.traffic = traffic
        self.clock = clock
        self.lease_token = lease_token
        self.faults = set() if faults is None else faults
        self._schema()

    def _schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS gate_state(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), state TEXT NOT NULL,
              predecessor_generation INTEGER NOT NULL, candidate_generation INTEGER,
              predecessor_json BLOB NOT NULL, candidate_json BLOB,
              route_generation INTEGER, route_fence TEXT NOT NULL,
              lease_token TEXT NOT NULL, transition_seq INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS gate_transition(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, generation INTEGER NOT NULL,
              kind TEXT NOT NULL, operation TEXT NOT NULL, from_state TEXT,
              to_state TEXT, fence TEXT, at INTEGER NOT NULL,
              detail_json BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS admission(
              request_id TEXT PRIMARY KEY, route_epoch TEXT NOT NULL,
              chosen_generation INTEGER NOT NULL, admitted_at INTEGER NOT NULL,
              finished_at INTEGER, result TEXT, abort TEXT,
              transition_seq INTEGER NOT NULL);
            """
        )
        self.connection.commit()

    @staticmethod
    def _json(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def _row(self) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM gate_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise GateError("gate is not initialized")
        return row

    def _hit(self, point: str) -> None:
        if point in self.faults:
            self.faults.remove(point)
            raise InjectedCrash(point)

    def _append(
        self,
        db: sqlite3.Connection,
        generation: int,
        kind: str,
        operation: str,
        from_state: GateState | None,
        to_state: GateState | None,
        fence: str | None,
        detail: dict[str, Any],
    ) -> int:
        cursor = db.execute(
            "INSERT INTO gate_transition(generation,kind,operation,from_state,"
            "to_state,fence,at,detail_json) VALUES(?,?,?,?,?,?,?,?)",
            (
                generation,
                kind,
                operation,
                None if from_state is None else from_state.value,
                None if to_state is None else to_state.value,
                fence,
                self.clock(),
                self._json(detail),
            ),
        )
        return int(cursor.lastrowid)

    def _transition(
        self,
        db: sqlite3.Connection,
        generation: int,
        target: GateState,
        operation: str,
        kind: str,
        detail: dict[str, Any],
        fence: str | None = None,
    ) -> int:
        row = self._row()
        current = GateState(row["state"])
        if target != current and target not in self._ALLOWED[current]:
            raise GateError(f"invalid gate transition {current.value}->{target.value}")
        seq = self._append(
            db, generation, kind, operation, current, target, fence, detail
        )
        db.execute(
            "UPDATE gate_state SET state=?,transition_seq=? WHERE singleton=1",
            (target.value, seq),
        )
        return seq

    def stage(self, candidate: Any, predecessor: Any) -> int:
        predecessor_value = (
            asdict(predecessor)
            if hasattr(predecessor, "__dataclass_fields__")
            else predecessor
        )
        candidate_value = (
            asdict(candidate)
            if hasattr(candidate, "__dataclass_fields__")
            else candidate
        )
        predecessor_generation = int(predecessor_value["generation"])
        candidate_generation = predecessor_generation + 1
        existing = self.connection.execute("SELECT * FROM gate_state").fetchone()
        if existing is not None:
            if (
                existing["candidate_generation"] == candidate_generation
                and json.loads(existing["candidate_json"]) == candidate_value
            ):
                return candidate_generation
            raise GateError("another candidate is already staged")
        route = self.traffic.route
        if route.generation != predecessor_generation:
            raise GateError("actual predecessor route does not match snapshot")
        with self.connection as db:
            db.execute(
                "INSERT INTO gate_state VALUES(1,?,?,?,?,?,?,?,?,?)",
                (
                    GateState.PREDECESSOR_OPEN.value,
                    predecessor_generation,
                    candidate_generation,
                    self._json(predecessor_value),
                    self._json(candidate_value),
                    route.generation,
                    route.fence,
                    self.lease_token,
                    0,
                ),
            )
            self._transition(
                db,
                candidate_generation,
                GateState.CANDIDATE_STAGED,
                "stage",
                "receipt",
                {"candidate": candidate_value},
            )
        return candidate_generation

    def close(self, generation: int) -> None:
        row = self._row()
        state = GateState(row["state"])
        if state is GateState.CANDIDATE_CLOSED:
            return
        if row["candidate_generation"] != generation:
            raise GateError("stale generation close")
        with self.connection as db:
            self._append(db, generation, "intent", "close", state, None, None, {})
        self._hit("close.after_intent")
        self.traffic.close(generation)
        with self.connection as db:
            self._transition(
                db, generation, GateState.CANDIDATE_CLOSED, "close", "receipt", {}
            )

    def open(self, generation: int, proof: dict[str, Any]) -> str:
        row = self._row()
        if GateState(row["state"]) is GateState.CANDIDATE_OPEN:
            return str(row["route_fence"])
        if GateState(row["state"]) is GateState.OPENING:
            raise GateError("opening outcome requires reconcile")
        required = {
            "signed_receipts_verified",
            "required_process_coverage",
            "lease_valid",
            "generation_cas",
        }
        if any(proof.get(name) is not True for name in required):
            raise GateError("open proof is incomplete")
        if row["candidate_generation"] != generation:
            raise GateError("stale generation open")
        if not self.traffic.lease_valid(str(proof.get("lease_token", ""))):
            raise GateError("lease lost")
        fence = f"gate-{generation}-{row['transition_seq'] + 1}"
        self._hit("open.before_intent")
        with self.connection as db:
            self._transition(
                db,
                generation,
                GateState.OPENING,
                "open",
                "intent",
                proof,
                fence,
            )
        self._hit("open.after_intent")
        candidate = json.loads(row["candidate_json"])
        self.traffic.open(generation, fence, candidate)
        self._hit("open.after_side_effect")
        with self.connection as db:
            seq = self._transition(
                db,
                generation,
                GateState.CANDIDATE_OPEN,
                "open",
                "receipt",
                {"actual_route": generation},
                fence,
            )
            db.execute(
                "UPDATE gate_state SET route_generation=?,route_fence=?,"
                "transition_seq=? WHERE singleton=1",
                (generation, fence, seq),
            )
        return fence

    def drain(self, generation: int) -> bool:
        row = self._row()
        if row["candidate_generation"] != generation:
            raise GateError("stale generation drain")
        state = GateState(row["state"])
        if state is not GateState.DRAINING:
            with self.connection as db:
                self._transition(
                    db, generation, GateState.DRAINING, "drain", "intent", {}
                )
        unfinished = self.connection.execute(
            "SELECT COUNT(*) FROM admission WHERE chosen_generation=? "
            "AND finished_at IS NULL",
            (row["predecessor_generation"],),
        ).fetchone()[0]
        if unfinished:
            return False
        with self.connection as db:
            self._transition(
                db,
                generation,
                GateState.CANDIDATE_OPEN,
                "drain",
                "receipt",
                {"unfinished_predecessor": 0},
            )
        return True

    def observe(
        self, request: AdmissionRequest, result: AdmissionResult | None = None
    ) -> int:
        existing = self.connection.execute(
            "SELECT * FROM admission WHERE request_id=?", (request.request_id,)
        ).fetchone()
        if existing is None:
            actual = self.traffic.route
            row = self._row()
            if actual.generation is None or actual.fence == "closed":
                raise GateError("traffic is failed safe")
            if (
                actual.generation != row["route_generation"]
                or actual.fence != row["route_fence"]
            ):
                raise GateError("unknown route state")
            with self.connection as db:
                db.execute(
                    "INSERT INTO admission VALUES(?,?,?,?,?,?,?,?)",
                    (
                        request.request_id,
                        actual.fence,
                        actual.generation,
                        request.admitted_at,
                        None,
                        None,
                        None,
                        row["transition_seq"],
                    ),
                )
            existing = self.connection.execute(
                "SELECT * FROM admission WHERE request_id=?", (request.request_id,)
            ).fetchone()
        if result is not None:
            if existing["finished_at"] is not None:
                if (existing["result"], existing["abort"]) != (
                    result.result,
                    result.abort,
                ):
                    raise GateError("immutable request result mismatch")
            else:
                with self.connection as db:
                    db.execute(
                        "UPDATE admission SET finished_at=?,result=?,abort=? "
                        "WHERE request_id=?",
                        (
                            result.finished_at,
                            result.result,
                            result.abort,
                            request.request_id,
                        ),
                    )
        return int(existing["chosen_generation"])

    def reconcile(self) -> GateState:
        row = self._row()
        state = GateState(row["state"])
        if state is not GateState.OPENING:
            return state
        generation = int(row["candidate_generation"])
        intent = self.connection.execute(
            "SELECT * FROM gate_transition WHERE operation='open' AND kind='intent' "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        actual = self.traffic.route
        if actual.generation == generation and actual.fence == intent["fence"]:
            with self.connection as db:
                seq = self._transition(
                    db,
                    generation,
                    GateState.CANDIDATE_OPEN,
                    "open.reconcile",
                    "receipt",
                    {"queried_actual_route": generation},
                    actual.fence,
                )
                db.execute(
                    "UPDATE gate_state SET route_generation=?,route_fence=?,"
                    "transition_seq=? WHERE singleton=1",
                    (generation, actual.fence, seq),
                )
            return GateState.CANDIDATE_OPEN
        with self.connection as db:
            self._append(
                db,
                generation,
                "intent",
                "open.reconcile.close_all",
                GateState.OPENING,
                None,
                "closed",
                {"queried_actual_generation": actual.generation},
            )
        self.traffic.close_all()
        with self.connection as db:
            self._transition(
                db,
                generation,
                GateState.FAILED_SAFE,
                "open.reconcile",
                "receipt",
                {"actual_generation": actual.generation, "action": "close_all"},
            )
            db.execute(
                "UPDATE gate_state SET route_generation=NULL,route_fence='closed' "
                "WHERE singleton=1"
            )
        return GateState.FAILED_SAFE

    def rollback(
        self, generation: int, behavioral_oracle: bool = False
    ) -> RollbackClass:
        row = self._row()
        predecessor = json.loads(row["predecessor_json"])
        predecessor_generation = int(row["predecessor_generation"])
        predecessor_fence = f"fence-{predecessor_generation}"
        with self.connection as db:
            self._append(
                db,
                generation,
                "intent",
                "rollback",
                GateState(row["state"]),
                None,
                predecessor_fence,
                {},
            )
        try:
            actual = self.traffic.restore(
                predecessor_generation, predecessor_fence, predecessor
            )
        except Exception:
            self.traffic.close_all()
            outcome = RollbackClass.FAILED_SAFE
        else:
            if actual.snapshot == predecessor and actual.fence == predecessor_fence:
                outcome = RollbackClass.RESTORED_STRONG
            elif behavioral_oracle and self.traffic.behavioral_restore:
                outcome = RollbackClass.BEHAVIORAL
            else:
                self.traffic.close_all()
                outcome = RollbackClass.FAILED_SAFE
        target = (
            GateState.ROLLED_BACK
            if outcome is not RollbackClass.FAILED_SAFE
            else GateState.FAILED_SAFE
        )
        with self.connection as db:
            self._transition(
                db,
                generation,
                target,
                "rollback",
                "receipt",
                {"classification": outcome.value},
            )
            route = self.traffic.route
            db.execute(
                "UPDATE gate_state SET route_generation=?,route_fence=? "
                "WHERE singleton=1",
                (route.generation, route.fence),
            )
        return outcome

    def close_store(self) -> None:
        self.connection.close()


def evaluate_trace(path: str | Path) -> dict[str, Any]:
    """Offline oracle over raw rows; does not call gate decision methods."""
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    transitions = db.execute("SELECT * FROM gate_transition ORDER BY seq").fetchall()
    admissions = db.execute("SELECT * FROM admission ORDER BY admitted_at").fetchall()
    state = db.execute("SELECT * FROM gate_state WHERE singleton=1").fetchone()
    errors: list[str] = []
    open_receipts = [
        row
        for row in transitions
        if row["kind"] == "receipt"
        and row["to_state"] == GateState.CANDIDATE_OPEN.value
        and row["operation"].startswith("open")
    ]
    candidate = None if state is None else state["candidate_generation"]
    predecessor = None if state is None else state["predecessor_generation"]
    first_open_seq = None if not open_receipts else open_receipts[0]["seq"]
    open_fence = None if not open_receipts else open_receipts[0]["fence"]
    if state is None or not transitions:
        errors.append("missing gate state or transitions")
    seen: dict[str, int] = {}
    for row in admissions:
        prior = seen.setdefault(row["request_id"], row["chosen_generation"])
        if prior != row["chosen_generation"]:
            errors.append(f"request {row['request_id']} crossed generation")
        if (
            candidate is not None
            and row["chosen_generation"] == candidate
            and (first_open_seq is None or row["transition_seq"] < first_open_seq)
        ):
            errors.append(f"candidate admitted before open: {row['request_id']}")
        if (
            predecessor is not None
            and row["chosen_generation"] == predecessor
            and first_open_seq is not None
            and row["transition_seq"] >= first_open_seq
        ):
            errors.append(f"predecessor admitted after open: {row['request_id']}")
        if row["chosen_generation"] not in {candidate, predecessor}:
            errors.append(f"unknown generation: {row['request_id']}")
        if not row["route_epoch"]:
            errors.append(f"missing route fence: {row['request_id']}")
        if row["chosen_generation"] == candidate and row["route_epoch"] != open_fence:
            errors.append(f"candidate fence mismatch: {row['request_id']}")
        if (
            row["chosen_generation"] == predecessor
            and row["route_epoch"] != f"fence-{predecessor}"
        ):
            errors.append(f"predecessor fence mismatch: {row['request_id']}")
    verdict = "PASS" if not errors else "FAIL"
    result = {
        "schema": "ecpa-exposure-oracle/0.1",
        "verdict": verdict,
        "errors": errors,
        "transition_count": len(transitions) if transitions else None,
        "admission_count": len(admissions) if admissions else None,
        "candidate_generation": candidate,
        "predecessor_generation": predecessor,
        "first_candidate_open_seq": first_open_seq,
    }
    db.close()
    return result


def export_trace(path: str | Path) -> list[dict[str, Any]]:
    """Export exact logical rows in deterministic JSON-serializable form."""
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    exported: list[dict[str, Any]] = []
    for row in db.execute("SELECT * FROM gate_transition ORDER BY seq"):
        item = dict(row)
        item["detail"] = json.loads(item.pop("detail_json"))
        item["classification"] = "synthetic/reference"
        exported.append(item)
    for row in db.execute("SELECT * FROM admission ORDER BY admitted_at"):
        item = dict(row)
        item["type"] = "admission"
        item["classification"] = "synthetic/reference"
        exported.append(item)
    db.close()
    return exported
