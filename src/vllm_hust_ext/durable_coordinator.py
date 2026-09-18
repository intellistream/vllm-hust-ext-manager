"""SQLite-backed single-host ECPA activation coordinator reference MVP."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from .ecpa_model import (
    Attestation,
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
    canonical_bytes,
)

TRANSITIONS: dict[State, frozenset[State]] = {
    State.INTENT: frozenset({State.PLANNED}),
    State.PLANNED: frozenset({State.PREPARING}),
    State.PREPARING: frozenset({State.PREPARED, State.RECONCILE}),
    State.PREPARED: frozenset({State.LAUNCHING, State.ROLLBACK}),
    State.LAUNCHING: frozenset({State.OBSERVING, State.RECONCILE}),
    State.OBSERVING: frozenset(
        {State.COMMIT_READY, State.DEGRADED, State.RECONCILE, State.ROLLBACK}
    ),
    State.COMMIT_READY: frozenset(
        {State.EFFECTIVE, State.RECONCILE, State.FAILED_SAFE}
    ),
    State.EFFECTIVE: frozenset({State.DEGRADED, State.ROLLBACK}),
    State.DEGRADED: frozenset({State.RECONCILE, State.ROLLBACK}),
    State.RECONCILE: frozenset({State.OBSERVING, State.ROLLBACK, State.FAILED_SAFE}),
    State.ROLLBACK: frozenset(
        {State.ROLLED_BACK, State.FAILED_SAFE, State.SAFETY_UNKNOWN}
    ),
    State.ROLLED_BACK: frozenset(),
    State.FAILED_SAFE: frozenset(),
    State.SAFETY_UNKNOWN: frozenset(),
}


class HostAdapter(Protocol):
    def prepare(self, plan: Plan) -> dict[str, Any]: ...

    def launch(self, plan: Plan, launch_id: str) -> Iterable[ProcessIdentity]: ...

    def rollback(self, predecessor: PredecessorSnapshot) -> dict[str, Any]: ...


class EvidenceVerifier(Protocol):
    def verify(self, attestation: Attestation, now: int, plan: Plan) -> None: ...


class EvidenceIssuer(Protocol):
    def issue(
        self,
        plan: Plan,
        launch_id: str,
        process: ProcessIdentity,
        obligation: EvidenceObligation,
        nonce: str,
        now: int,
    ) -> Attestation: ...


class TrafficGate(Protocol):
    def hold_predecessor(self, predecessor: PredecessorSnapshot) -> None: ...

    def activate(self, plan: Plan) -> None: ...

    def restore(self, predecessor: PredecessorSnapshot) -> None: ...


class ExternalServiceAdapter(Protocol):
    def lease_valid(self, plan: Plan) -> bool: ...


@dataclass
class FaultInjector:
    points: set[str]

    def hit(self, point: str) -> None:
        if point in self.points:
            self.points.remove(point)
            raise RuntimeError(f"injected fault: {point}")


@dataclass
class FakeHostAdapter:
    inventory: tuple[ProcessIdentity, ...]
    prepared: bool = False
    launched: bool = False
    rollback_succeeds: bool = True

    def prepare(self, plan: Plan) -> dict[str, Any]:
        self.prepared = True
        return {"prepared": True, "plan_id": plan.plan_id}

    def launch(self, plan: Plan, launch_id: str) -> Iterable[ProcessIdentity]:
        self.launched = True
        return self.inventory

    def rollback(self, predecessor: PredecessorSnapshot) -> dict[str, Any]:
        if not self.rollback_succeeds:
            raise RuntimeError("deterministic rollback failure")
        self.launched = False
        return {"restored_generation": predecessor.generation}


@dataclass
class FakeTrafficGate:
    active_plan_id: str | None = None
    predecessor_plan_id: str | None = None

    def hold_predecessor(self, predecessor: PredecessorSnapshot) -> None:
        self.active_plan_id = predecessor.plan_id
        self.predecessor_plan_id = predecessor.plan_id

    def activate(self, plan: Plan) -> None:
        self.active_plan_id = plan.plan_id

    def restore(self, predecessor: PredecessorSnapshot) -> None:
        self.active_plan_id = predecessor.plan_id


class FakeEvidenceVerifier:
    def verify(self, attestation: Attestation, now: int, plan: Plan) -> None:
        if attestation.authority != "host-runtime":
            raise ContractError(ErrorCode.AUTHORITY_VIOLATION, attestation.authority)
        if attestation.issued_at > now or attestation.expires_at < now:
            raise ContractError(ErrorCode.STALE_EVIDENCE, attestation.nonce)


class FakeEvidenceIssuer:
    def issue(
        self,
        plan: Plan,
        launch_id: str,
        process: ProcessIdentity,
        obligation: EvidenceObligation,
        nonce: str,
        now: int,
    ) -> Attestation:
        return Attestation(
            plan.plan_id,
            launch_id,
            process,
            obligation.obligation_id,
            obligation.event,
            nonce,
            now,
            now + 60,
            plan.plugins[0].id,
        )


@dataclass
class FakeExternalServiceAdapter:
    valid: bool = True

    def lease_valid(self, plan: Plan) -> bool:
        return self.valid


def _plan_from_json(raw: str) -> Plan:
    value = json.loads(raw)
    return Plan(
        tuple(PluginIdentity(**item) for item in value["plugins"]),
        HostCompatibility(**value["host"]),
        tuple(ResourceClaim(**item) for item in value["claims"]),
        tuple(
            EvidenceObligation(
                item["obligation_id"],
                item["role"],
                item["event"],
                tuple(item["required_ordinals"]),
            )
            for item in value["obligations"]
        ),
        PredecessorSnapshot(**value["predecessor"]),
        value.get("fallback_proven", False),
    )


class SQLiteActivationStore:
    """Reference persistence choice; SQLite is not required by ECPA."""

    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self._schema()

    def _schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              generation INTEGER NOT NULL, manager_epoch INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO meta VALUES (1, 0, 0);
            CREATE TABLE IF NOT EXISTS activation (
              plan_id TEXT PRIMARY KEY, plan_json BLOB NOT NULL,
              state TEXT NOT NULL, launch_id TEXT,
              predecessor_json BLOB NOT NULL, created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS journal (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL,
              kind TEXT NOT NULL, operation TEXT NOT NULL,
              detail_json BLOB NOT NULL, created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inventory (
              plan_id TEXT NOT NULL, host TEXT NOT NULL, role TEXT NOT NULL,
              ordinal INTEGER NOT NULL, start_id TEXT NOT NULL, epoch INTEGER NOT NULL,
              PRIMARY KEY(plan_id, role, ordinal)
            );
            CREATE TABLE IF NOT EXISTS evidence (
              nonce TEXT PRIMARY KEY, plan_id TEXT NOT NULL, launch_id TEXT NOT NULL,
              process_key TEXT NOT NULL, role TEXT NOT NULL, ordinal INTEGER NOT NULL,
              epoch INTEGER NOT NULL, obligation_id TEXT NOT NULL, event TEXT NOT NULL,
              issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
              artifact_id TEXT NOT NULL, authority TEXT NOT NULL,
              manager_epoch INTEGER NOT NULL, valid INTEGER NOT NULL,
              issuer TEXT NOT NULL DEFAULT '', kid TEXT NOT NULL DEFAULT '',
              observed_at INTEGER NOT NULL DEFAULT 0,
              evidence_digest TEXT NOT NULL DEFAULT '',
              artifact_digest TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS rollback_outcome (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL,
              success INTEGER NOT NULL, detail_json BLOB NOT NULL,
              created_at INTEGER NOT NULL
            );
            """
        )
        columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(evidence)")
        }
        migrations = {
            "issuer": "TEXT NOT NULL DEFAULT ''",
            "kid": "TEXT NOT NULL DEFAULT ''",
            "observed_at": "INTEGER NOT NULL DEFAULT 0",
            "evidence_digest": "TEXT NOT NULL DEFAULT ''",
            "artifact_digest": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in migrations.items():
            if name not in columns:
                self.connection.execute(
                    f"ALTER TABLE evidence ADD COLUMN {name} {definition}"
                )
        self.connection.commit()

    def transaction(self) -> sqlite3.Connection:
        return self.connection

    def boot(self) -> int:
        with self.connection:
            self.connection.execute(
                "UPDATE meta SET manager_epoch=manager_epoch+1 WHERE singleton=1"
            )
            epoch = self.connection.execute(
                "SELECT manager_epoch FROM meta WHERE singleton=1"
            ).fetchone()[0]
            self.connection.execute("UPDATE evidence SET valid=0")
        return int(epoch)

    def close(self) -> None:
        self.connection.close()


class ActivationCoordinator:
    def __init__(
        self,
        store: SQLiteActivationStore,
        host: HostAdapter,
        verifier: EvidenceVerifier,
        traffic: TrafficGate,
        external: ExternalServiceAdapter,
        faults: FaultInjector | None = None,
        clock: Any = time.time,
    ):
        self.store = store
        self.host = host
        self.verifier = verifier
        self.traffic = traffic
        self.external = external
        self.faults = faults or FaultInjector(set())
        self.clock = clock
        self.manager_epoch = store.boot()

    def _now(self) -> int:
        return int(self.clock())

    def _exposure_gate(self) -> Any | None:
        from .exposure_gate import ReferenceExposureGate

        return self.traffic if isinstance(self.traffic, ReferenceExposureGate) else None

    def _row(self, plan_id: str) -> sqlite3.Row:
        row = self.store.connection.execute(
            "SELECT * FROM activation WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise ContractError(ErrorCode.UNKNOWN_RESOURCE, plan_id)
        return row

    def _transition(self, db: sqlite3.Connection, plan_id: str, target: State) -> None:
        current = State(self._row(plan_id)["state"])
        if target not in TRANSITIONS[current]:
            raise ContractError(
                ErrorCode.INVALID_TRANSITION, f"{current.value} -> {target.value}"
            )
        db.execute(
            "UPDATE activation SET state=? WHERE plan_id=?", (target.value, plan_id)
        )
        self._journal(db, plan_id, "transition", target.value, {"from": current.value})

    def _journal(
        self,
        db: sqlite3.Connection,
        plan_id: str,
        kind: str,
        operation: str,
        detail: Any,
    ) -> None:
        db.execute(
            "INSERT INTO journal"
            "(plan_id,kind,operation,detail_json,created_at) VALUES(?,?,?,?,?)",
            (plan_id, kind, operation, canonical_bytes(detail), self._now()),
        )

    def plan(self, plan: Plan) -> str:
        if not plan.obligations or any(
            not obligation.required_ordinals for obligation in plan.obligations
        ):
            raise ContractError(
                ErrorCode.MISSING_PROCESS_EVIDENCE,
                "activation Plan requires non-empty evidence obligations and targets",
            )
        with self.store.connection as db:
            db.execute(
                "INSERT INTO activation VALUES(?,?,?,?,?,?)",
                (
                    plan.plan_id,
                    canonical_bytes(asdict(plan)),
                    State.PLANNED.value,
                    None,
                    canonical_bytes(asdict(plan.predecessor)),
                    self._now(),
                ),
            )
            self._journal(db, plan.plan_id, "transition", "plan", {"state": "Planned"})
        gate = self._exposure_gate()
        if gate is not None:
            try:
                gate.stage(plan.plan_id, plan.predecessor)
            except Exception:
                with self.store.connection as db:
                    db.execute("DELETE FROM journal WHERE plan_id=?", (plan.plan_id,))
                    db.execute(
                        "DELETE FROM activation WHERE plan_id=?", (plan.plan_id,)
                    )
                raise
        else:
            self.traffic.hold_predecessor(plan.predecessor)
        return plan.plan_id

    def prepare(self, plan_id: str) -> None:
        plan = _plan_from_json(self._row(plan_id)["plan_json"])
        with self.store.connection as db:
            self._transition(db, plan_id, State.PREPARING)
            self._journal(db, plan_id, "wal", "prepare", {})
        self.faults.hit("prepare.after_wal")
        receipt = self.host.prepare(plan)
        self.faults.hit("prepare.after_side_effect")
        with self.store.connection as db:
            self._journal(db, plan_id, "receipt", "prepare", receipt)
            self._transition(db, plan_id, State.PREPARED)
        gate = self._exposure_gate()
        if gate is not None:
            gate.close(plan.predecessor.generation + 1)

    def launch(self, plan_id: str, launch_id: str) -> None:
        plan = _plan_from_json(self._row(plan_id)["plan_json"])
        with self.store.connection as db:
            self._transition(db, plan_id, State.LAUNCHING)
            db.execute(
                "UPDATE activation SET launch_id=? WHERE plan_id=?",
                (launch_id, plan_id),
            )
            self._journal(db, plan_id, "wal", "launch", {"launch_id": launch_id})
        self.faults.hit("launch.after_wal")
        inventory = tuple(self.host.launch(plan, launch_id))
        self.faults.hit("launch.after_side_effect")
        with self.store.connection as db:
            db.execute("DELETE FROM inventory WHERE plan_id=?", (plan_id,))
            db.executemany(
                "INSERT INTO inventory VALUES(?,?,?,?,?,?)",
                [
                    (plan_id, p.host, p.role, p.ordinal, p.start_id, p.epoch)
                    for p in inventory
                ],
            )
            self._journal(db, plan_id, "receipt", "launch", {"count": len(inventory)})
            self._transition(db, plan_id, State.OBSERVING)

    def observe(self, plan_id: str, item: Attestation, now: int | None = None) -> None:
        row = self._row(plan_id)
        state = State(row["state"])
        if state not in {State.OBSERVING, State.RECONCILE}:
            raise ContractError(
                ErrorCode.INVALID_TRANSITION, f"observe from {state.value}"
            )
        plan = _plan_from_json(row["plan_json"])
        observed_at = self._now() if now is None else now
        self.verifier.verify(item, observed_at, plan)
        inventory = self.store.connection.execute(
            "SELECT * FROM inventory WHERE plan_id=? AND role=? AND ordinal=?",
            (plan_id, item.process.role, item.process.ordinal),
        ).fetchone()
        if (
            item.plan_id != plan_id
            or item.launch_id != row["launch_id"]
            or item.artifact_id not in {plugin.id for plugin in plan.plugins}
            or inventory is None
            or inventory["start_id"] != item.process.start_id
            or inventory["epoch"] != item.process.epoch
        ):
            raise ContractError(ErrorCode.STALE_EVIDENCE, item.nonce)
        try:
            with self.store.connection as db:
                db.execute(
                    "INSERT INTO evidence "
                    "(nonce,plan_id,launch_id,process_key,role,ordinal,epoch,"
                    "obligation_id,event,issued_at,expires_at,artifact_id,authority,"
                    "manager_epoch,valid,issuer,kid,observed_at,evidence_digest,"
                    "artifact_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)",
                    (
                        item.nonce,
                        plan_id,
                        item.launch_id,
                        item.process.key,
                        item.process.role,
                        item.process.ordinal,
                        item.process.epoch,
                        item.obligation_id,
                        item.event,
                        item.issued_at,
                        item.expires_at,
                        item.artifact_id,
                        item.authority,
                        self.manager_epoch,
                        item.issuer,
                        item.kid,
                        item.observed_at,
                        item.evidence_digest,
                        item.artifact_digest,
                    ),
                )
                self._journal(db, plan_id, "evidence", item.event, asdict(item))
        except sqlite3.IntegrityError as exc:
            raise ContractError(ErrorCode.REPLAYED_NONCE, item.nonce) from exc

    def refresh_inventory(
        self, plan_id: str, inventory: Iterable[ProcessIdentity]
    ) -> None:
        state = State(self._row(plan_id)["state"])
        if state not in {State.OBSERVING, State.RECONCILE}:
            raise ContractError(
                ErrorCode.INVALID_TRANSITION, f"refresh inventory from {state.value}"
            )
        processes = tuple(inventory)
        with self.store.connection as db:
            db.execute("DELETE FROM inventory WHERE plan_id=?", (plan_id,))
            db.executemany(
                "INSERT INTO inventory VALUES(?,?,?,?,?,?)",
                [
                    (plan_id, p.host, p.role, p.ordinal, p.start_id, p.epoch)
                    for p in processes
                ],
            )
            db.execute("UPDATE evidence SET valid=0 WHERE plan_id=?", (plan_id,))
            self._journal(
                db,
                plan_id,
                "inventory",
                "refresh",
                {"processes": [asdict(process) for process in processes]},
            )

    def _evidence_complete(self, plan: Plan, now: int) -> bool:
        if not plan.obligations or any(
            not obligation.required_ordinals for obligation in plan.obligations
        ):
            return False
        inventory = self.store.connection.execute(
            "SELECT role,ordinal,epoch FROM inventory WHERE plan_id=?", (plan.plan_id,)
        ).fetchall()
        by_process = {(row["role"], row["ordinal"]): row["epoch"] for row in inventory}
        evidence = self.store.connection.execute(
            "SELECT role,ordinal,epoch,obligation_id,event FROM evidence "
            "WHERE plan_id=? AND valid=1 AND manager_epoch=? AND expires_at>=?",
            (plan.plan_id, self.manager_epoch, now),
        ).fetchall()
        observed = {
            (
                row["role"],
                row["ordinal"],
                row["epoch"],
                row["obligation_id"],
                row["event"],
            )
            for row in evidence
        }
        for obligation in plan.obligations:
            for ordinal in obligation.required_ordinals:
                epoch = by_process.get((obligation.role, ordinal))
                if (
                    epoch is None
                    or (
                        obligation.role,
                        ordinal,
                        epoch,
                        obligation.obligation_id,
                        obligation.event,
                    )
                    not in observed
                ):
                    return False
        return True

    def _open_proof(self, plan: Plan, generation: int) -> Any:
        from .exposure_gate import OpenProof

        rows = self.store.connection.execute(
            "SELECT nonce,evidence_digest,process_key,obligation_id,event "
            "FROM evidence WHERE plan_id=? AND valid=1 AND manager_epoch=? "
            "ORDER BY nonce",
            (plan.plan_id, self.manager_epoch),
        ).fetchall()
        evidence = [dict(row) for row in rows]
        coverage = [asdict(item) for item in plan.obligations]

        def digest(value: Any) -> str:
            return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

        gate = self._exposure_gate()
        assert gate is not None
        return OpenProof(
            plan.plan_id,
            generation,
            len(evidence),
            digest(evidence),
            digest(coverage),
            gate.authority.current(),
        )

    def commit(self, plan_id: str, expected_generation: int) -> int:
        plan = _plan_from_json(self._row(plan_id)["plan_json"])
        if not self.external.lease_valid(plan):
            self.external_lease_lost(plan_id)
            raise ContractError(ErrorCode.EXTERNAL_LEASE_INVALID, plan_id)
        if not self._evidence_complete(plan, self._now()):
            raise ContractError(ErrorCode.MISSING_PROCESS_EVIDENCE, plan_id)
        with self.store.connection as db:
            self._transition(db, plan_id, State.COMMIT_READY)
            self._journal(db, plan_id, "wal", "commit", {"from": expected_generation})
            changed = db.execute(
                "UPDATE meta SET generation=generation+1 "
                "WHERE singleton=1 AND generation=?",
                (expected_generation,),
            ).rowcount
            if changed != 1 or plan.predecessor.generation != expected_generation:
                raise ContractError(ErrorCode.CAS_MISMATCH, str(expected_generation))
        self.faults.hit("commit.after_wal")
        gate = self._exposure_gate()
        if gate is not None:
            from .attestation import SignedAttestationVerifier

            if not isinstance(self.verifier, SignedAttestationVerifier):
                raise ContractError(
                    ErrorCode.MISSING_PROCESS_EVIDENCE,
                    "ExposureGate requires signed receipt verification",
                )
            gate.open(
                expected_generation + 1,
                self._open_proof(plan, expected_generation + 1),
            )
        else:
            self.traffic.activate(plan)
        self.faults.hit("commit.after_side_effect")
        with self.store.connection as db:
            generation = int(
                db.execute("SELECT generation FROM meta WHERE singleton=1").fetchone()[
                    0
                ]
            )
            self._journal(db, plan_id, "receipt", "commit", {"generation": generation})
            self._transition(db, plan_id, State.EFFECTIVE)
        return generation

    def recover(self, plan_id: str) -> State:
        row = self._row(plan_id)
        state = State(row["state"])
        plan = _plan_from_json(row["plan_json"])
        gate = self._exposure_gate()
        if state is State.ROLLBACK:
            if gate is None:
                with self.store.connection as db:
                    self._transition(db, plan_id, State.FAILED_SAFE)
                return State.FAILED_SAFE
            from .exposure_gate import GateState

            host_receipt = self.store.connection.execute(
                "SELECT detail_json FROM journal WHERE plan_id=? "
                "AND operation='rollback.host' ORDER BY sequence DESC LIMIT 1",
                (plan_id,),
            ).fetchone()
            gate_state = gate.reconcile()
            if host_receipt is None:
                gate_state = {
                    "FAILED_SAFE": GateState.FAILED_SAFE,
                    "SAFETY_UNKNOWN": GateState.SAFETY_UNKNOWN,
                }[
                    gate.fail_close(
                        plan.predecessor.generation + 1,
                        "host rollback outcome missing during recovery",
                    ).classification.value
                ]
                host_detail = {"outcome": None, "error": "missing host receipt"}
            else:
                host_detail = json.loads(host_receipt["detail_json"])
            if gate_state is GateState.SAFETY_UNKNOWN:
                target = State.SAFETY_UNKNOWN
            elif (
                gate_state is GateState.FAILED_SAFE
                or host_detail.get("error") is not None
                or host_detail.get("outcome") is None
            ):
                target = State.FAILED_SAFE
            elif gate_state is GateState.ROLLED_BACK:
                target = State.ROLLED_BACK
            else:
                outcome = gate.fail_close(
                    plan.predecessor.generation + 1,
                    f"unexpected gate recovery state {gate_state.value}",
                )
                target = (
                    State.FAILED_SAFE
                    if outcome.classification.value == "FAILED_SAFE"
                    else State.SAFETY_UNKNOWN
                )
            with self.store.connection as db:
                detail = {
                    "recovered": True,
                    "host": host_detail,
                    "gate_state": gate_state.value,
                }
                db.execute(
                    "INSERT INTO rollback_outcome"
                    "(plan_id,success,detail_json,created_at) VALUES(?,?,?,?)",
                    (
                        plan_id,
                        int(target is State.ROLLED_BACK),
                        canonical_bytes(detail),
                        self._now(),
                    ),
                )
                self._journal(db, plan_id, "receipt", "rollback.recover", detail)
                self._transition(db, plan_id, target)
            return target
        if state is State.COMMIT_READY and gate is not None:
            from .exposure_gate import GateState

            gate_state = gate.reconcile()
            if gate_state is GateState.CANDIDATE_OPEN:
                with self.store.connection as db:
                    self._journal(
                        db, plan_id, "receipt", "commit.reconcile", {"queried": True}
                    )
                    self._transition(db, plan_id, State.EFFECTIVE)
                return State.EFFECTIVE
            if gate_state is GateState.CANDIDATE_CLOSED:
                gate.rollback(plan.predecessor.generation + 1)
            with self.store.connection as db:
                self._transition(db, plan_id, State.RECONCILE)
                self._journal(
                    db,
                    plan_id,
                    "recovery",
                    "gate-not-open",
                    {"gate_state": gate_state.value},
                )
        elif state in {State.PREPARING, State.LAUNCHING, State.OBSERVING} and gate:
            gate.rollback(plan.predecessor.generation + 1)
            with self.store.connection as db:
                self._transition(db, plan_id, State.RECONCILE)
                self._journal(
                    db,
                    plan_id,
                    "recovery",
                    "pre-open-rollback",
                    {"state": state.value},
                )
        elif state in {State.PREPARING, State.LAUNCHING, State.COMMIT_READY}:
            self.traffic.restore(plan.predecessor)
            with self.store.connection as db:
                self._transition(db, plan_id, State.RECONCILE)
                self._journal(db, plan_id, "recovery", "reobserve", {})
        elif state is State.OBSERVING:
            self.traffic.restore(plan.predecessor)
            with self.store.connection as db:
                self._transition(db, plan_id, State.RECONCILE)
        return State(self._row(plan_id)["state"])

    def resume_observing(self, plan_id: str) -> None:
        with self.store.connection as db:
            self._transition(db, plan_id, State.OBSERVING)

    def rollback(self, plan_id: str, reason: str) -> State:
        row = self._row(plan_id)
        plan = _plan_from_json(row["plan_json"])
        with self.store.connection as db:
            self._transition(db, plan_id, State.ROLLBACK)
            self._journal(db, plan_id, "wal", "rollback", {"reason": reason})
        host_outcome = None
        host_error = None
        try:
            host_outcome = self.host.rollback(plan.predecessor)
        except Exception as exc:
            host_error = str(exc)
        with self.store.connection as db:
            self._journal(
                db,
                plan_id,
                "receipt",
                "rollback.host",
                {"outcome": host_outcome, "error": host_error},
            )

        gate = self._exposure_gate()
        if gate is not None:
            from .exposure_gate import RollbackClass

            gate_error = None
            try:
                if host_error is None:
                    gate_outcome = gate.rollback(plan.predecessor.generation + 1)
                else:
                    gate_outcome = gate.fail_close(
                        plan.predecessor.generation + 1,
                        "host rollback failed",
                    ).classification
            except Exception as exc:
                gate_error = str(exc)
                try:
                    gate_outcome = gate.fail_close(
                        plan.predecessor.generation + 1,
                        "traffic rollback failed",
                    ).classification
                except Exception as close_exc:
                    gate_error = f"{gate_error}; fail-close: {close_exc}"
                    gate_outcome = RollbackClass.SAFETY_UNKNOWN
            self.faults.hit("rollback.after_traffic_side_effect")
            with self.store.connection as db:
                self._journal(
                    db,
                    plan_id,
                    "receipt",
                    "rollback.traffic",
                    {"outcome": gate_outcome.value, "error": gate_error},
                )
            if gate_outcome is RollbackClass.SAFETY_UNKNOWN:
                target = State.SAFETY_UNKNOWN
            elif host_error is not None or gate_outcome is RollbackClass.FAILED_SAFE:
                target = State.FAILED_SAFE
            else:
                target = State.ROLLED_BACK
            with self.store.connection as db:
                db.execute(
                    "INSERT INTO rollback_outcome"
                    "(plan_id,success,detail_json,created_at) VALUES(?,?,?,?)",
                    (
                        plan_id,
                        int(target is State.ROLLED_BACK),
                        canonical_bytes(
                            {
                                "host_outcome": host_outcome,
                                "host_error": host_error,
                                "traffic_outcome": gate_outcome.value,
                                "traffic_error": gate_error,
                            }
                        ),
                        self._now(),
                    ),
                )
                self._transition(db, plan_id, target)
            return target

        try:
            if host_error is not None:
                raise RuntimeError(host_error)
            assert host_outcome is not None
            self.traffic.restore(plan.predecessor)
        except Exception as exc:
            with self.store.connection as db:
                db.execute(
                    "INSERT INTO rollback_outcome"
                    "(plan_id,success,detail_json,created_at) VALUES(?,?,?,?)",
                    (plan_id, 0, canonical_bytes({"error": str(exc)}), self._now()),
                )
                self._transition(db, plan_id, State.FAILED_SAFE)
            raise ContractError(ErrorCode.ROLLBACK_FAILED, str(exc)) from exc
        with self.store.connection as db:
            db.execute(
                "INSERT INTO rollback_outcome"
                "(plan_id,success,detail_json,created_at) VALUES(?,?,?,?)",
                (plan_id, 1, canonical_bytes(host_outcome), self._now()),
            )
            self._journal(db, plan_id, "receipt", "rollback", host_outcome)
            self._transition(db, plan_id, State.ROLLED_BACK)
        return State.ROLLED_BACK

    def external_lease_lost(self, plan_id: str) -> State:
        plan = _plan_from_json(self._row(plan_id)["plan_json"])
        with self.store.connection as db:
            self._transition(db, plan_id, State.DEGRADED)
        if plan.fallback_proven:
            with self.store.connection as db:
                self._transition(db, plan_id, State.RECONCILE)
            return State.RECONCILE
        return self.rollback(plan_id, "external lease invalid")

    def status(self, plan_id: str) -> dict[str, Any]:
        row = self._row(plan_id)
        generation = self.store.connection.execute(
            "SELECT generation FROM meta WHERE singleton=1"
        ).fetchone()[0]
        return {
            "plan_id": plan_id,
            "state": row["state"],
            "launch_id": row["launch_id"],
            "generation": generation,
            "manager_epoch": self.manager_epoch,
        }
