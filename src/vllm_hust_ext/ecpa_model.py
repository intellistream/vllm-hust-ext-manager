"""Pure executable model of the ECPA 0.1 contract; performs no external I/O."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class State(str, Enum):
    INTENT = "Intent"
    RESOLVED = "Resolved"
    PLANNED = "Planned"
    PREPARING = "Preparing"
    PREPARED = "Prepared"
    LAUNCHING = "Launching"
    OBSERVING = "Observing"
    COMMIT_READY = "CommitReady"
    EFFECTIVE = "Effective"
    DEGRADED = "Degraded"
    RECONCILE = "Reconcile"
    ROLLBACK = "Rollback"
    ROLLED_BACK = "RolledBack"
    FAILED_SAFE = "FailedSafe"


class ErrorCode(str, Enum):
    UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE"
    AMBIGUOUS_RESOURCE = "AMBIGUOUS_RESOURCE"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    INCOMPATIBLE_HOST = "INCOMPATIBLE_HOST"
    MISSING_PROCESS_EVIDENCE = "MISSING_PROCESS_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    CAS_MISMATCH = "CAS_MISMATCH"
    EXTERNAL_LEASE_INVALID = "EXTERNAL_LEASE_INVALID"
    AUTHORITY_VIOLATION = "AUTHORITY_VIOLATION"
    INVALID_TRANSITION = "INVALID_TRANSITION"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class ContractError(ValueError):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def content_id(prefix: str, value: Any) -> str:
    return f"{prefix}:sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def canonical_uri(value: str, kind: str) -> str:
    prefix = f"urn:ecpa:{kind}:"
    if not value.startswith(prefix) or value.lower() != value or " " in value:
        raise ContractError(ErrorCode.UNKNOWN_RESOURCE, value)
    return value


@dataclass(frozen=True)
class PluginIdentity:
    namespace: str
    name: str
    version: str
    artifact_sha256: str

    @property
    def id(self) -> str:
        return content_id("plugin", asdict(self))


@dataclass(frozen=True)
class HostCompatibility:
    runtime: str
    version: str
    provider: str
    abi: str


@dataclass(frozen=True)
class ProcessIdentity:
    host: str
    role: str
    ordinal: int
    start_id: str
    epoch: int

    @property
    def key(self) -> str:
        return f"{self.host}/{self.role}/{self.ordinal}/{self.start_id}/{self.epoch}"


@dataclass(frozen=True)
class ResourceClaim:
    uri: str
    owner: str
    mode: str = "exclusive"


@dataclass(frozen=True)
class EvidenceObligation:
    obligation_id: str
    role: str
    event: str
    required_ordinals: tuple[int, ...]


@dataclass(frozen=True)
class Attestation:
    plan_id: str
    launch_id: str
    process: ProcessIdentity
    obligation_id: str
    event: str
    nonce: str
    issued_at: int
    expires_at: int
    artifact_id: str
    authority: str = "host-runtime"
    issuer: str = ""
    kid: str = ""
    observed_at: int = 0
    evidence_digest: str = ""
    artifact_digest: str = ""


@dataclass(frozen=True)
class PredecessorSnapshot:
    generation: int
    plan_id: str | None
    rendered_inputs: dict[str, Any]


@dataclass(frozen=True)
class Plan:
    plugins: tuple[PluginIdentity, ...]
    host: HostCompatibility
    claims: tuple[ResourceClaim, ...]
    obligations: tuple[EvidenceObligation, ...]
    predecessor: PredecessorSnapshot
    fallback_proven: bool = False

    @property
    def plan_id(self) -> str:
        return content_id("plan", asdict(self))


@dataclass
class EvidenceStore:
    records: list[dict[str, Any]] = field(default_factory=list)

    def append(self, kind: str, payload: Any) -> None:
        self.records.append(
            {"sequence": len(self.records), "kind": kind, "payload": payload}
        )


class ReferenceModel:
    """Single-host/single-manager logical model with append-only WAL receipts."""

    def __init__(self, generation: int = 0):
        self.state = State.INTENT
        self.generation = generation
        self.store = EvidenceStore()
        self.plan: Plan | None = None
        self.launch_id: str | None = None
        self.inventory: tuple[ProcessIdentity, ...] = ()
        self.nonces: set[str] = set()
        self.accepted: list[Attestation] = []

    def _require(self, *states: State) -> None:
        if self.state not in states:
            raise ContractError(
                ErrorCode.INVALID_TRANSITION,
                f"{self.state.value} not in {[s.value for s in states]}",
            )

    def resolve(self, registrations: Iterable[str], expected_namespace: str) -> None:
        self._require(State.INTENT)
        matches = [x for x in registrations if x == expected_namespace]
        if not matches:
            raise ContractError(ErrorCode.UNKNOWN_RESOURCE, expected_namespace)
        if len(matches) != 1:
            raise ContractError(ErrorCode.AMBIGUOUS_RESOURCE, expected_namespace)
        self.state = State.RESOLVED

    def make_plan(
        self,
        plugins: Iterable[PluginIdentity],
        host: HostCompatibility,
        claims: Iterable[ResourceClaim],
        obligations: Iterable[EvidenceObligation],
        predecessor: PredecessorSnapshot,
        fallback_proven: bool = False,
    ) -> Plan:
        self._require(State.RESOLVED)
        normalized: dict[str, ResourceClaim] = {}
        for claim in claims:
            uri = canonical_uri(claim.uri, "resource")
            prior = normalized.get(uri)
            if (
                prior
                and (prior.mode == "exclusive" or claim.mode == "exclusive")
                and prior.owner != claim.owner
            ):
                raise ContractError(
                    ErrorCode.RESOURCE_CONFLICT,
                    f"{uri}: {prior.owner} vs {claim.owner}",
                )
            normalized[uri] = claim
        self.plan = Plan(
            tuple(plugins),
            host,
            tuple(normalized.values()),
            tuple(obligations),
            predecessor,
            fallback_proven,
        )
        self.store.append("plan", {"plan_id": self.plan.plan_id})
        self.state = State.PLANNED
        return self.plan

    def prepare(self) -> None:
        self._require(State.PLANNED)
        assert self.plan
        self.state = State.PREPARING
        self.store.append("wal", {"operation": "prepare", "plan_id": self.plan.plan_id})
        self.store.append(
            "receipt", {"operation": "prepare", "plan_id": self.plan.plan_id}
        )
        self.state = State.PREPARED

    def launch(self, launch_id: str, inventory: Iterable[ProcessIdentity]) -> None:
        self._require(State.PREPARED)
        assert self.plan
        self.state = State.LAUNCHING
        self.launch_id = launch_id
        self.inventory = tuple(inventory)
        self.store.append("wal", {"operation": "launch", "launch_id": launch_id})
        self.store.append("receipt", {"operation": "launch", "launch_id": launch_id})
        self.state = State.OBSERVING

    def attest(self, item: Attestation, now: int) -> None:
        self._require(State.OBSERVING, State.RECONCILE)
        assert self.plan
        if item.authority != "host-runtime":
            raise ContractError(ErrorCode.AUTHORITY_VIOLATION, item.authority)
        if (
            item.plan_id != self.plan.plan_id
            or item.artifact_id not in {p.id for p in self.plan.plugins}
            or item.launch_id != self.launch_id
            or item.expires_at < now
            or item.issued_at > now
        ):
            raise ContractError(ErrorCode.STALE_EVIDENCE, item.nonce)
        if item.nonce in self.nonces:
            raise ContractError(ErrorCode.REPLAYED_NONCE, item.nonce)
        current = {p.key for p in self.inventory}
        if item.process.key not in current:
            raise ContractError(ErrorCode.STALE_EVIDENCE, item.process.key)
        self.nonces.add(item.nonce)
        self.accepted.append(item)
        self.store.append("attestation", asdict(item))

    def evidence_complete(self) -> bool:
        assert self.plan
        for obligation in self.plan.obligations:
            processes = {
                p.ordinal: p for p in self.inventory if p.role == obligation.role
            }
            if not set(obligation.required_ordinals).issubset(processes):
                return False
            expected = {
                (obligation.role, ordinal, processes[ordinal].epoch)
                for ordinal in obligation.required_ordinals
            }
            observed = {
                (a.process.role, a.process.ordinal, a.process.epoch)
                for a in self.accepted
                if a.obligation_id == obligation.obligation_id
                and a.event == obligation.event
            }
            if expected != observed:
                return False
        return True

    def commit(self, expected_generation: int) -> int:
        self._require(State.OBSERVING)
        assert self.plan
        if (
            expected_generation != self.generation
            or self.plan.predecessor.generation != self.generation
        ):
            raise ContractError(
                ErrorCode.CAS_MISMATCH,
                f"expected {expected_generation}, current {self.generation}",
            )
        if not self.evidence_complete():
            raise ContractError(
                ErrorCode.MISSING_PROCESS_EVIDENCE,
                "all-required-process coverage failed",
            )
        self.state = State.COMMIT_READY
        self.store.append("wal", {"operation": "commit", "from": self.generation})
        self.generation += 1
        self.store.append(
            "receipt", {"operation": "commit", "generation": self.generation}
        )
        self.state = State.EFFECTIVE
        return self.generation

    def external_lease_lost(self) -> None:
        assert self.plan
        self.state = State.DEGRADED
        if self.plan.fallback_proven:
            self.state = State.RECONCILE
        else:
            self.rollback("external lease invalid")

    def rollback(self, reason: str, succeeds: bool = True) -> None:
        assert self.plan
        self.state = State.ROLLBACK
        self.store.append(
            "wal",
            {
                "operation": "rollback",
                "reason": reason,
                "predecessor": asdict(self.plan.predecessor),
            },
        )
        if not succeeds:
            self.store.append("receipt", {"operation": "rollback", "success": False})
            self.state = State.FAILED_SAFE
            raise ContractError(ErrorCode.ROLLBACK_FAILED, reason)
        self.store.append("receipt", {"operation": "rollback", "conditional": True})
        self.state = State.ROLLED_BACK

    def recover_after_crash(self) -> None:
        self.accepted.clear()
        self.state = State.RECONCILE
        self.store.append("reobserve-required", {"launch_id": self.launch_id})
