"""Encoding-independent ECPA attestation statement semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SCHEMA = "ecpa-attestation-statement/0.1"
PROFILE = "ecpa-jcs-jws-eddsa/0.1"


@dataclass(frozen=True)
class ProcessStatement:
    host: str
    role: str
    ordinal: int
    start_identity: str
    epoch: int


@dataclass(frozen=True)
class AttestationStatement:
    schema: str
    profile: str
    issuer: str
    kid: str
    subject: str
    plan_id: str
    launch_id: str
    plugin_id: str
    artifact_digest: str
    process: ProcessStatement
    obligation: str
    event: str
    observed_at: int
    issued_at: int
    expires_at: int
    challenge_nonce: str
    evidence_digest: str
    critical_claims: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["critical_claims"] = list(self.critical_claims)
        return value

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AttestationStatement:
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected or not isinstance(value.get("process"), dict):
            raise ValueError("statement fields do not match schema")
        process_fields = set(ProcessStatement.__dataclass_fields__)
        if set(value["process"]) != process_fields:
            raise ValueError("process fields do not match schema")
        return cls(
            **{
                **value,
                "process": ProcessStatement(**value["process"]),
                "critical_claims": tuple(value["critical_claims"]),
            }
        )
