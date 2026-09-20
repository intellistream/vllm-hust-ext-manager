"""Canonical, immutable execution-plan artifacts for managed launches."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ResourceClaim,
    canonical_bytes,
    canonical_uri,
)

SCHEMA = "ecpa-execution-plan/v1"


class PlanArtifactError(ValueError):
    """The execution-plan artifact is unsafe or not canonical."""


@dataclass(frozen=True)
class ExecutionPlanArtifact:
    path: Path
    raw: bytes
    plan: Plan

    @property
    def plan_id(self) -> str:
        return self.plan.plan_id


def plan_artifact_value(plan: Plan) -> dict[str, Any]:
    """Return the only accepted on-disk representation of an ECPA Plan."""
    return {
        "schema": SCHEMA,
        "plan_id": plan.plan_id,
        "plan": asdict(plan),
    }


def plan_artifact_bytes(plan: Plan) -> bytes:
    return canonical_bytes(plan_artifact_value(plan)) + b"\n"


def _exact_fields(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PlanArtifactError(f"{context} fields do not match the schema")
    return value


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(character.isspace() for character in value)
    ):
        raise PlanArtifactError(
            f"{context} must be a non-empty string without whitespace"
        )
    return value


def _integer(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PlanArtifactError(f"{context} must be a non-negative integer")
    return value


def _sha256(value: Any, context: str) -> str:
    value = _string(value, context)
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise PlanArtifactError(f"{context} must be a lowercase SHA-256 digest")
    return value


def parse_plan_artifact(raw: bytes) -> Plan:
    """Parse canonical bytes and recompute the content-addressed Plan identity."""

    def reject_nonfinite(value: str) -> None:
        raise PlanArtifactError(f"non-finite JSON number is forbidden: {value}")

    try:
        value = json.loads(raw, parse_constant=reject_nonfinite)
    except (UnicodeDecodeError, ValueError) as exc:
        raise PlanArtifactError("execution plan is not valid UTF-8 JSON") from exc
    envelope = _exact_fields(value, {"schema", "plan_id", "plan"}, "artifact")
    if raw != canonical_bytes(envelope) + b"\n":
        raise PlanArtifactError("execution plan artifact is not canonical")
    if envelope["schema"] != SCHEMA:
        raise PlanArtifactError("unsupported execution plan schema")
    body = _exact_fields(
        envelope["plan"],
        {
            "plugins",
            "host",
            "claims",
            "obligations",
            "predecessor",
            "fallback_proven",
        },
        "plan",
    )
    if not isinstance(body["plugins"], list) or not body["plugins"]:
        raise PlanArtifactError("execution plan requires at least one plugin")
    plugins = []
    for index, item in enumerate(body["plugins"]):
        plugin = _exact_fields(
            item,
            {"namespace", "name", "version", "artifact_sha256"},
            f"plugin {index}",
        )
        plugins.append(
            PluginIdentity(
                _string(plugin["namespace"], "plugin namespace"),
                _string(plugin["name"], "plugin name"),
                _string(plugin["version"], "plugin version"),
                _sha256(plugin["artifact_sha256"], "plugin artifact digest"),
            )
        )
    if len({plugin.id for plugin in plugins}) != len(plugins):
        raise PlanArtifactError("execution plan contains duplicate plugins")
    host_value = _exact_fields(
        body["host"], {"runtime", "version", "provider", "abi"}, "host"
    )
    host = HostCompatibility(
        *(
            _string(host_value[field], f"host {field}")
            for field in ("runtime", "version", "provider", "abi")
        )
    )
    if not isinstance(body["claims"], list):
        raise PlanArtifactError("plan claims must be an array")
    claims = []
    for index, item in enumerate(body["claims"]):
        claim = _exact_fields(item, {"uri", "owner", "mode"}, f"claim {index}")
        uri = _string(claim["uri"], "claim URI")
        canonical_uri(uri, "resource")
        if re.fullmatch(r"urn:ecpa:resource:[a-z0-9._-]+", uri) is None:
            raise PlanArtifactError("claim URI does not match the resource profile")
        mode = _string(claim["mode"], "claim mode")
        if mode not in {"exclusive", "shared-read"}:
            raise PlanArtifactError("claim mode is unsupported")
        claims.append(ResourceClaim(uri, _string(claim["owner"], "claim owner"), mode))
    if len({claim.uri for claim in claims}) != len(claims):
        raise PlanArtifactError("execution plan contains duplicate resource claims")
    if not isinstance(body["obligations"], list) or not body["obligations"]:
        raise PlanArtifactError("execution plan requires evidence obligations")
    obligations = []
    for index, item in enumerate(body["obligations"]):
        obligation = _exact_fields(
            item,
            {"obligation_id", "role", "event", "required_ordinals"},
            f"obligation {index}",
        )
        ordinals = obligation["required_ordinals"]
        if not isinstance(ordinals, list) or not ordinals:
            raise PlanArtifactError("evidence obligation requires target ordinals")
        parsed_ordinals = tuple(
            _integer(ordinal, "required ordinal") for ordinal in ordinals
        )
        if tuple(sorted(set(parsed_ordinals))) != parsed_ordinals:
            raise PlanArtifactError("required ordinals must be unique and sorted")
        obligations.append(
            EvidenceObligation(
                _string(obligation["obligation_id"], "obligation id"),
                _string(obligation["role"], "obligation role"),
                _string(obligation["event"], "obligation event"),
                parsed_ordinals,
            )
        )
    if len({item.obligation_id for item in obligations}) != len(obligations):
        raise PlanArtifactError("execution plan contains duplicate obligations")
    predecessor_value = _exact_fields(
        body["predecessor"],
        {"generation", "plan_id", "rendered_inputs"},
        "predecessor",
    )
    predecessor_plan_id = predecessor_value["plan_id"]
    if predecessor_plan_id is not None:
        predecessor_plan_id = _string(predecessor_plan_id, "predecessor plan id")
    rendered_inputs = predecessor_value["rendered_inputs"]
    if not isinstance(rendered_inputs, dict):
        raise PlanArtifactError("predecessor rendered inputs must be an object")
    fallback_proven = body["fallback_proven"]
    if not isinstance(fallback_proven, bool):
        raise PlanArtifactError("fallback_proven must be boolean")
    plan = Plan(
        tuple(plugins),
        host,
        tuple(claims),
        tuple(obligations),
        PredecessorSnapshot(
            _integer(predecessor_value["generation"], "predecessor generation"),
            predecessor_plan_id,
            rendered_inputs,
        ),
        fallback_proven,
    )
    if envelope["plan_id"] != plan.plan_id:
        raise PlanArtifactError("execution plan id does not match its content")
    return plan


def read_plan_artifact(path: str | Path) -> ExecutionPlanArtifact:
    """Read an owned, canonical regular file without following a symlink."""
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise PlanArtifactError("execution plan path must be absolute and real")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PlanArtifactError("execution plan path is unavailable") from exc
    if resolved != candidate:
        raise PlanArtifactError("execution plan path must be canonical")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise PlanArtifactError("cannot open execution plan artifact") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PlanArtifactError(
                "execution plan must be a private owned regular file"
            )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return ExecutionPlanArtifact(candidate, raw, parse_plan_artifact(raw))
