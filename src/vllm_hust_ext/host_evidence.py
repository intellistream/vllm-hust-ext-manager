"""Strict ingestion of unsigned vLLM-HUST host lifecycle events.

Raw events are audit inputs, never coordinator attestations. A trusted host
issuer must translate, bind to a Plan, and sign the resulting statement.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .attestation import AttestationStatement, ProcessStatement
from .attestation.model import PROFILE, SCHEMA
from .attestation.profile import (
    AttestationError,
    AttestationErrorCode,
    parse_strict,
)
from .ecpa_model import Plan

HOST_SCHEMA = "vllm-hust-plugin-evidence/0.1"
EVENTS = {"discovered", "resolved", "invoked", "failed", "skipped"}
OBSERVATION_KINDS = {
    "loader_lifecycle",
    "scheduler_resolution",
    "scheduler_dispatch",
}


@dataclass(frozen=True)
class EntryPointBinding:
    group: str
    name: str
    value: str
    plugin_id: str
    obligation: str


@dataclass(frozen=True)
class HostReceipt:
    raw: bytes
    event: dict[str, Any]
    statement: AttestationStatement


def _invalid(detail: str) -> None:
    raise AttestationError(AttestationErrorCode.INVALID_STATEMENT, detail)


def _validate_unicode(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AttestationError(
                AttestationErrorCode.UNSUPPORTED_VALUE,
                "invalid Unicode scalar",
            ) from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)


def parse_host_event(raw: bytes) -> dict[str, Any]:
    try:
        value = parse_strict(raw)
    except AttestationError:
        raise
    required = {
        "schema",
        "event_id",
        "event",
        "observation_kind",
        "entry_point",
        "process",
        "observed_at_ns",
        "delivery_attempt",
        "plan_id",
        "launch_id",
        "binding_status",
        "occurrence_id",
        "controller_instance_id",
        "invocation_seq",
        "dispatch_id",
        "plugin_id",
        "artifact_digest",
        "identity_status",
        "detail",
    }
    if not isinstance(value, dict) or set(value) != required:
        _invalid("host event fields do not match schema")
    if (
        value["schema"] != HOST_SCHEMA
        or value["event"] not in EVENTS
        or value["observation_kind"] not in OBSERVATION_KINDS
    ):
        _invalid("unsupported host event schema or event")
    _validate_unicode(value)
    entry = value["entry_point"]
    process = value["process"]
    if not isinstance(entry, dict) or set(entry) != {"group", "name", "value"}:
        _invalid("entry_point fields do not match schema")
    if not isinstance(process, dict) or set(process) != {
        "host",
        "role",
        "ordinal",
        "pid",
        "start_identity",
        "process_epoch",
    }:
        _invalid("process fields do not match schema")
    strings = [value["event_id"], value["identity_status"]]
    strings += [entry[name] for name in ("group", "name", "value")]
    strings += [process[name] for name in ("host", "role", "start_identity")]
    if any(not isinstance(item, str) or not item for item in strings):
        _invalid("required host event strings must be non-empty")
    for item in (
        process["ordinal"],
        process["pid"],
        process["process_epoch"],
        value["observed_at_ns"],
        value["delivery_attempt"],
    ):
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            _invalid("host event integer must be non-negative")
    start_identity = process["start_identity"]
    prefix = f"pid:{process['pid']}:start_ticks:"
    if not start_identity.startswith(prefix):
        _invalid("start_identity does not bind the process pid")
    try:
        if int(start_identity.removeprefix(prefix)) < 0:
            _invalid("process start ticks must be non-negative")
    except ValueError:
        _invalid("process start identity is unavailable")
    if value["delivery_attempt"] < 1:
        _invalid("delivery_attempt must be positive")
    for name in ("plan_id", "launch_id", "detail", "controller_instance_id"):
        item = value[name]
        if item is not None and (not isinstance(item, str) or not item):
            _invalid(f"{name} must be null or string")
    binding_status = value["binding_status"]
    if binding_status not in {"bound", "unbound"}:
        _invalid("binding_status must be bound or unbound")
    if (value["plan_id"] is None) != (value["launch_id"] is None):
        _invalid("plan and launch identity must both be present or both be absent")
    is_bound = value["plan_id"] is not None and value["launch_id"] is not None
    if is_bound != (binding_status == "bound"):
        _invalid("binding_status does not match plan and launch identity")
    occurrence_id = value["occurrence_id"]
    if occurrence_id is not None and (
        isinstance(occurrence_id, bool)
        or not isinstance(occurrence_id, (int, str))
        or isinstance(occurrence_id, int)
        and occurrence_id < 1
        or isinstance(occurrence_id, str)
        and not occurrence_id
    ):
        _invalid("occurrence_id must be a positive integer, string, or null")
    invocation_seq = value["invocation_seq"]
    if invocation_seq is not None and (
        isinstance(invocation_seq, bool)
        or not isinstance(invocation_seq, int)
        or invocation_seq < 1
    ):
        _invalid("invocation_seq must be a positive integer or null")
    dispatch_id = value["dispatch_id"]
    if dispatch_id is not None and (
        not isinstance(dispatch_id, str)
        or len(dispatch_id) != 64
        or any(character not in "0123456789abcdef" for character in dispatch_id)
    ):
        _invalid("dispatch_id must be a lowercase SHA-256 hex digest or null")
    observation_kind = value["observation_kind"]
    controller_instance_id = value["controller_instance_id"]
    if observation_kind == "loader_lifecycle":
        if any(
            item is not None
            for item in (
                occurrence_id,
                controller_instance_id,
                invocation_seq,
                dispatch_id,
            )
        ):
            _invalid("loader lifecycle event contains scheduler-only identity")
    elif observation_kind == "scheduler_resolution":
        if (
            value["event"] != "resolved"
            or not isinstance(controller_instance_id, str)
            or occurrence_id != f"controller:{controller_instance_id}"
            or invocation_seq is not None
            or dispatch_id is not None
        ):
            _invalid("scheduler resolution identity is inconsistent")
    else:
        if (
            value["event"] != "invoked"
            or not isinstance(controller_instance_id, str)
            or not isinstance(occurrence_id, int)
            or invocation_seq != occurrence_id
        ):
            _invalid("scheduler dispatch identity is inconsistent")
        material = json.dumps(
            [
                process["host"],
                process["start_identity"],
                process["process_epoch"],
                value["plan_id"],
                value["launch_id"],
                controller_instance_id,
                occurrence_id,
            ],
            separators=(",", ":"),
        ).encode()
        if dispatch_id != hashlib.sha256(material).hexdigest():
            _invalid("scheduler dispatch identity digest is inconsistent")
    event_material = json.dumps(
        [
            process["host"],
            process["pid"],
            process["start_identity"],
            process["process_epoch"],
            process["role"],
            process["ordinal"],
            entry["group"],
            entry["name"],
            entry["value"],
            value["event"],
            value["detail"],
            occurrence_id,
            value["plan_id"],
            value["launch_id"],
            observation_kind,
            controller_instance_id,
            value["delivery_attempt"],
            value["observed_at_ns"],
        ],
        separators=(",", ":"),
    ).encode()
    if value["event_id"] != hashlib.sha256(event_material).hexdigest():
        _invalid("event_id does not match host event material")
    if value["plugin_id"] is not None or value["artifact_digest"] is not None:
        _invalid("Phase A host events must not invent plugin identity or digest")
    return value


def translate_invocation(
    raw: bytes,
    *,
    plan: Plan,
    launch_id: str,
    process_epoch: int,
    binding: EntryPointBinding,
    issuer: str,
    kid: str,
    challenge_nonce: str,
    issued_at: int,
    expires_at: int,
) -> HostReceipt:
    event = parse_host_event(raw)
    if event["event"] != "invoked":
        _invalid("only host-observed invoked events satisfy invocation evidence")
    if event["binding_status"] != "bound":
        raise AttestationError(
            AttestationErrorCode.BINDING_MISMATCH,
            "unbound host events cannot satisfy invocation evidence",
        )
    if event["plan_id"] != plan.plan_id or event["launch_id"] != launch_id:
        raise AttestationError(
            AttestationErrorCode.BINDING_MISMATCH, "plan or launch mismatch"
        )
    if event["process"]["process_epoch"] != process_epoch:
        raise AttestationError(
            AttestationErrorCode.BINDING_MISMATCH, "process epoch mismatch"
        )
    entry = event["entry_point"]
    if (entry["group"], entry["name"], entry["value"]) != (
        binding.group,
        binding.name,
        binding.value,
    ):
        raise AttestationError(
            AttestationErrorCode.BINDING_MISMATCH, "entry point mismatch"
        )
    plugin = next((item for item in plan.plugins if item.id == binding.plugin_id), None)
    if plugin is None:
        raise AttestationError(
            AttestationErrorCode.BINDING_MISMATCH, "plugin is absent from Plan"
        )
    evidence_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    statement = AttestationStatement(
        SCHEMA,
        PROFILE,
        issuer,
        kid,
        "host-runtime",
        plan.plan_id,
        launch_id,
        plugin.id,
        "sha256:" + plugin.artifact_sha256,
        ProcessStatement(
            event["process"]["host"],
            event["process"]["role"],
            event["process"]["ordinal"],
            event["process"]["start_identity"],
            process_epoch,
        ),
        binding.obligation,
        "invoked",
        event["observed_at_ns"] // 1_000_000_000,
        issued_at,
        expires_at,
        challenge_nonce,
        evidence_digest,
    )
    return HostReceipt(raw, event, statement)
