"""Independent snapshots of vLLM-HUST host-owned effect evidence.

This module deliberately does not turn runner phase acknowledgements into
runtime facts.  It only derives invocation coverage from exact journal bytes
and live Linux process identities observed outside the target process.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .ecpa_model import Plan
from .host_event_sink import JournalEvent, read_events
from .host_evidence import EntryPointBinding

OBSERVATION_SCHEMA = "ecpa-host-effect-observation/v1"


class HostObservationError(ValueError):
    """Host evidence cannot support a formal runtime-effect observation."""


def parse_linux_start_ticks(raw: bytes) -> int:
    """Parse field 22 of ``/proc/PID/stat`` with an arbitrary comm field."""
    close = raw.rfind(b")")
    if close < 2 or close + 2 >= len(raw) or raw[close + 1 : close + 2] != b" ":
        raise HostObservationError("process stat has no complete comm field")
    fields = raw[close + 2 :].split()
    if len(fields) <= 19:
        raise HostObservationError("process stat is missing start ticks")
    try:
        ticks = int(fields[19])
    except ValueError as exc:
        raise HostObservationError("process start ticks are not an integer") from exc
    if ticks <= 0:
        raise HostObservationError("process start ticks must be positive")
    return ticks


def read_linux_process_identity(
    pid: int, expected_start_identity: str
) -> dict[str, Any]:
    """Bind PID, start ticks, and exact argv while rejecting PID reuse."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise HostObservationError("process pid must be positive")
    proc = Path("/proc") / str(pid)
    try:
        before = parse_linux_start_ticks((proc / "stat").read_bytes())
        argv_raw = (proc / "cmdline").read_bytes()
        after = parse_linux_start_ticks((proc / "stat").read_bytes())
    except OSError as exc:
        raise HostObservationError(
            "effect process is not independently observable"
        ) from exc
    if before != after:
        raise HostObservationError("effect process identity changed while reading")
    start_identity = f"pid:{pid}:start_ticks:{before}"
    if expected_start_identity != start_identity:
        raise HostObservationError(
            "effect process start identity differs from host event"
        )
    argv = [
        part.decode(errors="surrogateescape") for part in argv_raw.split(b"\0") if part
    ]
    if not argv:
        raise HostObservationError("effect process argv is unavailable")
    return {
        "pid": pid,
        "start_ticks": before,
        "start_identity": start_identity,
        "argv": argv,
    }


def _required_processes(
    values: Iterable[dict[str, Any]],
) -> tuple[tuple[str, str, int, int], ...]:
    fields = {"host", "role", "ordinal", "process_epoch"}
    parsed: list[tuple[str, str, int, int]] = []
    for value in values:
        if not isinstance(value, dict) or set(value) != fields:
            raise HostObservationError("required process fields do not match schema")
        host, role = value["host"], value["role"]
        ordinal, epoch = value["ordinal"], value["process_epoch"]
        if (
            not isinstance(host, str)
            or not host
            or host.strip() != host
            or not isinstance(role, str)
            or not role
            or role.strip() != role
            or isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or isinstance(epoch, bool)
            or not isinstance(epoch, int)
            or epoch < 0
        ):
            raise HostObservationError("required process identity is malformed")
        parsed.append((host, role, ordinal, epoch))
    if not parsed or parsed != sorted(parsed) or len(parsed) != len(set(parsed)):
        raise HostObservationError("required process snapshot is not canonical")
    logical = [(host, role, ordinal) for host, role, ordinal, _ in parsed]
    if len(logical) != len(set(logical)):
        raise HostObservationError("required process snapshot repeats a logical slot")
    return tuple(parsed)


def _evidence_record(record: JournalEvent) -> dict[str, Any]:
    return {
        "event_id": record.event["event_id"],
        "journal": record.journal,
        "line_number": record.line_number,
        "raw_base64": base64.b64encode(record.raw).decode("ascii"),
        "raw_sha256": "sha256:" + hashlib.sha256(record.raw).hexdigest(),
    }


def observe_bound_invocations(
    root: Path,
    *,
    expected_directory_identity: tuple[int, int],
    plan: Plan,
    launch_id: str,
    controller_instance: str,
    bindings: Iterable[EntryPointBinding],
    required_processes: Iterable[dict[str, Any]],
    local_host: str | None = None,
) -> dict[str, Any]:
    """Derive a Plan-wide immutable effect snapshot from host journals.

    All Plan obligations are observed in one pass so a Linux process identity
    cannot be reused to cover multiple logical roles.  Loader events bind Plan,
    launch, process, and effect but do not claim a controller identity;
    scheduler dispatch events additionally bind the controller.
    """
    required = _required_processes(required_processes)
    local_host = socket.gethostname() if local_host is None else local_host
    if not isinstance(local_host, str) or not local_host:
        raise HostObservationError("local host identity is unavailable")

    plugins = {item.id: item for item in plan.plugins}
    obligations = {item.obligation_id: item for item in plan.obligations}
    binding_rows = tuple(bindings)
    by_entry: dict[tuple[str, str, str], EntryPointBinding] = {}
    by_obligation: dict[str, EntryPointBinding] = {}
    for binding in binding_rows:
        entry = (binding.group, binding.name, binding.value)
        if entry in by_entry or binding.obligation in by_obligation:
            raise HostObservationError("entry-point bindings are ambiguous")
        if binding.plugin_id not in plugins:
            raise HostObservationError("entry-point binding plugin is absent from Plan")
        obligation = obligations.get(binding.obligation)
        if obligation is None or obligation.event != "invoked":
            raise HostObservationError(
                "entry-point binding invocation obligation is absent"
            )
        by_entry[entry] = binding
        by_obligation[binding.obligation] = binding
    if set(by_obligation) != set(obligations):
        raise HostObservationError(
            "every Plan obligation requires one entry-point binding"
        )

    declared = {(host, role, ordinal) for host, role, ordinal, _ in required}
    obligated = {
        (local_host, item.role, ordinal)
        for item in plan.obligations
        for ordinal in item.required_ordinals
    }
    if declared != obligated:
        raise HostObservationError(
            "Plan obligations differ from required process snapshot"
        )
    required_by_slot = {
        (host, role, ordinal): epoch for host, role, ordinal, epoch in required
    }
    targets_by_obligation = {
        obligation_id: tuple(
            item
            for item in required
            if item[1] == obligation.role and item[2] in obligation.required_ordinals
        )
        for obligation_id, obligation in obligations.items()
    }

    if (
        not isinstance(expected_directory_identity, tuple)
        or len(expected_directory_identity) != 2
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in expected_directory_identity
        )
        or expected_directory_identity[1] <= 0
    ):
        raise HostObservationError("host journal directory identity is invalid")
    try:
        metadata = root.stat()
    except OSError as exc:
        raise HostObservationError("host journal directory is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise HostObservationError("host journal path is not a directory")
    if (metadata.st_dev, metadata.st_ino) != expected_directory_identity:
        raise HostObservationError("host journal directory identity changed")
    records = read_events(root, expected_directory_identity)

    effects: dict[str, dict[tuple[str, str, int], dict[str, Any]]] = {
        obligation_id: {} for obligation_id in obligations
    }
    effect_records: dict[str, list[dict[str, Any]]] = {
        obligation_id: [] for obligation_id in obligations
    }
    stale_records: dict[str, list[dict[str, Any]]] = {
        obligation_id: [] for obligation_id in obligations
    }
    controller_bound = {obligation_id: False for obligation_id in obligations}
    linux_slots: dict[tuple[str, int, int], tuple[str, str, int]] = {}
    other_records: list[dict[str, Any]] = []

    for record in records:
        event = record.event
        process = event["process"]
        if (
            event["binding_status"] != "bound"
            or event["plan_id"] != plan.plan_id
            or event["launch_id"] != launch_id
            or process.get("assignment_source") != "host"
        ):
            raise HostObservationError(
                "journal contains unbound or cross-launch evidence"
            )
        if (
            event["observation_kind"] in {"scheduler_resolution", "scheduler_dispatch"}
            and event["controller_instance_id"] != controller_instance
        ):
            raise HostObservationError(
                "scheduler evidence has another controller identity"
            )
        entry = event["entry_point"]
        binding = by_entry.get((entry["group"], entry["name"], entry["value"]))
        if binding is None or event["event"] != "invoked":
            other_records.append(_evidence_record(record))
            continue
        obligation = obligations[binding.obligation]
        slot = (process["host"], process["role"], process["ordinal"])
        expected_epoch = required_by_slot.get(slot)
        if (
            expected_epoch is None
            or process["role"] != obligation.role
            or process["ordinal"] not in obligation.required_ordinals
        ):
            raise HostObservationError(
                "effect evidence is outside its bound obligation target set"
            )
        evidence = _evidence_record(record)
        if process["process_epoch"] != expected_epoch:
            stale_records[binding.obligation].append(evidence)
            continue
        linux = read_linux_process_identity(process["pid"], process["start_identity"])
        observed = {
            "host": process["host"],
            "role": process["role"],
            "ordinal": process["ordinal"],
            "process_epoch": process["process_epoch"],
            **linux,
            "assignment_source": "host",
        }
        existing = effects[binding.obligation].get(slot)
        if existing is not None and existing != observed:
            raise HostObservationError("one target slot has multiple live identities")
        linux_key = (
            process["host"],
            linux["pid"],
            linux["start_ticks"],
        )
        prior_slot = linux_slots.setdefault(linux_key, slot)
        if prior_slot != slot:
            raise HostObservationError(
                "one Linux identity covers multiple target slots"
            )
        effects[binding.obligation][slot] = observed
        effect_records[binding.obligation].append(evidence)
        if event["observation_kind"] == "scheduler_dispatch":
            controller_bound[binding.obligation] = True

    obligation_results: dict[str, dict[str, Any]] = {}
    all_effects: dict[tuple[str, str, int], dict[str, Any]] = {}
    for obligation_id in obligations:
        binding = by_obligation[obligation_id]
        plugin = plugins[binding.plugin_id]
        observed = effects[obligation_id]
        targets = targets_by_obligation[obligation_id]
        observed_processes = [observed[key] for key in sorted(observed)]
        all_effects.update(observed)
        coverage = len(observed_processes) / len(targets)
        obligation_results[obligation_id] = {
            "plugin_id": plugin.id,
            "artifact_digest": "sha256:" + plugin.artifact_sha256,
            "entry_point": {
                "group": binding.group,
                "name": binding.name,
                "value": binding.value,
            },
            "controller_binding": {
                "source": (
                    "scheduler_dispatch" if controller_bound[obligation_id] else None
                ),
                "value": (
                    controller_instance if controller_bound[obligation_id] else None
                ),
            },
            "effect_records": effect_records[obligation_id],
            "stale_effect_records": stale_records[obligation_id],
            "effect_process_identities": observed_processes,
            "plugin_invoked": bool(observed_processes),
            "coverage": coverage,
            "complete_coverage": coverage == 1.0,
        }

    return {
        "schema": OBSERVATION_SCHEMA,
        "plan_id": plan.plan_id,
        "launch_id": launch_id,
        "journal_directory": {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        },
        "audited_event_count": len(records),
        "other_records": other_records,
        "obligations": obligation_results,
        "effect_process_identities": [all_effects[key] for key in sorted(all_effects)],
        "complete_coverage": all(
            result["complete_coverage"] for result in obligation_results.values()
        ),
    }
