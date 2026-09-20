"""False-effective experiment control plane; no production-result defaults."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import subprocess
import time
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
LATIN_SQUARE = (
    ("vanilla-vllm-entry-points", "manual-integration", "ecpa"),
    ("manual-integration", "ecpa", "vanilla-vllm-entry-points"),
    ("ecpa", "vanilla-vllm-entry-points", "manual-integration"),
)
RULE_VERSION = "ecpa-false-effective-oracle/v1"
SEMANTIC_ENV = (
    "VLLM_USE_V1",
    "VLLM_ATTENTION_BACKEND",
    "VLLM_WORKER_MULTIPROC_METHOD",
    "CUDA_VISIBLE_DEVICES",
    "CUDA_DEVICE_ORDER",
    "ASCEND_RT_VISIBLE_DEVICES",
    "NCCL_DEBUG",
    "NCCL_SOCKET_IFNAME",
    "HCCL_CONNECT_TIMEOUT",
    "LD_PRELOAD",
    "PYTHONHASHSEED",
)
ALLOW_ENV = {
    "LANG",
    "LC_ALL",
    "PATH",
    "PYTHONPATH",
    "ECPA_EVALUATION_ARM",
    "ECPA_ACTIVATION_CONTRACT",
    *SEMANTIC_ENV,
}
VERIFIED_ADAPTER_REGISTRY = Path(__file__).with_name("verified-adapters.json")
FORMAL_HOST_OBSERVABLES = {
    "service-ready",
    "workload-complete",
    "fault-injected",
    "observer-captured",
    "service-shutdown",
    "activation-path",
    "effective-claim",
    "plugin-invoked",
    "coverage",
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def safe_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root.resolve() and root.resolve() not in candidate.parents:
        raise ValueError("artifact path escapes run root")
    return candidate


def validate_formal_adapter_verification(
    record: dict[str, Any], command: dict[str, Any]
) -> None:
    """Recheck formal provenance against the repository-owned adapter registry."""
    registry_bytes = VERIFIED_ADAPTER_REGISTRY.read_bytes()
    registry = json.loads(registry_bytes)
    if (
        registry_bytes != canonical(registry) + b"\n"
        or registry.get("schema") != "ecpa-formal-adapter-registry/v1"
    ):
        raise ValueError("verified adapter registry is not canonical")
    rows = registry.get("adapters", [])
    entries = {entry.get("id"): entry for entry in rows}
    if None in entries or len(entries) != len(rows):
        raise ValueError("verified adapter registry contains invalid or duplicate ids")
    verification = record.get("identity", {}).get("adapter_verification")
    entry = entries.get(verification.get("verification_id"))
    if entry is None:
        raise ValueError("formal adapter is absent from the trusted registry")
    expected_contract = {
        "vanilla-vllm-entry-points": "entry-points-unmanaged",
        "manual-integration": "explicit-manual-hooks",
        "ecpa": "manager-controlled-activation",
    }[record["arm"]]
    if (
        entry.get("arm") != record["arm"]
        or entry.get("activation_contract") != expected_contract
        or entry.get("evidence_owner") != "vllm-hust-host"
        or entry.get("evidence_channel") != "host-owned-event-stream"
        or entry.get("host_event_schema") != "ecpa-host-runtime-evidence/v1"
        or not FORMAL_HOST_OBSERVABLES.issubset(
            set(entry.get("required_observables", []))
        )
    ):
        raise ValueError("trusted registry entry does not satisfy the formal contract")
    expected = {
        "registry_schema": registry["schema"],
        "verification_id": entry["id"],
        "registry_digest": digest_bytes(registry_bytes),
        "sut_command": verification.get("sut_command"),
        "observer_command": verification.get("observer_command"),
        "activation_probe": verification.get("activation_probe"),
        "evidence_owner": entry.get("evidence_owner"),
        "evidence_channel": entry.get("evidence_channel"),
        "host_event_schema": entry.get("host_event_schema"),
        "required_observables": sorted(entry.get("required_observables", [])),
    }
    if verification != expected:
        raise ValueError("formal adapter metadata differs from the trusted registry")

    activation_probe = verification.get("activation_probe")
    registered_probe = entry.get("activation_probe")
    if not isinstance(activation_probe, dict) or not isinstance(registered_probe, dict):
        raise ValueError("formal activation probe metadata is missing")
    expected_options = {
        "vanilla-vllm-entry-points": [
            "--disable-ecpa-manager",
            "--enable-entrypoints",
        ],
        "manual-integration": ["--disable-ecpa-manager", "--manual-hooks"],
        "ecpa": ["--disable-entrypoints", "--enable-ecpa-manager"],
    }[record["arm"]]
    try:
        probe_stdout = base64.b64decode(
            activation_probe.get("stdout_base64", ""), validate=True
        )
        probe_stderr = base64.b64decode(
            activation_probe.get("stderr_base64", ""), validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("formal activation probe bytes are invalid") from exc
    probe_output = probe_stdout + probe_stderr
    expected_receipt = {
        "schema": "ecpa-activation-probe/v1",
        "activation_contract": expected_contract,
        "accepted_options": sorted(expected_options),
    }
    if (
        activation_probe.get("exit_code") != 0
        or activation_probe.get("required_options") != sorted(expected_options)
        or activation_probe.get("command", {}).get("digest")
        != registered_probe.get("command_digest")
        or not isinstance(activation_probe.get("output_sha256"), str)
        or activation_probe.get("output_sha256") != digest_bytes(probe_output)
        or len(probe_output) > 1024 * 1024
        or activation_probe.get("receipt") != expected_receipt
        or probe_stdout != canonical(expected_receipt) + b"\n"
    ):
        raise ValueError("formal activation probe does not satisfy the registry")

    fixture_root = (Path(__file__).parents[2] / "tests" / "fixtures").resolve()
    fixture_files = [path for path in fixture_root.rglob("*") if path.is_file()]
    fixture_digests = {digest_file(path) for path in fixture_files}
    fixture_markers = {str(fixture_root), "tests/fixtures", "tests\\fixtures"}
    for role, fingerprint, registered_digest in (
        ("SUT", verification["sut_command"], entry.get("sut_command_digest")),
        (
            "observer",
            verification["observer_command"],
            entry.get("observer_command_digest"),
        ),
        (
            "activation probe",
            activation_probe["command"],
            registered_probe.get("command_digest"),
        ),
    ):
        if not isinstance(fingerprint, dict):
            raise ValueError(f"{role} fingerprint is missing")
        values = [fingerprint.get("executable"), *fingerprint.get("arguments", [])]
        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"{role} fingerprint contains a non-string argv")
            if any(marker in value for marker in fixture_markers):
                raise ValueError(
                    f"{role} fixture-referencing command is forbidden for formal-real"
                )
            candidate = Path(value)
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            try:
                content = resolved.read_text(errors="ignore")
            except OSError:
                content = ""
            if (
                resolved.is_relative_to(fixture_root)
                or digest_file(resolved) in fixture_digests
                or any(marker in content for marker in fixture_markers)
            ):
                raise ValueError(
                    f"{role} fixture-referencing command is forbidden for formal-real"
                )
        unsigned = {key: value for key, value in fingerprint.items() if key != "digest"}
        if (
            fingerprint.get("digest") != digest_bytes(canonical(unsigned))
            or fingerprint.get("digest") != registered_digest
        ):
            raise ValueError(f"{role} fingerprint differs from the trusted registry")
        executable = Path(fingerprint["executable"])
        if not executable.is_file() or digest_file(executable) != fingerprint.get(
            "executable_sha256"
        ):
            raise ValueError(f"{role} executable no longer matches its fingerprint")
        for artifact in fingerprint.get("argument_files", []):
            path = Path(artifact["path"])
            if (
                not path.is_file()
                or digest_file(path) != artifact.get("sha256")
                or path.resolve()
                != Path(fingerprint["arguments"][artifact["index"]]).resolve()
            ):
                raise ValueError(
                    f"{role} argument file no longer matches its fingerprint"
                )

    sut_fingerprint = verification["sut_command"]
    observer_fingerprint = verification["observer_command"]
    probe_fingerprint = activation_probe["command"]
    if probe_fingerprint.get("executable") != sut_fingerprint.get(
        "executable"
    ) or probe_fingerprint.get("arguments") != [
        *sut_fingerprint.get("arguments", []),
        "--ecpa-formal-activation-probe",
    ]:
        raise ValueError("activation probe does not exercise the registered SUT argv")
    sut_argv = command.get("sut_process", {}).get("argv", [])
    observer_argv = command.get("observer_process", {}).get("argv", [])
    if (
        not sut_argv
        or Path(sut_argv[0]).resolve() != Path(sut_fingerprint["executable"])
        or sut_argv[1:] != sut_fingerprint["arguments"]
        or command.get("argv") != sut_argv
    ):
        raise ValueError("executed SUT argv differs from the registered command")
    if (
        not observer_argv
        or Path(observer_argv[0]).resolve() != Path(observer_fingerprint["executable"])
        or observer_argv[1:] != observer_fingerprint["arguments"]
    ):
        raise ValueError("executed observer argv differs from the registered command")


def canonical_record_core(record: dict[str, Any]) -> dict[str, Any]:
    """Fields sealed by the runner receipt; receipt pointers are cycle-excluded."""
    return {
        key: record.get(key)
        for key in (
            "schema",
            "status",
            "evidence_class",
            "measurement_source",
            "cell_id",
            "scenario",
            "arm",
            "start_id",
            "repetition",
            "arm_order",
            "identity",
            "command",
            "observations",
            "observer_binding",
            "missing_reason",
            "intake_digest",
            "oracle",
        )
    } | {
        "artifact_digests": {
            name: record.get("artifacts", {}).get("digests", {}).get(name)
            for name in sorted(record.get("artifacts", {}).get("digests", {}))
            if name != "runner-receipt.json"
        }
    }


def sanitized_env(source: dict[str, str]) -> dict[str, Any]:
    secret_words = ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL")
    result: dict[str, Any] = {}
    for key, value in sorted(source.items()):
        if key in ALLOW_ENV:
            result[key] = value
        elif any(word in key.upper() for word in secret_words):
            result[key] = {"redacted": True, "sha256": digest_bytes(value.encode())}
    return result


def run_command(
    run_dir: Path,
    argv: list[str],
    *,
    env: dict[str, str],
    timeout_s: float,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=False)
    stdout_path = run_dir / "stdout.bin"
    stderr_path = run_dir / "stderr.bin"
    env_path = run_dir / "environment.json"
    command_path = run_dir / "command.json"
    manifest = sanitized_env(env)
    env_path.write_bytes(canonical(manifest) + b"\n")
    wall_start = time.time_ns()
    mono_start = time.monotonic_ns()
    timed_out = False
    signal = None
    try:
        completed = subprocess.run(
            argv,
            cwd=run_dir,
            env=env,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        exit_code = completed.returncode
        if exit_code < 0:
            signal = -exit_code
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = None
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
    mono_end = time.monotonic_ns()
    wall_end = time.time_ns()
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    command = {
        "argv": argv,
        "cwd": str(run_dir.resolve()),
        "environment_manifest": env_path.name,
        "wall_start_ns": wall_start,
        "wall_end_ns": wall_end,
        "monotonic_start_ns": mono_start,
        "monotonic_end_ns": mono_end,
        "exit_code": exit_code,
        "signal": signal,
        "timeout": timed_out,
    }
    command = {
        **command,
        "stdout": stdout_path.name,
        "stdout_sha256": digest_file(stdout_path),
        "stderr": stderr_path.name,
        "stderr_sha256": digest_file(stderr_path),
        "environment_sha256": digest_file(env_path),
    }
    command_path.write_bytes(canonical(command) + b"\n")
    return {**command, "command_sha256": digest_file(command_path)}


def validate_required_process_snapshot(
    required: Any,
) -> tuple[tuple[str, str, int, int], ...]:
    """Validate and freeze the logical target identity before a formal launch."""
    required_fields = {"host", "role", "ordinal", "process_epoch"}
    if not isinstance(required, list) or not required:
        raise ValueError("formal target process snapshot is missing")

    required_keys: list[tuple[str, str, int, int]] = []
    for item in required:
        if not isinstance(item, dict) or set(item) != required_fields:
            raise ValueError("formal target process snapshot is malformed")
        host, role = item.get("host"), item.get("role")
        ordinal, epoch = item.get("ordinal"), item.get("process_epoch")
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
            raise ValueError("formal target process snapshot is malformed")
        required_keys.append((host, role, ordinal, epoch))
    logical_slots = [(host, role, ordinal) for host, role, ordinal, _ in required_keys]
    if len(logical_slots) != len(set(logical_slots)):
        raise ValueError("formal target process snapshot contains duplicates")
    if required_keys != sorted(required_keys):
        raise ValueError("formal target process snapshot is not canonical")
    return tuple(required_keys)


def formal_process_coverage(
    record: dict[str, Any],
    invoked_event: dict[str, Any] | None,
    coverage_event: dict[str, Any] | None,
    reasons: list[str],
) -> float | None:
    """Recompute formal hook coverage from a Plan-bound target snapshot.

    The runner-owned controller identity proves only which process answered the
    phase protocol. Runtime-effect coverage is instead derived from distinct
    host-assigned process identities observed at the hook boundary.
    """
    try:
        required_keys = validate_required_process_snapshot(
            record.get("identity", {}).get("required_processes")
        )
    except ValueError as exc:
        reasons.append(str(exc))
        return None

    observed = (
        invoked_event.get("effect_process_identities")
        if isinstance(invoked_event, dict)
        else None
    )
    if not isinstance(observed, list):
        reasons.append("formal invocation lacks effect process identities")
        return None

    observed_fields = {
        "host",
        "role",
        "ordinal",
        "process_epoch",
        "pid",
        "start_ticks",
        "start_identity",
        "argv",
        "assignment_source",
    }
    observed_keys: list[tuple[str, str, int, int]] = []
    linux_identities: list[tuple[str, int, int, tuple[str, ...]]] = []
    malformed = False
    for item in observed:
        if not isinstance(item, dict) or set(item) != observed_fields:
            malformed = True
            break
        host, role = item.get("host"), item.get("role")
        ordinal, epoch = item.get("ordinal"), item.get("process_epoch")
        pid, start_ticks, argv = (
            item.get("pid"),
            item.get("start_ticks"),
            item.get("argv"),
        )
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
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or isinstance(start_ticks, bool)
            or not isinstance(start_ticks, int)
            or start_ticks <= 0
            or not isinstance(argv, list)
            or not argv
            or any(not isinstance(arg, str) or not arg for arg in argv)
            or item.get("start_identity") != f"pid:{pid}:start_ticks:{start_ticks}"
            or item.get("assignment_source") != "host"
        ):
            malformed = True
            break
        observed_keys.append((host, role, ordinal, epoch))
        linux_identities.append((host, pid, start_ticks, tuple(argv)))
    if malformed:
        reasons.append("formal effect process identity is malformed")
        return None
    if len(observed_keys) != len(set(observed_keys)) or len(linux_identities) != len(
        set(linux_identities)
    ):
        reasons.append("formal effect process identities contain duplicates")
        return None
    if not set(observed_keys).issubset(required_keys):
        reasons.append("formal effect process is outside the target snapshot")
        return None

    invoked = invoked_event.get("value") if invoked_event else None
    if not isinstance(invoked, bool) or invoked != bool(observed_keys):
        reasons.append("plugin invocation claim disagrees with process evidence")
    computed = len(observed_keys) / len(required_keys)
    reported = coverage_event.get("value") if coverage_event else None
    if (
        isinstance(reported, bool)
        or not isinstance(reported, (int, float))
        or not math.isfinite(reported)
        or not math.isclose(reported, computed, rel_tol=0.0, abs_tol=1e-12)
    ):
        reasons.append("reported coverage disagrees with process evidence")
    return computed


def oracle(scenario: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    observations = record["observations"]
    forbidden = {"truth", "false_effective", "conflict_truth"}
    if any(forbidden.intersection(item) for item in observations):
        raise ValueError("SUT observations contain oracle-owned truth fields")
    names = [item.get("event") for item in observations]
    duplicate = sorted({name for name in names if names.count(name) > 1})
    events = {item["event"]: item for item in observations}
    required = [
        *scenario["expected_observable"],
        "service-ready",
        "workload-complete",
        "fault-injected",
        "observer-captured",
        "effective-claim",
        "plugin-invoked",
        "service-shutdown",
    ]
    if record.get("evidence_class") == "formal-real":
        required.append("coverage")
    reasons = [f"missing observable: {name}" for name in required if name not in events]
    reasons.extend(f"duplicate observable: {name}" for name in duplicate)
    causal_evidence = record.get("evidence_class") in {
        "formal-real",
        "interface-fixture",
    }
    if causal_evidence:
        if not record.get("command", {}).get("phase_complete"):
            reasons.append("runner did not confirm every lifecycle phase")
        if record.get("command", {}).get("premature_exit"):
            reasons.append("SUT exited before runner shutdown phase")
        lifecycle = [
            "service-ready",
            "workload-complete",
            "fault-injected",
            "observer-captured",
            "service-shutdown",
        ]
        expected_source = (
            "host-observer"
            if record.get("evidence_class") == "formal-real"
            else "interface-observer"
        )
        execution_identity = record.get("command", {}).get("execution_identity", {})
        invocation_rows = record.get("command", {}).get("phase_invocations", [])
        invocations = {item.get("phase"): item for item in invocation_rows}
        if set(execution_identity) != {
            "plan_id",
            "launch_id",
            "controller_instance",
        } or not all(execution_identity.values()):
            reasons.append("missing plan/launch/controller execution identity")
        if (
            len(invocation_rows) != len(lifecycle)
            or [item.get("phase") for item in invocation_rows] != lifecycle
            or [item.get("sequence") for item in invocation_rows]
            != list(range(1, len(lifecycle) + 1))
            or len(invocations) != len(lifecycle)
            or len({item.get("challenge") for item in invocation_rows})
            != len(lifecycle)
            or len({item.get("invocation_id") for item in invocation_rows})
            != len(lifecycle)
            or any(not item.get("acknowledged") for item in invocation_rows)
        ):
            reasons.append("phase invocation identity is incomplete")
        sut_identity = (
            record.get("command", {}).get("sut_process", {}).get("linux_identity")
        )
        for name in required:
            event = events.get(name)
            if event and event.get("source_role") != expected_source:
                reasons.append(f"untrusted observable source: {name}")
            if event and event.get("clock") != "monotonic":
                reasons.append(f"invalid clock: {name}")
            phase = name if name in lifecycle else "observer-captured"
            invocation = invocations.get(phase, {})
            if event and any(
                event.get(field) != execution_identity.get(field)
                for field in ("plan_id", "launch_id", "controller_instance")
            ):
                reasons.append(f"execution identity mismatch: {name}")
            if event and event.get("invocation_id") != invocation.get("invocation_id"):
                reasons.append(f"invocation identity mismatch: {name}")
            if event and (
                event.get("sequence") != invocation.get("sequence")
                or event.get("challenge") != invocation.get("challenge")
                or event.get("causal_ack") is not True
            ):
                reasons.append(f"causal acknowledgement mismatch: {name}")
            if event and event.get("sut_process_identity") != sut_identity:
                reasons.append(f"observer SUT identity mismatch: {name}")
        times = [events.get(name, {}).get("monotonic_ns") for name in lifecycle]
        if all(isinstance(value, int) for value in times):
            if times != sorted(times) or len(set(times)) != len(times):
                reasons.append("lifecycle timestamps are not strictly ordered")
            bounds = record.get("command", {}).get("phase_bounds", {})
            for name, timestamp in zip(lifecycle, times, strict=True):
                phase = bounds.get(name)
                if not phase or not phase[0] <= timestamp <= phase[1]:
                    reasons.append(f"observable outside runner phase: {name}")
        else:
            reasons.append("lifecycle monotonic timestamp missing")
        fault = events.get("fault-injected", {}).get("value")
        if fault != scenario["id"]:
            reasons.append("fault observable does not match frozen scenario")
        boolean_lifecycle = [name for name in lifecycle if name != "fault-injected"]
        if any(
            events.get(name, {}).get("value") is not True for name in boolean_lifecycle
        ):
            reasons.append("lifecycle value must be true")
        activation = events.get("activation-path")
        expected_contract = record.get("identity", {}).get("activation_contract")
        if not activation:
            reasons.append("missing observable: activation-path")
        elif activation.get("value") != expected_contract:
            reasons.append("activation path does not match adapter contract")
        elif (
            activation.get("source_role") != expected_source
            or activation.get("clock") != "monotonic"
        ):
            reasons.append("activation path lacks trusted observer provenance")
        if record.get("evidence_class") == "formal-real":
            verification = record.get("identity", {}).get("adapter_verification", {})
            if (
                verification.get("evidence_owner") != "vllm-hust-host"
                or verification.get("evidence_channel") != "host-owned-event-stream"
            ):
                reasons.append("formal result lacks registry-pinned host evidence")
    truth = scenario["truth"]
    claimed = bool(events.get("effective-claim", {}).get("value", False))
    invoked = bool(events.get("plugin-invoked", {}).get("value", False))
    covered = events.get("coverage", {}).get("value")
    if record.get("evidence_class") == "formal-real":
        covered = formal_process_coverage(
            record,
            events.get("plugin-invoked"),
            events.get("coverage"),
            reasons,
        )
    decision = events.get("conflict-decision", {}).get("value")
    rollback = events.get("rollback-class", {}).get("value")
    false_effective = claimed and (
        not truth["activation_possible"]
        or not invoked
        or (record.get("evidence_class") == "formal-real" and covered != 1.0)
    )
    rollback_success = None
    if truth["rollback_required"]:
        rollback_success = rollback in {"RESTORED_STRONG", "BEHAVIORAL"}
    launch_ns = record.get("command", {}).get("monotonic_start_ns")
    ready_ns = events.get("service-ready", {}).get("monotonic_ns")
    startup_ms = None
    if launch_ns is not None and ready_ns is not None and ready_ns >= launch_ns:
        startup_ms = (ready_ns - launch_ns) / 1_000_000
    outcome = {
        "false_effective": false_effective,
        "activation_event_coverage": covered,
        "conflict_truth": truth["conflict"],
        "conflict_decision": decision,
        "rollback_class": rollback,
        "rollback_success": rollback_success,
        "startup_ms": startup_ms,
        "recovery_ms": None,
        "throughput": None,
        "latency_p99_ms": None,
        "evidence_bytes": record["artifacts"].get("evidence_bytes"),
        "message_bytes": record["artifacts"].get("message_bytes"),
    }
    inputs = {"scenario": scenario, "observations": observations}
    record_binding = {
        key: record.get(key)
        for key in (
            "schema",
            "status",
            "evidence_class",
            "measurement_source",
            "cell_id",
            "scenario",
            "arm",
            "start_id",
            "repetition",
            "arm_order",
            "identity",
            "command",
            "observations",
            "missing_reason",
            "intake_digest",
        )
    }
    return {
        "schema": RULE_VERSION,
        "input_digest": digest_bytes(canonical(inputs)),
        "record_digest": digest_bytes(canonical(record_binding)),
        "verdict": "INCOMPLETE" if reasons else "PASS",
        "reasons": reasons,
        "outcome": outcome,
    }


def validate_record(
    record: dict[str, Any],
    root: Path,
    *,
    scenario: dict[str, Any] | None = None,
    protocol: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
) -> None:
    canonical(record)
    artifact_root = safe_path(root, record.get("artifact_root", "."))
    if schema is not None:
        Draft7Validator(schema).validate(record)
    if record["status"] == "planned":
        if record["missing_reason"] is None:
            raise ValueError("planned record requires missing reason")
        return
    command = record.get("command")
    artifacts = record.get("artifacts", {})
    if record["status"] == "complete" and record["evidence_class"] == "formal-real":
        identity_fields = {
            "model",
            "dataset",
            "workload",
            "hardware",
            "software",
            "observer",
            "runtime_commit",
            "plugin_commits",
            "topology",
            "fault_plan",
            "fault",
            "warm_state",
            "git_dirty",
            "container_digest",
            "cpu",
            "gpu",
            "npu",
            "driver",
            "runtime",
            "semantic_environment",
        }
        missing_identity = identity_fields.difference(record["identity"])
        if missing_identity:
            raise ValueError(
                f"formal complete missing identity: {sorted(missing_identity)}"
            )
        if any(value is None for value in record["identity"].values()):
            raise ValueError("formal complete identity values must not be null")
        for field in (
            "raw_log",
            "environment",
            "command",
            "oracle",
            "intake",
            "observations",
            "scenario",
            "protocol",
        ):
            if not artifacts.get(field):
                raise ValueError(f"formal complete missing {field}")
            name = artifacts[field]
            if name not in artifacts.get("digests", {}):
                raise ValueError(f"formal complete missing digest for {field}")
    if command is None:
        raise ValueError("executed record requires command")
    for name, expected in artifacts.get("digests", {}).items():
        path = safe_path(artifact_root, name)
        if not path.is_file() or digest_file(path) != expected:
            raise ValueError(f"artifact digest mismatch: {name}")
    if record["status"] != "planned":
        intake_path = safe_path(artifact_root, artifacts.get("intake", ""))
        intake = json.loads(intake_path.read_text())
        if digest_file(intake_path) != record.get("intake_digest"):
            raise ValueError("runner intake digest mismatch")
        for field in (
            "evidence_class",
            "measurement_source",
            "scenario",
            "arm",
            "start_id",
            "repetition",
            "arm_order",
            "identity",
        ):
            if record[field] != intake[field]:
                raise ValueError(f"record relabelled outside runner intake: {field}")
        if command.get("execution_identity") != intake.get("execution_identity"):
            raise ValueError("execution identity differs from runner intake")
        if record["evidence_class"] in {"formal-real", "interface-fixture"}:
            sut = command.get("sut_process", {})
            observer = command.get("observer_process", {})
            if (
                not sut.get("pid")
                or not observer.get("pid")
                or sut["pid"] == observer["pid"]
            ):
                raise ValueError("formal SUT and observer must be distinct processes")
            if sut.get("argv") == observer.get("argv"):
                raise ValueError("formal SUT and observer argv must differ")
            for role, process in (("SUT", sut), ("observer", observer)):
                linux_identity = process.get("linux_identity", {})
                expected_start = (
                    f"pid:{process.get('pid')}@ticks:"
                    f"{linux_identity.get('start_ticks')}"
                )
                if (
                    linux_identity.get("pid") != process.get("pid")
                    or linux_identity.get("argv") != process.get("argv")
                    or process.get("start_identity") != expected_start
                ):
                    raise ValueError(f"{role} PID/start identity mismatch")
            observer_pipe = safe_path(artifact_root, artifacts["observer_pipe"])
            if digest_file(observer_pipe) != command.get("observer_pipe_sha256"):
                raise ValueError("observer pipe bytes digest mismatch")
            expected_binding = {
                "pid": observer.get("pid"),
                "start_identity": observer.get("start_identity"),
                "argv": observer.get("argv"),
                **command.get("execution_identity", {}),
            }
            if record.get("observer_binding") != expected_binding:
                raise ValueError("observer result binding mismatch")
            if record["evidence_class"] == "formal-real":
                verification = record.get("identity", {}).get("adapter_verification")
                if (
                    record.get("identity", {}).get("fixture_only") is not False
                    or not isinstance(verification, dict)
                    or verification.get("evidence_owner") != "vllm-hust-host"
                    or verification.get("evidence_channel") != "host-owned-event-stream"
                    or verification.get("host_event_schema")
                    != "ecpa-host-runtime-evidence/v1"
                ):
                    raise ValueError(
                        "formal adapter verification is not registry-owned"
                    )
                validate_formal_adapter_verification(record, command)
            semantic = {
                name: record["identity"]["semantic_environment"].get(name)
                for name in SEMANTIC_ENV
            }
            if semantic != intake.get("semantic_environment"):
                raise ValueError("semantic environment differs from runner intake")
            manifest = json.loads(
                safe_path(artifact_root, artifacts["environment"]).read_text()
            )
            expected_contract = {
                "vanilla-vllm-entry-points": "entry-points-unmanaged",
                "manual-integration": "explicit-manual-hooks",
                "ecpa": "manager-controlled-activation",
            }[record["arm"]]
            if (
                manifest.get("ECPA_EVALUATION_ARM") != record["arm"]
                or manifest.get("ECPA_ACTIVATION_CONTRACT") != expected_contract
                or intake.get("activation_contract") != expected_contract
            ):
                raise ValueError("adapter contract mismatch")
        if scenario is None or protocol is None:
            raise ValueError(
                "executed record validation requires scenario and protocol"
            )
        if digest_bytes(canonical(scenario)) != intake["scenario_digest"]:
            raise ValueError("scenario digest mismatch")
        if digest_bytes(canonical(protocol)) != intake["protocol_digest"]:
            raise ValueError("protocol digest mismatch")
        observation_path = safe_path(artifact_root, artifacts["observations"])
        observation_payload = json.loads(observation_path.read_text())
        raw_observations = observation_payload["events"]
        if raw_observations != record["observations"]:
            raise ValueError("raw observations mismatch")
        if observation_payload.get("observer_binding") != record.get(
            "observer_binding"
        ):
            raise ValueError("raw observer binding mismatch")
        recomputed = oracle(
            scenario, {k: v for k, v in record.items() if k != "oracle"}
        )
        if recomputed != record.get("oracle"):
            raise ValueError("independent oracle mismatch")
        if record["status"] == "complete" and recomputed["verdict"] != "PASS":
            raise ValueError("complete record has incomplete required observations")
        command_disk = json.loads(
            safe_path(artifact_root, artifacts["command"]).read_text()
        )
        if command_disk != record["command"]:
            raise ValueError("disk command differs from record command")
        oracle_disk = json.loads(
            safe_path(artifact_root, artifacts["oracle"]).read_text()
        )
        if oracle_disk != record["oracle"]:
            raise ValueError("disk oracle differs from record oracle")
        receipt_path = safe_path(artifact_root, artifacts.get("receipt", ""))
        receipt = json.loads(receipt_path.read_text())
        expected_receipt = {
            "schema": "ecpa-runner-receipt/v1",
            "core_digest": digest_bytes(canonical(canonical_record_core(record))),
            "status": record["status"],
            "cell_id": record["cell_id"],
            "command_digest": digest_file(
                safe_path(artifact_root, artifacts["command"])
            ),
            "oracle_digest": digest_file(safe_path(artifact_root, artifacts["oracle"])),
            "exit_code": record["command"]["exit_code"],
            "timeout": record["command"]["timeout"],
            "sut_identity": record["command"]
            .get("sut_process", {})
            .get("linux_identity"),
            "observer_identity": record["command"]
            .get("observer_process", {})
            .get("linux_identity"),
            "observer_argv": record["command"].get("observer_process", {}).get("argv"),
            "observer_pipe_sha256": record["command"].get("observer_pipe_sha256"),
            "execution_identity": record["command"].get("execution_identity"),
            "phase_invocations": record["command"].get("phase_invocations"),
            "excluded_fields": ["artifact_root", "receipt_digest"],
        }
        if receipt != expected_receipt or digest_file(receipt_path) != record.get(
            "receipt_digest"
        ):
            raise ValueError("runner receipt mismatch")
        should_complete = (
            command["exit_code"] == 0
            and not command["timeout"]
            and recomputed["verdict"] == "PASS"
        )
        if record["status"] == "complete" and not should_complete:
            raise ValueError("failed execution relabelled complete")


def validate_batch(records: list[dict[str, Any]], root: Path, *, formal: bool) -> None:
    here = Path(__file__).resolve().parent
    scenario_map = {
        item["id"]: item
        for item in json.loads((here / "scenarios.json").read_text())["scenarios"]
    }
    protocol = json.loads((here / "protocol.json").read_text())
    schema = json.loads((here / "raw-record.schema.json").read_text())
    ids = [item["start_id"] for item in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate start_id")
    for record in records:
        validate_record(
            record,
            root,
            scenario=scenario_map.get(record["scenario"]),
            protocol=protocol,
            schema=schema,
        )
        if formal and record["evidence_class"] != "formal-real":
            raise ValueError(
                "fixture-only or synthetic evidence cannot enter formal aggregate"
            )
        if formal and record.get("identity", {}).get("fixture_only"):
            raise ValueError("fixture-only evidence cannot enter formal aggregate")
    complete = [item for item in records if item["status"] == "complete"]
    if formal and complete:
        execution_identities = [
            item.get("command", {}).get("execution_identity", {}) for item in complete
        ]
        launch_ids = [item.get("launch_id") for item in execution_identities]
        controllers = [item.get("controller_instance") for item in execution_identities]
        invocation_ids = [
            invocation.get("invocation_id")
            for item in complete
            for invocation in item.get("command", {}).get("phase_invocations", [])
        ]
        process_identities = [
            (
                process.get("pid"),
                process.get("linux_identity", {}).get("start_ticks"),
            )
            for item in complete
            for process in (
                item.get("command", {}).get("sut_process", {}),
                item.get("command", {}).get("observer_process", {}),
            )
        ]
        if (
            None in launch_ids
            or len(launch_ids) != len(set(launch_ids))
            or None in controllers
            or len(controllers) != len(set(controllers))
            or None in invocation_ids
            or len(invocation_ids) != len(set(invocation_ids))
            or any(None in identity for identity in process_identities)
            or len(process_identities) != len(set(process_identities))
        ):
            raise ValueError(
                "launch/controller/invocation/process identity is not unique"
            )
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in complete:
            groups.setdefault(item["cell_id"], []).append(item)
        for cell, rows in groups.items():
            if len(rows) < 9 or {row["arm"] for row in rows} != set(ARMS):
                raise ValueError(f"cell {cell} lacks 3 starts x 3 arms")
            if any(sum(row["arm"] == arm for row in rows) < 3 for arm in ARMS):
                raise ValueError(f"cell {cell} has fewer than 3 starts per arm")
            for arm in ARMS:
                plan_ids = {
                    row["command"]["execution_identity"]["plan_id"]
                    for row in rows
                    if row["arm"] == arm
                }
                if len(plan_ids) != 1:
                    raise ValueError(f"cell {cell} arm {arm} does not share one plan")
            identities = [
                {
                    k: v
                    for k, v in row["identity"].items()
                    if k
                    not in {
                        "arm",
                        "evaluation_arm",
                        "activation_contract",
                        "adapter_verification",
                    }
                }
                for row in rows
            ]
            if any(value != identities[0] for value in identities[1:]):
                raise ValueError(f"cell {cell} matched-arm metadata mismatch")
            orders = {(row["repetition"], row["arm_order"]) for row in rows}
            if len(orders) != 9:
                raise ValueError(f"cell {cell} order schedule is unbalanced")
            actual = {(row["repetition"], row["arm_order"]): row["arm"] for row in rows}
            expected = {
                (repetition, order): arm
                for repetition, arms in enumerate(LATIN_SQUARE, 1)
                for order, arm in enumerate(arms, 1)
            }
            if actual != expected:
                raise ValueError(f"cell {cell} does not match frozen Latin square")


def wilson(numerator: int, denominator: int) -> list[float] | None:
    if denominator < 3:
        return None
    z = 1.959963984540054
    p = numerator / denominator
    d = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / d
    half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / d
    return [center - half, center + half]


def conflict_metrics(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [row for row in outcomes if row["conflict_truth"] != "not-applicable"]
    tp = sum(
        row["conflict_truth"] == "conflict" and row["conflict_decision"] == "reject"
        for row in rows
    )
    fp = sum(
        row["conflict_truth"] != "conflict" and row["conflict_decision"] == "reject"
        for row in rows
    )
    fn = sum(
        row["conflict_truth"] == "conflict" and row["conflict_decision"] != "reject"
        for row in rows
    )
    tn = sum(
        row["conflict_truth"] != "conflict" and row["conflict_decision"] != "reject"
        for row in rows
    )
    return {
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": tp / (tp + fp) if tp + fp >= 3 else None,
        "recall": tp / (tp + fn) if tp + fn >= 3 else None,
        "null_reason": None
        if min(tp + fp, tp + fn) >= 3
        else "fewer than 3 applicable decisions",
    }


def aggregate(
    records: list[dict[str, Any]], root: Path, *, formal: bool
) -> dict[str, Any]:
    validate_batch(records, root, formal=formal)
    complete = [row for row in records if row["status"] == "complete"]
    scenario_registry = [
        item["id"]
        for item in json.loads(
            (Path(__file__).resolve().parent / "scenarios.json").read_text()
        )["scenarios"]
    ]
    cells = []
    for (scenario, arm), rows in sorted(
        {
            (scenario, arm): [
                row
                for row in records
                if row["scenario"] == scenario and row["arm"] == arm
            ]
            for scenario in scenario_registry
            for arm in ARMS
        }.items()
    ):
        statuses = {
            status: sum(row["status"] == status for row in rows)
            for status in ("planned", "complete", "failed", "excluded")
        }
        valid = [row for row in rows if row["status"] == "complete"]
        outcomes = [row["oracle"]["outcome"] for row in valid]
        false_count = sum(bool(outcome["false_effective"]) for outcome in outcomes)
        coverage = [
            outcome["activation_event_coverage"]
            for outcome in outcomes
            if outcome["activation_event_coverage"] is not None
        ]
        rollback = [
            outcome["rollback_success"]
            for outcome in outcomes
            if outcome["rollback_success"] is not None
        ]
        conflicts = [
            outcome
            for outcome in outcomes
            if outcome["conflict_truth"] != "not-applicable"
        ]
        expected_decision = {
            "conflict": "reject",
            "compatible": "accept",
            "conditional": "conditional",
        }
        tp = sum(
            o["conflict_truth"] == "conflict" and o["conflict_decision"] == "reject"
            for o in conflicts
        )
        fp = sum(
            o["conflict_truth"] != "conflict" and o["conflict_decision"] == "reject"
            for o in conflicts
        )
        fn = sum(
            o["conflict_truth"] == "conflict" and o["conflict_decision"] != "reject"
            for o in conflicts
        )
        tn = sum(
            o["conflict_truth"] != "conflict" and o["conflict_decision"] != "reject"
            for o in conflicts
        )
        cells.append(
            {
                "scenario": scenario,
                "arm": arm,
                "status_counts": statuses,
                "false_effective": None
                if statuses["complete"] < 3
                else {
                    "numerator": false_count,
                    "denominator": len(valid),
                    "rate": false_count / len(valid),
                    "wilson95": wilson(false_count, len(valid)),
                },
                "quality": None
                if statuses["complete"] < 3
                else {
                    "coverage_samples": coverage,
                    "coverage_mean": sum(coverage) / len(coverage)
                    if coverage
                    else None,
                    "conflict_exact_correct": sum(
                        outcome["conflict_decision"]
                        == expected_decision.get(outcome["conflict_truth"])
                        for outcome in conflicts
                    ),
                    "conflict_denominator": len(conflicts),
                    "conflict_confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
                    "conflict_precision": tp / (tp + fp) if tp + fp >= 3 else None,
                    "conflict_recall": tp / (tp + fn) if tp + fn >= 3 else None,
                    "conflict_null_reason": None
                    if min(tp + fp, tp + fn) >= 3
                    else "fewer than 3 applicable decisions",
                    "rollback_successes": sum(value is True for value in rollback),
                    "rollback_denominator": len(rollback),
                },
                "cost": None
                if statuses["complete"] < 3
                else {
                    "startup_ms": [outcome["startup_ms"] for outcome in outcomes],
                    "recovery_ms": [outcome["recovery_ms"] for outcome in outcomes],
                    "evidence_bytes": [
                        outcome["evidence_bytes"] for outcome in outcomes
                    ],
                    "message_bytes": [outcome["message_bytes"] for outcome in outcomes],
                },
                "null_reason": (
                    "fewer than 3 complete independent starts"
                    if statuses["complete"] < 3
                    else None
                ),
            }
        )
    if not complete:
        return {
            "schema": "ecpa-false-effective-aggregate/v1",
            "formal": formal,
            "completed_cells": 0,
            "metrics": None,
            "cells": cells,
            "paired_contrasts": None,
            "conflict_by_arm": {arm: None for arm in ARMS},
            "failure_missing_modes": {
                "planned": sum(row["status"] == "planned" for row in records),
                "failed": sum(row["status"] == "failed" for row in records),
                "excluded": sum(row["status"] == "excluded" for row in records),
            },
            "reason": "no validator-approved complete formal-real cells",
        }
    strata = {}
    for row in complete:
        key = f"{row['scenario']}::{row['arm']}"
        strata.setdefault(key, []).append(row["oracle"]["outcome"])
    paired = []
    for scenario in sorted({row["scenario"] for row in complete}):
        for repetition in (1, 2, 3):
            matched = [
                row
                for row in complete
                if row["scenario"] == scenario and row["repetition"] == repetition
            ]
            if len(matched) == 3:
                values = {
                    row["arm"]: int(row["oracle"]["outcome"]["false_effective"])
                    for row in matched
                }
                paired.append(
                    {
                        "scenario": scenario,
                        "repetition": repetition,
                        "false_effective_delta_ecpa_vs_vanilla": values["ecpa"]
                        - values["vanilla-vllm-entry-points"],
                        "false_effective_delta_ecpa_vs_manual": values["ecpa"]
                        - values["manual-integration"],
                    }
                )
    conflict_by_arm = {
        arm: conflict_metrics(
            [row["oracle"]["outcome"] for row in complete if row["arm"] == arm]
        )
        for arm in ARMS
    }
    return {
        "schema": "ecpa-false-effective-aggregate/v1",
        "formal": formal,
        "completed_cells": len({row["cell_id"] for row in complete}),
        "cells": cells,
        "strata": strata,
        "paired_contrasts": paired,
        "conflict_by_arm": conflict_by_arm,
        "failure_missing_modes": {
            "planned": sum(row["status"] == "planned" for row in records),
            "failed": sum(row["status"] == "failed" for row in records),
            "excluded": sum(row["status"] == "excluded" for row in records),
        },
        "statistic_plan": {
            "binary_rate_interval": "Wilson score 95%",
            "continuous_summary": (
                "median and observed range; range is not a confidence interval"
            ),
            "paired_unit": "scenario x repetition",
        },
        "metrics": {
            "scope": "stratified-only; no mixed-arm primary estimate",
            "n_starts": len(complete),
            "by_scenario_arm": cells,
        },
    }


def project_paper_result(
    record: dict[str, Any], paper_schema: dict[str, Any]
) -> dict[str, Any]:
    outcome = record.get("oracle", {}).get("outcome", {})
    projected = {
        "schema": "ecpa-result/v1",
        "status": (
            "excluded-with-preregistered-reason"
            if record["status"] == "excluded"
            else record["status"]
        ),
        "cell_id": record["cell_id"],
        "hypothesis": "H1",
        "arm": record["arm"],
        "identity": {
            "manager_commit": record["identity"].get("runtime_commit"),
            "host_runtime": record["identity"].get("runtime", "planned-unconfigured"),
            "host_version": (
                json.dumps(record["identity"]["software"], sort_keys=True)
                if "software" in record["identity"]
                else "planned-unconfigured"
            ),
            "plugins": [],
            "providers": [],
            "hardware": record["identity"].get("hardware", "planned-unconfigured"),
            "process_topology": record["identity"].get(
                "topology", "planned-unconfigured"
            ),
            "container_digest": record["identity"].get("container_digest"),
        },
        "protocol": {
            "repetition": record["repetition"],
            "independent_service_start": True,
            "arm_order": record["arm_order"],
            "warm_state": record["identity"].get("warm_state", "cold"),
            "workload": record["identity"].get("workload", "planned-unconfigured"),
            "fault": record["scenario"],
        },
        "outcome": {
            "activation_event_coverage": outcome.get("activation_event_coverage"),
            "false_effective": outcome.get("false_effective"),
            "conflict_truth": outcome.get("conflict_truth"),
            "conflict_decision": outcome.get("conflict_decision"),
            "rollback_success": outcome.get("rollback_success"),
            "recovery_ms": outcome.get("recovery_ms"),
            "startup_ms": outcome.get("startup_ms"),
            "throughput": outcome.get("throughput"),
            "latency_p99_ms": outcome.get("latency_p99_ms"),
            "evidence_bytes": outcome.get("evidence_bytes"),
            "failure_phase": record.get("missing_reason"),
        },
        "artifacts": {
            "raw_log": record["artifacts"].get("raw_log"),
            "manifest": record["artifacts"].get("intake"),
            "plan": record["artifacts"].get("protocol"),
            "evidence": record["artifacts"].get("oracle"),
        },
    }
    Draft7Validator(paper_schema).validate(projected)
    return projected
