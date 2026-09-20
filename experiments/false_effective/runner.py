"""Reference self-test and independently observed formal command runner."""

from __future__ import annotations

import json
import os
import platform
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness import (
    ARMS,
    SEMANTIC_ENV,
    canonical,
    canonical_record_core,
    digest_bytes,
    digest_file,
    oracle,
    run_command,
    safe_path,
    validate_record,
)

HERE = Path(__file__).resolve().parent
VERIFIED_ADAPTER_REGISTRY = HERE / "verified-adapters.json"
FORMAL_HOST_OBSERVABLES = {
    "service-ready",
    "workload-complete",
    "fault-injected",
    "observer-captured",
    "service-shutdown",
    "activation-path",
    "effective-claim",
    "plugin-invoked",
}


def command_references_fixture(values: list[str]) -> bool:
    """Reject direct, textual, or byte-identical fixture command artifacts."""
    fixture_root = (HERE.parents[1] / "tests" / "fixtures").resolve()
    fixture_files = [path for path in fixture_root.rglob("*") if path.is_file()]
    fixture_digests = {digest_file(path) for path in fixture_files}
    markers = {str(fixture_root), "tests/fixtures", "tests\\fixtures"}
    for value in values:
        if any(marker in value for marker in markers):
            return True
        candidate = Path(value)
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if (
            resolved.is_relative_to(fixture_root)
            or digest_file(resolved) in fixture_digests
        ):
            return True
        try:
            content = resolved.read_text(errors="ignore")
        except OSError:
            continue
        if any(marker in content for marker in markers):
            return True
    return False


def parse_proc_stat_start_ticks(stat: str) -> int:
    """Parse Linux /proc/PID/stat field 22 despite spaces/parentheses in comm."""
    close = stat.rfind(")")
    if close < 0:
        raise ValueError("malformed /proc stat comm field")
    fields_from_three = stat[close + 2 :].split()
    if len(fields_from_three) < 20:
        raise ValueError("malformed /proc stat field count")
    return int(fields_from_three[19])


def linux_process_identity(pid: int) -> dict[str, Any]:
    """Read Linux PID identity using /proc stat starttime (field 22)."""
    stat_path = Path(f"/proc/{pid}/stat")
    start_ticks = parse_proc_stat_start_ticks(stat_path.read_text())
    argv_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    confirmed_start_ticks = parse_proc_stat_start_ticks(stat_path.read_text())
    if confirmed_start_ticks != start_ticks:
        raise RuntimeError("process identity changed while reading /proc")
    argv = [
        part.decode(errors="surrogateescape") for part in argv_raw.split(b"\0") if part
    ]
    return {"pid": pid, "start_ticks": start_ticks, "argv": argv}


def wait_for_linux_process_identity(
    process: subprocess.Popen[Any], expected_argv: list[str], timeout_s: float
) -> dict[str, Any]:
    """Wait until exec has installed the exact argv before recording identity."""
    deadline = time.monotonic() + timeout_s
    last_identity: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("process exited before its exec identity was observable")
        try:
            last_identity = linux_process_identity(process.pid)
        except (FileNotFoundError, ProcessLookupError, RuntimeError):
            last_identity = None
        if last_identity is not None and last_identity["argv"] == expected_argv:
            return last_identity
        time.sleep(0.001)
    observed = last_identity["argv"] if last_identity is not None else None
    raise TimeoutError(
        f"process exec identity did not stabilize: expected={expected_argv!r}, "
        f"observed={observed!r}"
    )


def command_fingerprint(executable: str, arguments: list[str]) -> dict[str, Any]:
    """Bind the launched executable and every file-backed argv component."""
    executable_path = Path(executable).resolve(strict=True)
    argument_files = []
    for index, value in enumerate(arguments):
        candidate = Path(value)
        if candidate.is_file():
            resolved = candidate.resolve(strict=True)
            argument_files.append(
                {
                    "index": index,
                    "path": str(resolved),
                    "sha256": digest_file(resolved),
                }
            )
    fingerprint = {
        "executable": str(executable_path),
        "executable_sha256": digest_file(executable_path),
        "arguments": arguments,
        "argument_files": argument_files,
    }
    return {**fingerprint, "digest": digest_bytes(canonical(fingerprint))}


def verified_adapter_contract(
    verification_id: str | None,
    adapter: FormalArmAdapter,
    executable: str,
    arguments: list[str],
    observer_executable: str,
    observer_arguments: list[str],
) -> dict[str, Any]:
    """Resolve a code-reviewed adapter entry; caller assertions are not authority."""
    if not verification_id:
        raise ValueError("real formal execution requires a registry verification id")
    registry_bytes = VERIFIED_ADAPTER_REGISTRY.read_bytes()
    registry = json.loads(registry_bytes)
    if (
        registry_bytes != canonical(registry) + b"\n"
        or registry.get("schema") != "ecpa-formal-adapter-registry/v1"
    ):
        raise ValueError("verified adapter registry must be canonical")
    rows = registry.get("adapters", [])
    entries = {entry["id"]: entry for entry in rows}
    if len(entries) != len(rows):
        raise ValueError("verified adapter registry contains duplicate ids")
    entry = entries.get(verification_id)
    if entry is None:
        raise ValueError("adapter verification id is not in the trusted registry")
    if (
        entry.get("arm") != adapter.arm
        or entry.get("activation_contract") != adapter.activation_contract
        or entry.get("evidence_owner") != "vllm-hust-host"
        or entry.get("evidence_channel") != "host-owned-event-stream"
        or entry.get("host_event_schema") != "ecpa-host-runtime-evidence/v1"
        or not FORMAL_HOST_OBSERVABLES.issubset(
            set(entry.get("required_observables", []))
        )
    ):
        raise ValueError("verified adapter contract does not match the requested arm")
    launch_paths = [executable, observer_executable, *arguments, *observer_arguments]
    if command_references_fixture(launch_paths):
        raise ValueError("fixture-referencing command is forbidden for formal-real")
    sut = command_fingerprint(executable, [*arguments, *adapter.activation_arguments])
    observer = command_fingerprint(observer_executable, observer_arguments)
    if sut["digest"] != entry.get("sut_command_digest"):
        raise ValueError("SUT command differs from the verified adapter artifact")
    if observer["digest"] != entry.get("observer_command_digest"):
        raise ValueError("observer command differs from the verified adapter artifact")
    return {
        "registry_schema": registry.get("schema"),
        "verification_id": verification_id,
        "registry_digest": digest_bytes(registry_bytes),
        "sut_command": sut,
        "observer_command": observer,
        "evidence_owner": entry["evidence_owner"],
        "evidence_channel": entry["evidence_channel"],
        "host_event_schema": entry["host_event_schema"],
        "required_observables": sorted(entry["required_observables"]),
    }


@dataclass(frozen=True)
class FormalArmAdapter:
    arm: str
    activation_contract: str
    activation_arguments: tuple[str, ...]

    def launch(self, executable: str, arguments: list[str], env: dict[str, str]):
        launched = dict(env)
        launched["ECPA_EVALUATION_ARM"] = self.arm
        launched["ECPA_ACTIVATION_CONTRACT"] = self.activation_contract
        return [executable, *arguments, *self.activation_arguments], launched


class VanillaVLLMAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__(
            "vanilla-vllm-entry-points",
            "entry-points-unmanaged",
            ("--disable-ecpa-manager", "--enable-entrypoints"),
        )


class ManualIntegrationAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__(
            "manual-integration",
            "explicit-manual-hooks",
            ("--disable-ecpa-manager", "--manual-hooks"),
        )


class ECPAAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__(
            "ecpa",
            "manager-controlled-activation",
            ("--enable-ecpa-manager", "--disable-entrypoints"),
        )


def _git_measurement() -> tuple[str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=HERE,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=HERE,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        return commit, dirty
    except (OSError, subprocess.SubprocessError):
        return "unavailable", True


def measured_identity(declared: dict[str, Any], arm: str, env: dict[str, str]):
    commit, dirty = _git_measurement()
    return dict(declared) | {
        "arm": arm,
        "hardware": platform.machine(),
        "cpu": platform.processor() or platform.machine(),
        "runtime": platform.python_version(),
        "runtime_commit": commit,
        "git_dirty": dirty,
        "semantic_environment": {
            name: env.get(name, "<unset>") for name in SEMANTIC_ENV
        },
        "evaluation_arm": env.get("ECPA_EVALUATION_ARM", arm),
        "activation_contract": env.get("ECPA_ACTIVATION_CONTRACT", "reference-only"),
    }


def _read_events(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        events = json.loads(path.read_text())["events"]
        if not isinstance(events, list):
            raise TypeError("events is not a list")
        return events, None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [], f"observer result unavailable or invalid: {type(exc).__name__}"


def _run_start(
    root: Path,
    scenario: dict[str, Any],
    arm: str,
    repetition: int,
    arm_order: int,
    *,
    argv: list[str],
    env: dict[str, str],
    timeout_s: float,
    evidence_class: str,
    measurement_source: str,
    identity: dict[str, Any],
    observations_from_stdout: bool,
    observer_argv: list[str] | None = None,
    execution_identity: dict[str, str] | None = None,
) -> dict[str, Any]:
    start_id = f"{scenario['id']}-r{repetition}-{arm}"
    run_dir = root / "starts" / start_id
    result_path = run_dir / "observer-result.json"
    observer_binding = None
    if observer_argv is None:
        command = run_command(run_dir, argv, env=dict(env), timeout_s=timeout_s)
        command_digest = command.pop("command_sha256")
    else:
        if execution_identity is None:
            raise ValueError("observed execution requires plan and launch identity")
        run_dir.mkdir(parents=True, exist_ok=False)
        manifest = __import__("harness").sanitized_env(env)
        (run_dir / "environment.json").write_bytes(canonical(manifest) + b"\n")
        sut_env = {
            key: value
            for key, value in env.items()
            if not key.startswith("ECPA_OBSERVER_")
            and not key.startswith("ECPA_RUNNER_")
            and key != "ECPA_FROZEN_SCENARIO"
        }
        sut_start = time.monotonic_ns()
        sut = subprocess.Popen(
            argv,
            cwd=run_dir,
            env=sut_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        sut_identity = wait_for_linux_process_identity(sut, argv, timeout_s)
        read_fd, write_fd = os.pipe()
        observer_env = dict(env)
        observer_env["ECPA_OBSERVER_FD"] = str(write_fd)
        observer_env["ECPA_EXPECTED_ARM"] = arm
        observer_env["ECPA_EXPECTED_CONTRACT"] = env["ECPA_ACTIVATION_CONTRACT"]
        observer_env["ECPA_SUT_PID"] = str(sut.pid)
        observer_env["ECPA_PLAN_ID"] = execution_identity["plan_id"]
        observer_env["ECPA_LAUNCH_ID"] = execution_identity["launch_id"]
        observer_env["ECPA_CONTROLLER_INSTANCE"] = execution_identity[
            "controller_instance"
        ]
        observer_env["ECPA_OBSERVER_SOURCE_ROLE"] = (
            "host-observer" if evidence_class == "formal-real" else "interface-observer"
        )
        observer_start = time.monotonic_ns()
        observer = subprocess.Popen(
            observer_argv,
            cwd=run_dir,
            env=observer_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            pass_fds=(write_fd,),
        )
        observer_identity = wait_for_linux_process_identity(
            observer, observer_argv, timeout_s
        )
        os.close(write_fd)
        phase_bounds: dict[str, list[int]] = {}
        phase_invocations: list[dict[str, Any]] = []
        sut_lines: list[str] = []

        def drive(phase: str, instruction: str, sequence: int) -> bool:
            start = time.monotonic_ns()
            challenge = secrets.token_hex(16)
            invocation_id = f"{execution_identity['launch_id']}:{sequence}:{challenge}"
            if sut.stdin is not None:
                try:
                    sut.stdin.write(
                        json.dumps(
                            {
                                "command": instruction,
                                "phase": phase,
                                "sequence": sequence,
                                "challenge": challenge,
                                **execution_identity,
                                "invocation_id": invocation_id,
                            }
                        )
                        + "\n"
                    )
                    sut.stdin.flush()
                except BrokenPipeError:
                    pass
            ready, _, _ = select.select([sut.stdout], [], [], timeout_s)
            line = sut.stdout.readline().strip() if ready and sut.stdout else ""
            end = time.monotonic_ns()
            phase_bounds[phase] = [start, end]
            if line:
                sut_lines.append(line)
            try:
                acknowledgement = json.loads(line)
            except ValueError:
                acknowledgement = {}
            causal = (
                acknowledgement.get("phase") == phase
                and acknowledgement.get("sequence") == sequence
                and acknowledgement.get("challenge") == challenge
                and acknowledgement.get("plan_id") == execution_identity["plan_id"]
                and acknowledgement.get("launch_id") == execution_identity["launch_id"]
                and acknowledgement.get("controller_instance")
                == execution_identity["controller_instance"]
                and acknowledgement.get("invocation_id") == invocation_id
                and acknowledgement.get("ack") is True
            )
            phase_invocations.append(
                {
                    "phase": phase,
                    "sequence": sequence,
                    "challenge": challenge,
                    "invocation_id": invocation_id,
                    "acknowledged": causal,
                }
            )
            if observer.stdin is not None:
                observer.stdin.write(
                    json.dumps(
                        {
                            "phase": phase,
                            "signal": line,
                            "monotonic_ns": end,
                            "scenario": scenario["id"],
                            "sequence": sequence,
                            "challenge": challenge,
                            "causal_ack": causal,
                            **execution_identity,
                            "invocation_id": invocation_id,
                        }
                    )
                    + "\n"
                )
                observer.stdin.flush()
            return causal

        phase_ok = drive("service-ready", "ready", 1)
        phase_ok &= drive("workload-complete", "workload", 2)
        phase_ok &= drive("fault-injected", f"fault {scenario['id']}", 3)
        phase_ok &= drive("observer-captured", "observe", 4)
        exited_before_shutdown = sut.poll() is not None
        phase_ok &= drive("service-shutdown", "shutdown", 5)
        phase_ok &= not exited_before_shutdown
        if observer.stdin is not None:
            observer.stdin.close()
        observer_timed_out = False
        try:
            observer.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            observer_timed_out = True
            observer.kill()
            observer.wait()
        observed_stdout = observer.stdout.read() if observer.stdout else ""
        observed_stderr = observer.stderr.read() if observer.stderr else ""
        observer_end = time.monotonic_ns()
        observer_binding = {
            "pid": observer.pid,
            "start_identity": (
                f"pid:{observer.pid}@ticks:{observer_identity['start_ticks']}"
            ),
            "argv": observer_identity["argv"],
            **execution_identity,
        }
        premature_exit = exited_before_shutdown
        if sut.poll() is None:
            sut.terminate()
        try:
            sut_exit = sut.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            sut.kill()
            sut_exit = sut.wait()
        sut_end = time.monotonic_ns()
        remaining_stdout, remaining_stderr = sut.communicate()
        if remaining_stdout:
            sut_lines.extend(remaining_stdout.splitlines())
        (run_dir / "stdout.bin").write_text("\n".join(sut_lines) + "\n")
        (run_dir / "stderr.bin").write_text(remaining_stderr or "")
        (run_dir / "observer-stdout.bin").write_text(observed_stdout)
        (run_dir / "observer-stderr.bin").write_text(observed_stderr)
        result_bytes = b""
        while chunk := os.read(read_fd, 65536):
            result_bytes += chunk
        os.close(read_fd)
        (run_dir / "observer-pipe.bin").write_bytes(result_bytes)
        result_path.write_bytes(result_bytes or canonical({"events": []}))
        pipe_digest = digest_bytes(result_bytes)
        command = {
            "argv": argv,
            "cwd": str(run_dir.resolve()),
            "environment_manifest": "environment.json",
            "wall_start_ns": time.time_ns(),
            "wall_end_ns": time.time_ns(),
            "monotonic_start_ns": sut_start,
            "monotonic_end_ns": sut_end,
            "exit_code": 0
            if phase_ok and sut_exit in (0, -15) and observer.returncode == 0
            else sut_exit,
            "signal": 15 if sut_exit == -15 else None,
            "timeout": observer_timed_out,
            "premature_exit": premature_exit,
            "exited_before_shutdown_ack": exited_before_shutdown,
            "phase_complete": phase_ok,
            "stdout": "stdout.bin",
            "stdout_sha256": digest_file(run_dir / "stdout.bin"),
            "stderr": "stderr.bin",
            "stderr_sha256": digest_file(run_dir / "stderr.bin"),
            "environment_sha256": digest_file(run_dir / "environment.json"),
            "sut_process": {
                "argv": sut_identity["argv"],
                "pid": sut.pid,
                "start_identity": f"pid:{sut.pid}@ticks:{sut_identity['start_ticks']}",
                "linux_identity": sut_identity,
            },
            "observer_process": {
                "argv": observer_identity["argv"],
                "pid": observer.pid,
                "start_identity": (
                    f"pid:{observer.pid}@ticks:{observer_identity['start_ticks']}"
                ),
                "exit_code": observer.returncode,
                "monotonic_start_ns": observer_start,
                "monotonic_end_ns": observer_end,
                "linux_identity": observer_identity,
            },
            "phase_bounds": phase_bounds,
            "phase_invocations": phase_invocations,
            "execution_identity": execution_identity,
            "observer_pipe_sha256": pipe_digest,
        }
        (run_dir / "command.json").write_bytes(canonical(command) + b"\n")
        command_digest = digest_file(run_dir / "command.json")
    stdout_path = run_dir / command["stdout"]
    if observations_from_stdout:
        try:
            observations = json.loads(stdout_path.read_text())["events"]
            observation_error = None
        except (OSError, ValueError, KeyError, TypeError) as exc:
            observations, observation_error = (
                [],
                f"stdout observations invalid: {type(exc).__name__}",
            )
        result_path.write_bytes(canonical({"events": observations}) + b"\n")
    elif observer_argv is None:
        observations, observation_error = _read_events(result_path)
        if not result_path.exists():
            result_path.write_bytes(canonical({"events": []}) + b"\n")
    else:
        observations, observation_error = _read_events(result_path)
        if not result_path.exists():
            result_path.write_bytes(canonical({"events": []}) + b"\n")
    protocol = json.loads((HERE / "protocol.json").read_text())
    schema = json.loads((HERE / "raw-record.schema.json").read_text())
    for name, value in (
        (
            "observations.json",
            {"events": observations, "observer_binding": observer_binding},
        ),
        ("scenario.json", scenario),
        ("protocol.json", protocol),
    ):
        (run_dir / name).write_bytes(canonical(value) + b"\n")
    intake = {
        "schema": "ecpa-runner-intake/v1",
        "evidence_class": evidence_class,
        "measurement_source": measurement_source,
        "scenario": scenario["id"],
        "scenario_digest": digest_bytes(canonical(scenario)),
        "protocol_digest": digest_bytes(canonical(protocol)),
        "arm": arm,
        "start_id": start_id,
        "repetition": repetition,
        "arm_order": arm_order,
        "identity": identity,
        "activation_contract": env.get("ECPA_ACTIVATION_CONTRACT"),
        "semantic_environment": {
            name: env.get(name, "<unset>") for name in SEMANTIC_ENV
        },
        "execution_identity": command.get("execution_identity"),
    }
    (run_dir / "intake.json").write_bytes(canonical(intake) + b"\n")
    artifacts = {
        "raw_log": command["stdout"],
        "environment": "environment.json",
        "command": "command.json",
        "oracle": "oracle.json",
        "intake": "intake.json",
        "observations": "observations.json",
        "observer_result": "observer-result.json",
        "observer_pipe": "observer-pipe.bin" if observer_argv is not None else None,
        "scenario": "scenario.json",
        "protocol": "protocol.json",
        "receipt": "runner-receipt.json",
        "evidence_bytes": stdout_path.stat().st_size,
        "message_bytes": len(canonical(observations)),
        "digests": {},
    }
    for name in (
        command["stdout"],
        command["stderr"],
        "environment.json",
        "command.json",
        "observations.json",
        "observer-result.json",
        "scenario.json",
        "protocol.json",
        "intake.json",
    ):
        artifacts["digests"][name] = digest_file(run_dir / name)
    for name in ("observer-stdout.bin", "observer-stderr.bin"):
        if (run_dir / name).is_file():
            artifacts["digests"][name] = digest_file(run_dir / name)
    if artifacts["observer_pipe"]:
        artifacts["digests"][artifacts["observer_pipe"]] = digest_file(
            run_dir / artifacts["observer_pipe"]
        )
    assert artifacts["digests"]["command.json"] == command_digest
    record = {
        "schema": "ecpa-false-effective-start/v1",
        "status": "failed",
        "evidence_class": evidence_class,
        "measurement_source": measurement_source,
        "cell_id": scenario["id"],
        "scenario": scenario["id"],
        "arm": arm,
        "start_id": start_id,
        "repetition": repetition,
        "arm_order": arm_order,
        "identity": identity,
        "command": command,
        "artifacts": artifacts,
        "observations": observations,
        "observer_binding": observer_binding,
        "missing_reason": observation_error,
        "intake_digest": artifacts["digests"]["intake.json"],
        "artifact_root": f"starts/{start_id}",
    }
    result = oracle(scenario, record)
    if (
        command["exit_code"] == 0
        and not command["timeout"]
        and result["verdict"] == "PASS"
    ):
        record["status"], record["missing_reason"] = "complete", None
        result = oracle(scenario, record)
    elif record["missing_reason"] is None:
        reasons = result["reasons"] or (
            ["command timeout"]
            if command["timeout"]
            else [f"exit code {command['exit_code']}"]
        )
        record["missing_reason"] = "; ".join(reasons)
        result = oracle(scenario, record)
    record["oracle"] = result
    (run_dir / "oracle.json").write_bytes(canonical(result) + b"\n")
    artifacts["digests"]["oracle.json"] = digest_file(run_dir / "oracle.json")
    receipt = {
        "schema": "ecpa-runner-receipt/v1",
        "core_digest": digest_bytes(canonical(canonical_record_core(record))),
        "status": record["status"],
        "cell_id": record["cell_id"],
        "command_digest": artifacts["digests"]["command.json"],
        "oracle_digest": artifacts["digests"]["oracle.json"],
        "exit_code": command["exit_code"],
        "timeout": command["timeout"],
        "sut_identity": command.get("sut_process", {}).get("linux_identity"),
        "observer_identity": command.get("observer_process", {}).get("linux_identity"),
        "observer_argv": command.get("observer_process", {}).get("argv"),
        "observer_pipe_sha256": command.get("observer_pipe_sha256"),
        "execution_identity": command.get("execution_identity"),
        "phase_invocations": command.get("phase_invocations"),
        "excluded_fields": ["artifact_root", "receipt_digest"],
    }
    (run_dir / "runner-receipt.json").write_bytes(canonical(receipt) + b"\n")
    record["receipt_digest"] = digest_file(run_dir / "runner-receipt.json")
    artifacts["digests"]["runner-receipt.json"] = record["receipt_digest"]
    (run_dir / "record.json").write_bytes(canonical(record) + b"\n")
    validate_record(record, root, scenario=scenario, protocol=protocol, schema=schema)
    if evidence_class == "formal-real":
        persisted = [
            json.loads(path.read_text())
            for path in sorted((root / "starts").glob("*/record.json"))
        ]
        write_formal_manifest(root, persisted)
    return record


def run_reference_start(
    root: Path,
    scenario: dict[str, Any],
    arm: str,
    repetition: int,
    arm_order: int,
    *,
    fail: bool = False,
    timeout_s: float = 5,
    **_: Any,
):
    helper = Path(__file__).with_name("helper_service.py").resolve()
    argv = [sys.executable, str(helper), "--arm", arm, "--scenario", scenario["id"]]
    if fail:
        argv.append("--fail")
    identity = measured_identity(
        {
            "model": "reference-helper",
            "dataset": "reference-events-v1",
            "workload": "deterministic-selftest",
            "software": {"python": sys.version.split()[0]},
            "observer": "helper-json-events/v1",
            "plugin_commits": [],
            "topology": "one helper process",
            "fault_plan": scenario["id"],
            "fault": scenario["id"],
            "warm_state": "cold",
            "container_digest": "not-containerized",
            "gpu": "not-applicable",
            "npu": "not-applicable",
            "driver": "not-applicable",
        },
        arm,
        dict(os.environ),
    )
    return _run_start(
        root,
        scenario,
        arm,
        repetition,
        arm_order,
        argv=argv,
        env=dict(os.environ),
        timeout_s=timeout_s,
        evidence_class="reference-synthetic",
        measurement_source="reference-helper-subprocess",
        identity=identity,
        observations_from_stdout=True,
    )


def run_formal_start(
    root: Path,
    scenario: dict[str, Any],
    protocol: dict[str, Any],
    adapter: FormalArmAdapter,
    repetition: int,
    arm_order: int,
    *,
    executable: str,
    arguments: list[str],
    observer_executable: str,
    observer_arguments: list[str],
    identity: dict[str, Any],
    timeout_s: float,
    fixture_mode: bool = False,
    adapter_verification_id: str | None = None,
):
    if protocol != json.loads((HERE / "protocol.json").read_text()):
        raise ValueError("formal protocol differs from frozen protocol")
    required = {
        "model",
        "dataset",
        "workload",
        "software",
        "observer",
        "plugin_commits",
        "topology",
        "fault_plan",
        "fault",
        "warm_state",
        "container_digest",
        "gpu",
        "npu",
        "driver",
    }
    if required.difference(identity) or any(
        identity.get(key) is None for key in required
    ):
        raise ValueError("formal declared identity is incomplete")
    if "adapter_contract_verified" in identity:
        raise ValueError("caller-declared adapter verification is not accepted")
    identity = dict(identity)
    identity["fixture_only"] = fixture_mode
    if fixture_mode:
        verification = None
        evidence_class = "interface-fixture"
        measurement_source = "controlled-interface-observer"
    else:
        verification = verified_adapter_contract(
            adapter_verification_id,
            adapter,
            executable,
            arguments,
            observer_executable,
            observer_arguments,
        )
        evidence_class = "formal-real"
        measurement_source = "registry-pinned-host-evidence-observer"
    identity["adapter_verification"] = verification
    argv, env = adapter.launch(executable, arguments, dict(os.environ))
    plan_material = {
        "protocol_digest": digest_bytes(canonical(protocol)),
        "scenario_digest": digest_bytes(canonical(scenario)),
        "arm": adapter.arm,
        "activation_contract": adapter.activation_contract,
        "declared_identity": identity,
    }
    execution_identity = {
        "plan_id": digest_bytes(canonical(plan_material)),
        "launch_id": "launch:" + secrets.token_hex(16),
        "controller_instance": "controller:" + secrets.token_hex(16),
    }
    return _run_start(
        root,
        scenario,
        adapter.arm,
        repetition,
        arm_order,
        argv=argv,
        env=env,
        timeout_s=timeout_s,
        evidence_class=evidence_class,
        measurement_source=measurement_source,
        identity=measured_identity(identity, adapter.arm, env),
        observations_from_stdout=False,
        observer_argv=[observer_executable, *observer_arguments],
        execution_identity=execution_identity,
    )


def planned_records(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "schema": "ecpa-false-effective-start/v1",
            "status": "planned",
            "evidence_class": "formal-real",
            "measurement_source": "external-command-adapter",
            "cell_id": scenario["id"],
            "scenario": scenario["id"],
            "arm": arm,
            "start_id": f"planned-{scenario['id']}-{arm}",
            "repetition": 1,
            "arm_order": 1,
            "identity": {},
            "command": None,
            "artifacts": {},
            "observations": [],
            "missing_reason": "real service and independent observer not configured",
        }
        for scenario in scenarios
        for arm in ARMS
    ]


def write_formal_manifest(root: Path, records: list[dict[str, Any]]) -> Path:
    """Publish the runner-owned record index consumed by the paper pipeline."""

    def atomic_bytes(path: Path, value: bytes) -> None:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            stream.write(value)
            temporary = Path(stream.name)
        os.replace(temporary, path)

    generation = root / "formal-generations" / secrets.token_hex(16)
    generation.mkdir(parents=True, exist_ok=False)
    jsonl = generation / "formal-records.jsonl"
    atomic_bytes(jsonl, b"".join(canonical(row) + b"\n" for row in records))
    entries = []
    for row in records:
        record_path = safe_path(root, f"{row['artifact_root']}/record.json")
        if json.loads(record_path.read_text()) != row:
            raise ValueError("record.json differs from runner record")
        entries.append(
            {
                "start_id": row["start_id"],
                "record": str(record_path.relative_to(root)),
                "digest": digest_file(record_path),
            }
        )
    manifest = {
        "schema": "ecpa-formal-record-index/v1",
        "records_jsonl": str(jsonl.relative_to(root)),
        "records_jsonl_digest": digest_file(jsonl),
        "records": entries,
    }
    index = generation / "index.json"
    atomic_bytes(index, canonical(manifest) + b"\n")
    current = {
        "schema": "ecpa-formal-current/v1",
        "generation_index": str(index.relative_to(root)),
        "generation_index_digest": digest_file(index),
    }
    path = root / "formal-record-index.json"
    atomic_bytes(path, canonical(current) + b"\n")
    return path


def read_manifest_bytes(root: Path, relative: str | Path) -> bytes:
    """Read one regular file beneath root without following any symlink component."""
    relative_path = Path(relative)
    if (
        relative_path.is_absolute()
        or not relative_path.parts
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        raise ValueError("manifest path is not a strict relative path")
    directory_fd = os.open(root.resolve(), os.O_RDONLY | os.O_DIRECTORY)
    opened_directories = [directory_fd]
    file_fd: int | None = None
    try:
        for part in relative_path.parts[:-1]:
            directory_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            opened_directories.append(directory_fd)
        file_fd = os.open(
            relative_path.parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise ValueError("manifest artifact is not a regular file")
        with os.fdopen(file_fd, "rb") as stream:
            file_fd = None
            return stream.read()
    except OSError as exc:
        raise ValueError(
            "manifest path contains a symlink or invalid component"
        ) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for opened in reversed(opened_directories):
            os.close(opened)


def load_formal_manifest(path: Path) -> tuple[list[dict[str, Any]], Path]:
    if path.name != "formal-record-index.json" or path.is_symlink():
        raise ValueError("formal input must be the runner-owned current pointer")
    root = path.parent
    current_bytes = read_manifest_bytes(root, path.name)
    current = json.loads(current_bytes)
    if (
        current_bytes != canonical(current) + b"\n"
        or current.get("schema") != "ecpa-formal-current/v1"
    ):
        raise ValueError("formal input must be a canonical runner current pointer")
    generation_index = Path(current["generation_index"])
    parts = generation_index.parts
    if (
        len(parts) != 3
        or parts[0] != "formal-generations"
        or len(parts[1]) != 32
        or any(char not in "0123456789abcdef" for char in parts[1])
        or parts[2] != "index.json"
    ):
        raise ValueError("formal generation index path is not runner-owned")
    index_bytes = read_manifest_bytes(root, generation_index)
    if digest_bytes(index_bytes) != current["generation_index_digest"]:
        raise ValueError("formal generation index digest mismatch")
    manifest = json.loads(index_bytes)
    if (
        index_bytes != canonical(manifest) + b"\n"
        or manifest.get("schema") != "ecpa-formal-record-index/v1"
    ):
        raise ValueError("formal generation index is not canonical")
    expected_jsonl = generation_index.parent / "formal-records.jsonl"
    if Path(manifest.get("records_jsonl", "")) != expected_jsonl:
        raise ValueError("formal JSONL is outside its generation")
    jsonl_bytes = read_manifest_bytes(root, expected_jsonl)
    if digest_bytes(jsonl_bytes) != manifest["records_jsonl_digest"]:
        raise ValueError("formal JSONL digest mismatch")
    indexed = [json.loads(line) for line in jsonl_bytes.splitlines() if line]
    if jsonl_bytes != b"".join(canonical(row) + b"\n" for row in indexed):
        raise ValueError("formal JSONL is not canonical")
    records = []
    for entry in manifest["records"]:
        record_bytes = read_manifest_bytes(root, entry["record"])
        if digest_bytes(record_bytes) != entry["digest"]:
            raise ValueError("indexed record digest mismatch")
        record = json.loads(record_bytes)
        if entry["start_id"] != record.get("start_id"):
            raise ValueError("index start_id does not match record")
        expected_path = f"{record['artifact_root']}/record.json"
        if entry["record"] != expected_path:
            raise ValueError("index path does not match record artifact root")
        records.append(record)
    if records != indexed:
        raise ValueError("formal JSONL and indexed records differ")
    return records, root
