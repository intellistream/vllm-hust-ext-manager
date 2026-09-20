"""Reference self-test and independently observed formal command runner."""

from __future__ import annotations

import base64
import contextlib
import copy
import json
import os
import platform
import secrets
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness import (
    ARMS,
    FORMAL_HOST_OBSERVABLES,
    FORMAL_LIFECYCLE_FACT_SCHEMA,
    FORMAL_LIFECYCLE_FACT_SCHEMA_PATH,
    FORMAL_LIFECYCLE_FACT_SOURCES,
    FORMAL_LIFECYCLE_FACT_TRANSPORT,
    SEMANTIC_ENV,
    canonical,
    canonical_record_core,
    digest_bytes,
    digest_file,
    oracle,
    run_command,
    safe_path,
    validate_formal_lifecycle_receipt,
    validate_record,
    validate_required_process_snapshot,
    validate_scenario_binding_contract,
)
from jsonschema import Draft7Validator

from vllm_hust_ext.formal_adapter_admission import (
    FORMAL_ADAPTER_REGISTRY_SCHEMA,
    validate_formal_adapter_admission,
)
from vllm_hust_ext.manager_controller import (
    ACTIVATION_CONTRACT as MANAGED_ACTIVATION_CONTRACT,
)
from vllm_hust_ext.manager_controller import (
    CONTROLLED_ENVIRONMENT,
)
from vllm_hust_ext.plan_artifact import read_plan_artifact
from vllm_hust_ext.quarantine_transaction import (
    QuarantineTransactionError,
    finalize_quarantine_transaction,
    read_quarantine_record,
)

HERE = Path(__file__).resolve().parent
VERIFIED_ADAPTER_REGISTRY = HERE / "verified-adapters.json"
FORMAL_ACTIVATION_PROBE_OPTION = "--ecpa-formal-activation-probe"
ECPA_FORMAL_ACTIVATION_OPTIONS = (
    "--controller-instance",
    "--host-event-dir",
    "--launch-id",
    "--plan",
    "--target-executable-device",
    "--target-executable-inode",
    "--target-executable-sha256",
    "formal-run",
)
CHILD_TERMINATION_GRACE_S = 2.0


def _single_option(arguments: list[str], name: str) -> str:
    positions = [index for index, value in enumerate(arguments) if value == name]
    if len(positions) != 1 or positions[0] + 1 >= len(arguments):
        raise ValueError(
            f"lifecycle fact source option is missing or duplicated: {name}"
        )
    value = arguments[positions[0] + 1]
    if not value or value.startswith("--"):
        raise ValueError(f"lifecycle fact source option is invalid: {name}")
    return value


def _finalize_fault_transaction(
    fingerprint: dict[str, Any],
    request: dict[str, Any],
    stderr: bytes,
    receipt_raw: bytes,
    source_identity: dict[str, Any],
) -> dict[str, Any]:
    """Validate the actuator audit and durably accept exactly its transaction."""
    if not stderr.endswith(b"\n") or stderr.count(b"\n") != 1:
        raise ValueError("fault actuator must emit exactly one audit record")
    try:
        audit = json.loads(stderr[:-1])
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("fault actuator audit JSON is invalid") from exc
    if not isinstance(audit, dict) or stderr != canonical(audit) + b"\n":
        raise ValueError("fault actuator audit is not canonical")
    transaction_id = audit.get("transaction_id")
    transaction_root_text = audit.get("transaction_directory")
    transaction_device = audit.get("transaction_directory_device")
    transaction_inode = audit.get("transaction_directory_inode")
    intent_digest = audit.get("transaction_intent_sha256")
    applied_digest = audit.get("transaction_applied_sha256")
    expected_root = Path(
        _single_option(fingerprint["arguments"], "--quarantine-dir")
    ).resolve(strict=True)
    expected_device = int(
        _single_option(fingerprint["arguments"], "--quarantine-device")
    )
    expected_inode = int(_single_option(fingerprint["arguments"], "--quarantine-inode"))
    source_root = Path(_single_option(fingerprint["arguments"], "--event-dir")).resolve(
        strict=True
    )
    event_directory_identity = (
        int(_single_option(fingerprint["arguments"], "--device")),
        int(_single_option(fingerprint["arguments"], "--inode")),
    )
    expected_descriptor_digest = _single_option(
        fingerprint["arguments"], "--descriptor-sha256"
    )
    if (
        audit.get("schema") != "ecpa-lifecycle-source-audit/v1"
        or audit.get("kind") != "partial-worker-evidence-quarantine"
        or audit.get("scenario") != request["scenario"]
        or audit.get("plan_id") != request["plan_id"]
        or audit.get("launch_id") != request["launch_id"]
        or audit.get("controller_instance") != request["controller_instance"]
        or audit.get("lifecycle_invocation_id") != request["invocation_id"]
        or not isinstance(transaction_id, str)
        or len(transaction_id) != 64
        or any(character not in "0123456789abcdef" for character in transaction_id)
        or not isinstance(transaction_root_text, str)
        or Path(transaction_root_text).resolve(strict=True) != expected_root
        or transaction_device != expected_device
        or transaction_inode != expected_inode
        or audit.get("descriptor_sha256") != expected_descriptor_digest
        or not isinstance(intent_digest, str)
        or not isinstance(applied_digest, str)
    ):
        raise ValueError("fault actuator audit binding is invalid")
    identity = (expected_device, expected_inode)
    try:
        intent = read_quarantine_record(
            expected_root, identity, transaction_id, "intent"
        )
        applied = read_quarantine_record(
            expected_root, identity, transaction_id, "applied"
        )
        assert intent is not None and applied is not None
        expected_binding = {
            "schema": "ecpa-quarantine-transaction-binding/v1",
            "scenario": request["scenario"],
            "plan_id": request["plan_id"],
            "launch_id": request["launch_id"],
            "controller_instance": request["controller_instance"],
            "invocation_id": request["invocation_id"],
            "challenge": request["challenge"],
            "target": audit.get("target"),
            "entry_point": audit.get("entry_point"),
            "journal": audit.get("quarantined_journal"),
            "descriptor_sha256": expected_descriptor_digest,
        }
        if (
            intent.digest != intent_digest
            or applied.digest != applied_digest
            or intent.value.get("binding") != expected_binding
        ):
            raise ValueError("fault actuator transaction chain differs from audit")
        finalized = finalize_quarantine_transaction(
            expected_root,
            identity,
            transaction_id,
            source_root=source_root,
            source_identity=event_directory_identity,
            applied_digest=applied_digest,
            fact_receipt_sha256=digest_bytes(receipt_raw),
            source_process_identity=source_identity,
        )
    except QuarantineTransactionError as exc:
        raise ValueError("fault actuator transaction finalization failed") from exc
    return {
        "transaction_id": transaction_id,
        "intent_sha256": intent.digest,
        "applied_sha256": applied.digest,
        "finalized_sha256": finalized.digest,
        "finalized_record_base64": base64.b64encode(finalized.raw).decode(),
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
    executable = Path(f"/proc/{pid}/exe")
    executable_metadata = executable.stat()
    return {
        "pid": pid,
        "start_ticks": start_ticks,
        "argv": argv,
        "executable_device": executable_metadata.st_dev,
        "executable_inode": executable_metadata.st_ino,
    }


def wait_for_linux_process_identity(
    process: subprocess.Popen[Any],
    expected_argv: list[str],
    timeout_s: float,
    expected_executable: dict[str, Any] | None = None,
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
            if expected_executable is not None and (
                last_identity["executable_device"]
                != expected_executable.get("executable_device")
                or last_identity["executable_inode"]
                != expected_executable.get("executable_inode")
            ):
                raise RuntimeError(
                    "process executable differs from the registered fingerprint"
                )
            return last_identity
        time.sleep(0.001)
    observed = last_identity["argv"] if last_identity is not None else None
    raise TimeoutError(
        f"process exec identity did not stabilize: expected={expected_argv!r}, "
        f"observed={observed!r}"
    )


def command_fingerprint(executable: str, arguments: list[str]) -> dict[str, Any]:
    """Bind the launched executable and every file-backed argv component."""
    executable_path = Path(executable).absolute()
    executable_resolved = executable_path.resolve(strict=True)
    executable_metadata = executable_resolved.stat()
    argument_files = []
    normalized_arguments = []
    for index, value in enumerate(arguments):
        candidate = Path(value)
        if candidate.is_file():
            resolved = candidate.resolve(strict=True)
            value = str(resolved)
            argument_files.append(
                {
                    "index": index,
                    "path": str(resolved),
                    "sha256": digest_file(resolved),
                }
            )
        normalized_arguments.append(value)
    fingerprint = {
        "executable": str(executable_path),
        "executable_resolved": str(executable_resolved),
        "executable_device": executable_metadata.st_dev,
        "executable_inode": executable_metadata.st_ino,
        "executable_sha256": digest_file(executable_resolved),
        "arguments": normalized_arguments,
        "argument_files": argument_files,
    }
    return {**fingerprint, "digest": digest_bytes(canonical(fingerprint))}


def executable_launch_prefix(executable: str) -> list[str]:
    """Return the stable argv that Linux exposes for a binary or direct shebang."""
    path = Path(executable).absolute()
    path.resolve(strict=True)
    with path.open("rb") as stream:
        first_line = stream.readline(4096)
    if not first_line.startswith(b"#!"):
        return [str(path)]
    try:
        shebang = shlex.split(first_line[2:].decode().strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("manager executable has an invalid shebang") from exc
    if not shebang or Path(shebang[0]).name == "env":
        raise ValueError("manager executable requires a direct interpreter shebang")
    interpreter_path = Path(shebang[0]).absolute()
    interpreter_path.resolve(strict=True)
    interpreter = str(interpreter_path)
    return [interpreter, *shebang[1:], str(path)]


def command_fingerprint_for_launch(
    executable: str, arguments: list[str]
) -> dict[str, Any]:
    """Fingerprint the actual exec image and argv for binaries or scripts."""
    prefix = executable_launch_prefix(executable)
    return command_fingerprint(prefix[0], [*prefix[1:], *arguments])


def verified_lifecycle_fact_commands(
    entry: dict[str, Any],
    commands: dict[str, tuple[str, list[str]]] | None,
    forbidden_digests: set[str],
) -> dict[str, dict[str, Any]]:
    """Pin one independent command/process boundary per lifecycle fact."""
    phases = set(FORMAL_LIFECYCLE_FACT_SOURCES)
    registered = entry.get("lifecycle_fact_command_digests")
    if (
        not isinstance(commands, dict)
        or set(commands) != phases
        or not isinstance(registered, dict)
        or set(registered) != phases
    ):
        raise ValueError("verified adapter lifecycle fact commands are incomplete")
    fingerprints: dict[str, dict[str, Any]] = {}
    for phase in sorted(phases):
        command = commands[phase]
        if (
            not isinstance(command, tuple)
            or len(command) != 2
            or not isinstance(command[0], str)
            or not isinstance(command[1], list)
            or any(not isinstance(value, str) for value in command[1])
        ):
            raise ValueError("lifecycle fact command is malformed")
        executable, arguments = command
        if command_references_fixture([executable, *arguments]):
            raise ValueError("fixture-referencing lifecycle fact source is forbidden")
        fingerprint = command_fingerprint_for_launch(executable, arguments)
        if fingerprint["digest"] != registered.get(phase):
            raise ValueError("lifecycle fact command differs from the registry")
        fingerprints[phase] = fingerprint
    digests = [item["digest"] for item in fingerprints.values()]
    if len(digests) != len(set(digests)) or forbidden_digests.intersection(digests):
        raise ValueError("lifecycle fact commands are not independent")
    return fingerprints


def verified_scenario_binding(
    entry: dict[str, Any],
    scenario_id: str,
    fault_command: dict[str, Any],
) -> dict[str, Any]:
    """Bind one reviewed scenario to the exact fault descriptor and entry point."""
    bindings = entry.get("scenario_bindings")
    binding = bindings.get(scenario_id) if isinstance(bindings, dict) else None
    if binding is None:
        raise ValueError("verified adapter does not bind the requested scenario")
    arguments = fault_command.get("arguments")
    verified_binding = validate_scenario_binding_contract(
        binding, scenario_id, arguments
    )
    entry_point = verified_binding["entry_point"]
    try:
        descriptor_path = Path(_single_option(arguments, "--descriptor"))
        descriptor_digest = _single_option(arguments, "--descriptor-sha256")
    except ValueError as exc:
        raise ValueError("fault source does not bind one descriptor") from exc
    raw = descriptor_path.read_bytes()
    if len(raw) > 64 * 1024:
        raise ValueError("fault descriptor exceeds the registration limit")
    try:
        descriptor = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("fault descriptor JSON is invalid") from exc
    actual_digest = digest_bytes(raw)
    target = descriptor.get("target") if isinstance(descriptor, dict) else None
    if (
        not isinstance(descriptor, dict)
        or raw != canonical(descriptor) + b"\n"
        or set(descriptor) != {"schema", "scenario", "target", "entry_point"}
        or descriptor.get("schema") != "ecpa-evidence-quarantine-fault/v1"
        or descriptor.get("scenario") != scenario_id
        or descriptor.get("entry_point") != entry_point
        or not isinstance(target, dict)
        or set(target) != {"host", "role", "ordinal", "process_epoch"}
        or target.get("role") != "worker"
        or not isinstance(target.get("host"), str)
        or not target["host"]
        or target["host"].strip() != target["host"]
        or any(
            isinstance(target.get(field), bool)
            or not isinstance(target.get(field), int)
            or target[field] < 0
            for field in ("ordinal", "process_epoch")
        )
        or descriptor_digest != actual_digest
        or binding.get("descriptor_sha256") != actual_digest
    ):
        raise ValueError("fault descriptor differs from scenario binding")
    return verified_binding


def run_bounded_command(
    argv: list[str],
    timeout_s: int,
    output_limit: int,
    executable_fingerprint: dict[str, Any] | None = None,
) -> tuple[int, bytes, bytes]:
    """Capture a child incrementally and terminate before output exceeds the limit."""
    process = popen_pinned(
        argv,
        executable_fingerprint,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("bounded command pipes were not created")
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    active = set(buffers)
    for stream in active:
        os.set_blocking(stream.fileno(), False)
    deadline = time.monotonic() + timeout_s
    try:
        while active:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout_s)
            readable, _, _ = select.select(list(active), [], [], remaining)
            if not readable:
                raise subprocess.TimeoutExpired(argv, timeout_s)
            for stream in readable:
                try:
                    captured = sum(len(value) for value in buffers.values())
                    chunk = os.read(
                        stream.fileno(), min(65536, output_limit - captured + 1)
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    active.remove(stream)
                    continue
                buffers[stream].extend(chunk)
                if captured + len(chunk) > output_limit:
                    raise ValueError(
                        "activation probe output exceeds the evidence limit"
                    )
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return (
            returncode,
            bytes(buffers[process.stdout]),
            bytes(buffers[process.stderr]),
        )
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        if process.poll() is None:
            process.wait()
        process.stdout.close()
        process.stderr.close()


def validate_fingerprint_argument_files(
    argv: list[str], executable_fingerprint: dict[str, Any]
) -> None:
    """Recheck every registry-fingerprinted file immediately before launch."""
    registered_arguments = executable_fingerprint.get("arguments")
    if (
        not isinstance(registered_arguments, list)
        or argv[1 : 1 + len(registered_arguments)] != registered_arguments
    ):
        raise ValueError("launch arguments differ from the registered fingerprint")
    artifacts = executable_fingerprint.get("argument_files")
    if not isinstance(artifacts, list):
        raise ValueError("registered argument-file fingerprints are invalid")
    seen: set[int] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "index",
            "path",
            "sha256",
        }:
            raise ValueError("registered argument-file fingerprint is invalid")
        index = artifact["index"]
        path = artifact["path"]
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= len(registered_arguments)
            or index in seen
            or not isinstance(path, str)
            or argv[index + 1] != path
        ):
            raise ValueError("registered argument-file binding is invalid")
        seen.add(index)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("registered argument file is not regular")
            if digest_file(Path(f"/proc/self/fd/{descriptor}")) != artifact["sha256"]:
                raise ValueError(
                    "argument file differs from its registered fingerprint"
                )
        finally:
            os.close(descriptor)


def popen_pinned(
    argv: list[str],
    executable_fingerprint: dict[str, Any] | None,
    **kwargs: Any,
) -> subprocess.Popen[Any]:
    """Open, verify, and exec the exact executable inode behind argv[0]."""
    if executable_fingerprint is None:
        return subprocess.Popen(argv, **kwargs)
    validate_fingerprint_argument_files(argv, executable_fingerprint)
    executable_fd = os.open(argv[0], os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(executable_fd)
        if (
            metadata.st_dev != executable_fingerprint.get("executable_device")
            or metadata.st_ino != executable_fingerprint.get("executable_inode")
            or digest_file(Path(f"/proc/self/fd/{executable_fd}"))
            != executable_fingerprint.get("executable_sha256")
        ):
            raise ValueError("executable differs from its registered fingerprint")
        inherited = tuple(kwargs.pop("pass_fds", ()))
        return subprocess.Popen(
            argv,
            executable=f"/proc/self/fd/{executable_fd}",
            pass_fds=(*inherited, executable_fd),
            **kwargs,
        )
    finally:
        os.close(executable_fd)


def run_lifecycle_fact_source(
    phase: str,
    fingerprint: dict[str, Any],
    *,
    request: dict[str, Any],
    cwd: Path,
    env: dict[str, str],
    timeout_s: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Collect one fact over a dedicated, registry-pinned process channel."""
    argv = [fingerprint["executable"], *fingerprint["arguments"]]
    started = time.monotonic_ns()
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    source_env = dict(env)
    source_env["ECPA_LIFECYCLE_FACT_FD"] = str(sender.fileno())
    try:
        process = popen_pinned(
            argv,
            fingerprint,
            cwd=cwd,
            env=source_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(sender.fileno(),),
            start_new_session=True,
        )
    except BaseException:
        receiver.close()
        sender.close()
        raise
    sender.close()
    pidfd = -1
    try:
        try:
            pidfd = os.pidfd_open(process.pid)
        except (AttributeError, OSError) as exc:
            raise RuntimeError(
                "formal lifecycle sources require Linux pidfd support"
            ) from exc
        initial_identity = wait_for_linux_process_identity(
            process, argv, timeout_s, fingerprint
        )
        executable_identity = {
            "device": initial_identity["executable_device"],
            "inode": initial_identity["executable_inode"],
        }
        identity = {
            key: initial_identity[key] for key in ("pid", "start_ticks", "argv")
        }
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RuntimeError("lifecycle fact source pipes were not created")
        process.stdin.write(canonical(request) + b"\n")
        process.stdin.flush()
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        active = set(streams)
        for stream in active:
            os.set_blocking(stream.fileno(), False)
        deadline = time.monotonic() + timeout_s
        receipt_complete = False
        raw = b""
        channel_credentials: dict[str, int] | None = None
        while not receipt_complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"lifecycle fact source timed out: {phase}")
            readable, _, _ = select.select(
                [*active, receiver, pidfd], [], [], remaining
            )
            if not readable:
                raise ValueError(f"lifecycle fact source timed out: {phase}")
            for stream in readable:
                if stream == pidfd:
                    raise ValueError(
                        f"lifecycle fact source exited before receipt: {phase}"
                    )
                if stream is receiver:
                    raw, ancillary, flags, _ = receiver.recvmsg(
                        1024 * 1024,
                        socket.CMSG_SPACE(struct.calcsize("3i")),
                    )
                    if flags & socket.MSG_TRUNC or not raw:
                        raise ValueError(
                            f"lifecycle fact source receipt is truncated: {phase}"
                        )
                    credentials = [
                        data
                        for level, kind, data in ancillary
                        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
                    ]
                    if len(credentials) != 1:
                        raise ValueError(
                            f"lifecycle fact source credentials are missing: {phase}"
                        )
                    sender_pid, sender_uid, sender_gid = struct.unpack(
                        "3i", credentials[0][: struct.calcsize("3i")]
                    )
                    channel_credentials = {
                        "pid": sender_pid,
                        "uid": sender_uid,
                        "gid": sender_gid,
                    }
                    if (
                        sender_pid != process.pid
                        or sender_uid != os.geteuid()
                        or sender_gid != os.getegid()
                    ):
                        raise ValueError(
                            f"lifecycle fact source sender identity mismatch: {phase}"
                        )
                    receipt_complete = True
                    continue
                captured = sum(len(value) for value in streams.values())
                try:
                    chunk = os.read(
                        stream.fileno(), min(65536, 1024 * 1024 - captured + 1)
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    active.remove(stream)
                    continue
                streams[stream].extend(chunk)
                if captured + len(chunk) > 1024 * 1024:
                    raise ValueError(
                        f"lifecycle fact source output exceeds the limit: {phase}"
                    )
        try:
            final_identity = linux_process_identity(process.pid)
        except (FileNotFoundError, ProcessLookupError, RuntimeError) as exc:
            raise ValueError(
                f"lifecycle fact source exited before identity recheck: {phase}"
            ) from exc
        if final_identity != initial_identity:
            raise ValueError(f"lifecycle fact source changed exec identity: {phase}")
        receiver.setblocking(False)
        try:
            receiver.recvmsg(
                1024 * 1024,
                socket.CMSG_SPACE(struct.calcsize("3i")),
            )
        except BlockingIOError:
            pass
        else:
            raise ValueError(
                f"lifecycle fact source emitted duplicate receipts: {phase}"
            )
        finally:
            receiver.setblocking(True)
        try:
            pending = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"lifecycle fact source JSON is invalid: {phase}") from exc
        if (
            not isinstance(pending, dict)
            or raw != canonical(pending)
            or list(Draft7Validator(FORMAL_LIFECYCLE_FACT_SCHEMA).iter_errors(pending))
        ):
            raise ValueError(
                f"lifecycle fact source receipt is invalid before commit: {phase}"
            )
        expected_pending = {
            "schema": "ecpa-formal-lifecycle-fact/v1",
            "fact": phase,
            "source_kind": FORMAL_LIFECYCLE_FACT_SOURCES[phase],
            "plan_id": request["plan_id"],
            "launch_id": request["launch_id"],
            "controller_instance": request["controller_instance"],
            "invocation_id": request["invocation_id"],
            "sequence": request["sequence"],
            "challenge": request["challenge"],
            "monotonic_ns": pending["monotonic_ns"],
            "value": pending["value"],
            "sut_process_identity": request["sut_process_identity"],
        }
        if (
            pending != expected_pending
            or not started <= pending["monotonic_ns"] <= time.monotonic_ns()
            or pending["value"]
            != (request["scenario"] if phase == "fault-injected" else True)
        ):
            raise ValueError(
                f"lifecycle fact source binding is invalid before commit: {phase}"
            )
        process.stdin.write(
            canonical(
                {
                    "command": "commit",
                    "challenge": request.get("challenge"),
                    "phase": phase,
                }
            )
            + b"\n"
        )
        process.stdin.flush()
        process.stdin.close()
        source_exited = False
        while active or not source_exited:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"lifecycle fact source timed out: {phase}")
            watched: list[Any] = [*active, receiver]
            if not source_exited:
                watched.append(pidfd)
            readable, _, _ = select.select(watched, [], [], remaining)
            if not readable:
                raise ValueError(f"lifecycle fact source timed out: {phase}")
            for stream in readable:
                if stream == pidfd:
                    process.wait()
                    source_exited = True
                    continue
                if stream is receiver:
                    receiver.recvmsg(
                        1024 * 1024,
                        socket.CMSG_SPACE(struct.calcsize("3i")),
                    )
                    raise ValueError(
                        f"lifecycle fact source emitted duplicate receipts: {phase}"
                    )
                captured = sum(len(value) for value in streams.values())
                try:
                    chunk = os.read(
                        stream.fileno(), min(65536, 1024 * 1024 - captured + 1)
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    active.remove(stream)
                    continue
                streams[stream].extend(chunk)
                if captured + len(chunk) > 1024 * 1024:
                    raise ValueError(
                        f"lifecycle fact source output exceeds the limit: {phase}"
                    )
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"lifecycle fact source timed out: {phase}") from exc
        receiver.setblocking(False)
        try:
            receiver.recvmsg(
                1024 * 1024,
                socket.CMSG_SPACE(struct.calcsize("3i")),
            )
        except BlockingIOError:
            pass
        else:
            raise ValueError(
                f"lifecycle fact source emitted duplicate receipts: {phase}"
            )
        stdout = bytes(streams[process.stdout])
        stderr = bytes(streams[process.stderr])
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        if process.poll() is None:
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if pidfd >= 0:
            os.close(pidfd)
        receiver.close()
    ended = time.monotonic_ns()
    if process.returncode != 0 or stdout or len(raw) + len(stderr) > 1024 * 1024:
        raise ValueError(f"lifecycle fact source failed: {phase}")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"lifecycle fact source JSON is invalid: {phase}") from exc
    event = {
        "event": phase,
        "value": payload.get("value") if isinstance(payload, dict) else None,
        "source_role": "lifecycle-fact-source",
        "clock": "monotonic",
        "monotonic_ns": (
            payload.get("monotonic_ns") if isinstance(payload, dict) else None
        ),
        "plan_id": payload.get("plan_id") if isinstance(payload, dict) else None,
        "launch_id": payload.get("launch_id") if isinstance(payload, dict) else None,
        "controller_instance": (
            payload.get("controller_instance") if isinstance(payload, dict) else None
        ),
        "invocation_id": (
            payload.get("invocation_id") if isinstance(payload, dict) else None
        ),
        "sequence": payload.get("sequence") if isinstance(payload, dict) else None,
        "challenge": payload.get("challenge") if isinstance(payload, dict) else None,
        "sut_process_identity": (
            payload.get("sut_process_identity") if isinstance(payload, dict) else None
        ),
        "fact_receipt": {
            "source_kind": FORMAL_LIFECYCLE_FACT_SOURCES[phase],
            "source_process_identity": identity,
            "source_command_digest": fingerprint["digest"],
            "source_channel_credentials": channel_credentials,
            "raw_base64": base64.b64encode(raw).decode(),
            "raw_sha256": digest_bytes(raw),
        },
    }
    source_process = {
        "argv": identity["argv"],
        "pid": process.pid,
        "start_identity": f"pid:{process.pid}@ticks:{identity['start_ticks']}",
        "linux_identity": identity,
        "executable_identity": executable_identity,
        "command_digest": fingerprint["digest"],
        "channel_credentials": channel_credentials,
        "exit_code": process.returncode,
        "monotonic_start_ns": started,
        "monotonic_end_ns": ended,
        "stderr_base64": base64.b64encode(stderr).decode(),
        "stderr_sha256": digest_bytes(stderr),
    }
    reasons: list[str] = []
    validate_formal_lifecycle_receipt(phase, event, source_process, reasons)
    if reasons:
        raise ValueError(reasons[0])
    if (
        phase == "fault-injected"
        and request.get("scenario") == "partial-worker-coverage"
    ):
        source_process["quarantine_finalization"] = _finalize_fault_transaction(
            fingerprint,
            request,
            stderr,
            raw,
            initial_identity,
        )
    return event, source_process


def run_activation_probe(
    entry: dict[str, Any],
    adapter: FormalArmAdapter,
    executable: str,
    arguments: list[str],
) -> dict[str, Any]:
    """Prove the registered executable exposes the adapter's launch options."""
    probe = entry.get("activation_probe")
    if not isinstance(probe, dict):
        raise ValueError("verified adapter is missing an activation probe")
    required = probe.get("required_options")
    timeout_s = probe.get("timeout_s")
    if (
        not isinstance(required, list)
        or not all(isinstance(value, str) for value in required)
        or sorted(required) != sorted(adapter.activation_arguments)
        or not isinstance(timeout_s, int)
        or isinstance(timeout_s, bool)
        or not 1 <= timeout_s <= 30
    ):
        raise ValueError("verified adapter activation probe is invalid")
    probe_arguments = [
        *arguments,
        *adapter.activation_arguments,
        FORMAL_ACTIVATION_PROBE_OPTION,
    ]
    if command_references_fixture([executable, *probe_arguments]):
        raise ValueError("fixture-referencing activation probe is forbidden")
    fingerprint = command_fingerprint_for_launch(executable, probe_arguments)
    if fingerprint["digest"] != probe.get("command_digest"):
        raise ValueError("activation probe command differs from the registry")
    try:
        returncode, stdout, stderr = run_bounded_command(
            [executable, *probe_arguments], timeout_s, 1024 * 1024
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("activation probe did not complete") from exc
    output = stdout + stderr
    try:
        receipt = json.loads(stdout)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("activation probe did not emit a JSON receipt") from exc
    expected_receipt = {
        "schema": "ecpa-activation-probe/v1",
        "activation_contract": adapter.activation_contract,
        "accepted_options": sorted(required),
    }
    if (
        returncode != 0
        or receipt != expected_receipt
        or stdout != canonical(expected_receipt) + b"\n"
    ):
        raise ValueError("executable does not expose the registered activation options")
    return {
        "command": fingerprint,
        "required_options": sorted(required),
        "exit_code": returncode,
        "output_sha256": digest_bytes(output),
        "stdout_base64": base64.b64encode(stdout).decode(),
        "stderr_base64": base64.b64encode(stderr).decode(),
        "receipt": receipt,
    }


def run_ecpa_activation_probe(
    entry: dict[str, Any], adapter: ECPAAdapter, manager_executable: str
) -> dict[str, Any]:
    """Probe the real manager subcommand without launching the target."""
    probe = entry.get("activation_probe")
    if not isinstance(probe, dict):
        raise ValueError("verified adapter is missing an activation probe")
    required = probe.get("required_options")
    timeout_s = probe.get("timeout_s")
    if (
        required != sorted(ECPA_FORMAL_ACTIVATION_OPTIONS)
        or not isinstance(timeout_s, int)
        or isinstance(timeout_s, bool)
        or not 1 <= timeout_s <= 30
    ):
        raise ValueError("verified ECPA activation probe is invalid")
    manager_prefix = executable_launch_prefix(manager_executable)
    probe_arguments = [
        *manager_prefix[1:],
        "formal-run",
        FORMAL_ACTIVATION_PROBE_OPTION,
    ]
    if command_references_fixture([manager_prefix[0], *probe_arguments]):
        raise ValueError("fixture-referencing activation probe is forbidden")
    fingerprint = command_fingerprint(manager_prefix[0], probe_arguments)
    if fingerprint["digest"] != probe.get("command_digest"):
        raise ValueError("manager activation probe differs from the registry")
    try:
        returncode, stdout, stderr = run_bounded_command(
            [fingerprint["executable"], *fingerprint["arguments"]],
            timeout_s,
            1024 * 1024,
            fingerprint,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("manager activation probe did not complete") from exc
    output = stdout + stderr
    try:
        receipt = json.loads(stdout)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(
            "manager activation probe did not emit a JSON receipt"
        ) from exc
    expected_receipt = {
        "schema": "ecpa-activation-probe/v1",
        "activation_contract": adapter.activation_contract,
        "accepted_options": sorted(ECPA_FORMAL_ACTIVATION_OPTIONS),
    }
    if (
        returncode != 0
        or receipt != expected_receipt
        or stdout != canonical(expected_receipt) + b"\n"
    ):
        raise ValueError("manager does not expose the registered formal-run contract")
    return {
        "command": fingerprint,
        "required_options": sorted(ECPA_FORMAL_ACTIVATION_OPTIONS),
        "exit_code": returncode,
        "output_sha256": digest_bytes(output),
        "stdout_base64": base64.b64encode(stdout).decode(),
        "stderr_base64": base64.b64encode(stderr).decode(),
        "receipt": receipt,
    }


def verified_adapter_contract(
    verification_id: str | None,
    adapter: FormalArmAdapter,
    executable: str,
    arguments: list[str],
    observer_executable: str,
    observer_arguments: list[str],
    lifecycle_fact_commands: dict[str, tuple[str, list[str]]] | None = None,
    scenario_id: str = "partial-worker-coverage",
) -> dict[str, Any]:
    """Resolve a code-reviewed adapter entry; caller assertions are not authority."""
    if isinstance(adapter, ECPAAdapter):
        raise ValueError("ECPA formal-real requires managed adapter verification")
    if not verification_id:
        raise ValueError("real formal execution requires a registry verification id")
    registry_bytes = VERIFIED_ADAPTER_REGISTRY.read_bytes()
    registry = json.loads(registry_bytes)
    if (
        registry_bytes != canonical(registry) + b"\n"
        or registry.get("schema") != FORMAL_ADAPTER_REGISTRY_SCHEMA
    ):
        raise ValueError("verified adapter registry must be canonical")
    rows = registry.get("adapters", [])
    entries = {entry["id"]: entry for entry in rows}
    if len(entries) != len(rows):
        raise ValueError("verified adapter registry contains duplicate ids")
    entry = entries.get(verification_id)
    if entry is None:
        raise ValueError("adapter verification id is not in the trusted registry")
    admission = validate_formal_adapter_admission(entry.get("admission"))
    if (
        entry.get("arm") != adapter.arm
        or entry.get("activation_contract") != adapter.activation_contract
        or entry.get("evidence_owner") != "vllm-hust-host"
        or entry.get("evidence_channel") != "host-owned-event-stream"
        or entry.get("host_event_schema") != "ecpa-host-runtime-evidence/v1"
        or entry.get("lifecycle_fact_schema") != "ecpa-formal-lifecycle-fact/v1"
        or entry.get("lifecycle_fact_schema_digest")
        != digest_file(FORMAL_LIFECYCLE_FACT_SCHEMA_PATH)
        or entry.get("lifecycle_fact_sources") != FORMAL_LIFECYCLE_FACT_SOURCES
        or entry.get("lifecycle_fact_transport") != FORMAL_LIFECYCLE_FACT_TRANSPORT
        or not FORMAL_HOST_OBSERVABLES.issubset(
            set(entry.get("required_observables", []))
        )
    ):
        raise ValueError("verified adapter contract does not match the requested arm")
    launch_paths = [executable, observer_executable, *arguments, *observer_arguments]
    if command_references_fixture(launch_paths):
        raise ValueError("fixture-referencing command is forbidden for formal-real")
    sut = command_fingerprint_for_launch(
        executable, [*arguments, *adapter.activation_arguments]
    )
    observer = command_fingerprint_for_launch(observer_executable, observer_arguments)
    if sut["digest"] != entry.get("sut_command_digest"):
        raise ValueError("SUT command differs from the verified adapter artifact")
    if observer["digest"] != entry.get("observer_command_digest"):
        raise ValueError("observer command differs from the verified adapter artifact")
    fact_commands = verified_lifecycle_fact_commands(
        entry,
        lifecycle_fact_commands,
        {sut["digest"], observer["digest"]},
    )
    scenario_binding = verified_scenario_binding(
        entry, scenario_id, fact_commands["fault-injected"]
    )
    activation_probe = run_activation_probe(entry, adapter, executable, arguments)
    return {
        "registry_schema": registry.get("schema"),
        "verification_id": verification_id,
        "registry_digest": digest_bytes(registry_bytes),
        "admission": admission,
        "sut_command": sut,
        "observer_command": observer,
        "lifecycle_fact_commands": fact_commands,
        "scenario_binding": scenario_binding,
        "activation_probe": activation_probe,
        "evidence_owner": entry["evidence_owner"],
        "evidence_channel": entry["evidence_channel"],
        "host_event_schema": entry["host_event_schema"],
        "lifecycle_fact_schema": entry["lifecycle_fact_schema"],
        "lifecycle_fact_schema_digest": entry["lifecycle_fact_schema_digest"],
        "lifecycle_fact_sources": entry["lifecycle_fact_sources"],
        "lifecycle_fact_transport": entry["lifecycle_fact_transport"],
        "required_observables": sorted(entry["required_observables"]),
    }


def verified_ecpa_adapter_contract(
    verification_id: str | None,
    adapter: ECPAAdapter,
    manager_executable: str,
    target_executable: str,
    target_arguments: list[str],
    observer_executable: str,
    observer_arguments: list[str],
    lifecycle_fact_commands: dict[str, tuple[str, list[str]]] | None = None,
    scenario_id: str = "partial-worker-coverage",
) -> dict[str, Any]:
    """Pin manager, target, and observer independently for managed ECPA."""
    if not verification_id:
        raise ValueError("real formal execution requires a registry verification id")
    registry_bytes = VERIFIED_ADAPTER_REGISTRY.read_bytes()
    registry = json.loads(registry_bytes)
    if (
        registry_bytes != canonical(registry) + b"\n"
        or registry.get("schema") != FORMAL_ADAPTER_REGISTRY_SCHEMA
    ):
        raise ValueError("verified adapter registry must be canonical")
    rows = registry.get("adapters", [])
    entries = {entry["id"]: entry for entry in rows}
    if len(entries) != len(rows):
        raise ValueError("verified adapter registry contains duplicate ids")
    entry = entries.get(verification_id)
    if entry is None:
        raise ValueError("adapter verification id is not in the trusted registry")
    admission = validate_formal_adapter_admission(entry.get("admission"))
    if (
        entry.get("arm") != adapter.arm
        or entry.get("activation_contract") != adapter.activation_contract
        or entry.get("evidence_owner") != "vllm-hust-host"
        or entry.get("evidence_channel") != "host-owned-event-stream"
        or entry.get("host_event_schema") != "ecpa-host-runtime-evidence/v1"
        or entry.get("lifecycle_fact_schema") != "ecpa-formal-lifecycle-fact/v1"
        or entry.get("lifecycle_fact_schema_digest")
        != digest_file(FORMAL_LIFECYCLE_FACT_SCHEMA_PATH)
        or entry.get("lifecycle_fact_sources") != FORMAL_LIFECYCLE_FACT_SOURCES
        or entry.get("lifecycle_fact_transport") != FORMAL_LIFECYCLE_FACT_TRANSPORT
        or not FORMAL_HOST_OBSERVABLES.issubset(
            set(entry.get("required_observables", []))
        )
    ):
        raise ValueError("verified ECPA adapter does not match the requested arm")
    launch_paths = [
        manager_executable,
        target_executable,
        observer_executable,
        *target_arguments,
        *observer_arguments,
    ]
    if command_references_fixture(launch_paths):
        raise ValueError("fixture-referencing command is forbidden for formal-real")
    manager_prefix = executable_launch_prefix(manager_executable)
    manager = command_fingerprint(manager_prefix[0], manager_prefix[1:])
    target = command_fingerprint_for_launch(target_executable, target_arguments)
    observer = command_fingerprint_for_launch(observer_executable, observer_arguments)
    if manager["digest"] != entry.get("manager_command_digest"):
        raise ValueError("manager command differs from the verified adapter artifact")
    if target["digest"] != entry.get("target_command_digest"):
        raise ValueError("target command differs from the verified adapter artifact")
    if observer["digest"] != entry.get("observer_command_digest"):
        raise ValueError("observer command differs from the verified adapter artifact")
    fact_commands = verified_lifecycle_fact_commands(
        entry,
        lifecycle_fact_commands,
        {
            manager["digest"],
            target["digest"],
            observer["digest"],
        },
    )
    scenario_binding = verified_scenario_binding(
        entry, scenario_id, fact_commands["fault-injected"]
    )
    activation_probe = run_ecpa_activation_probe(entry, adapter, manager_executable)
    return {
        "registry_schema": registry.get("schema"),
        "verification_id": verification_id,
        "registry_digest": digest_bytes(registry_bytes),
        "admission": admission,
        "manager_command": manager,
        "target_command": target,
        "observer_command": observer,
        "lifecycle_fact_commands": fact_commands,
        "scenario_binding": scenario_binding,
        "activation_probe": activation_probe,
        "evidence_owner": entry["evidence_owner"],
        "evidence_channel": entry["evidence_channel"],
        "host_event_schema": entry["host_event_schema"],
        "lifecycle_fact_schema": entry["lifecycle_fact_schema"],
        "lifecycle_fact_schema_digest": entry["lifecycle_fact_schema_digest"],
        "lifecycle_fact_sources": entry["lifecycle_fact_sources"],
        "lifecycle_fact_transport": entry["lifecycle_fact_transport"],
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


def _freeze_plan_snapshot(event_root: Path, artifact: Any) -> tuple[Path, Any]:
    """Atomically publish validated Plan bytes inside the private run directory."""
    event_metadata = event_root.stat()
    if (
        event_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(event_metadata.st_mode) & 0o022
    ):
        raise ValueError("host event directory must be private and owned")
    token = secrets.token_hex(16)
    partial_name = f".ecpa-plan-partial-{token}"
    snapshot_name = f".ecpa-plan-{token}"
    event_fd = -1
    snapshot_fd = -1
    plan_fd = -1
    created = False
    published = False
    try:
        event_fd = os.open(
            event_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        opened_event_metadata = os.fstat(event_fd)
        if (
            (opened_event_metadata.st_dev, opened_event_metadata.st_ino)
            != (event_metadata.st_dev, event_metadata.st_ino)
            or opened_event_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(opened_event_metadata.st_mode) & 0o022
        ):
            raise ValueError("host event directory changed while opening")
        os.mkdir(partial_name, mode=0o700, dir_fd=event_fd)
        created = True
        snapshot_fd = os.open(
            partial_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=event_fd,
        )
        plan_fd = os.open(
            "plan.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=snapshot_fd,
        )
        remaining = memoryview(artifact.raw)
        while remaining:
            written = os.write(plan_fd, remaining)
            if written <= 0:
                raise OSError("execution-plan snapshot write made no progress")
            remaining = remaining[written:]
        os.fsync(plan_fd)
        os.close(plan_fd)
        plan_fd = -1
        os.fsync(snapshot_fd)
        partial_path = event_root / partial_name / "plan.json"
        frozen_artifact = read_plan_artifact(partial_path)
        if (
            frozen_artifact.raw != artifact.raw
            or frozen_artifact.plan_id != artifact.plan_id
        ):
            raise ValueError("execution-plan snapshot differs from validated input")
        os.fchmod(snapshot_fd, 0o500)
        os.fsync(snapshot_fd)
        os.rename(
            partial_name,
            snapshot_name,
            src_dir_fd=event_fd,
            dst_dir_fd=event_fd,
        )
        published = True
        os.fsync(event_fd)
        plan = event_root / snapshot_name / "plan.json"
        published_artifact = read_plan_artifact(plan)
        if (
            published_artifact.raw != artifact.raw
            or published_artifact.plan_id != artifact.plan_id
        ):
            raise ValueError("published execution-plan snapshot differs")
        return plan, published_artifact
    except BaseException:
        if plan_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(plan_fd)
            plan_fd = -1
        if snapshot_fd >= 0:
            with contextlib.suppress(OSError):
                os.fchmod(snapshot_fd, 0o700)
            with contextlib.suppress(OSError):
                os.unlink("plan.json", dir_fd=snapshot_fd)
        if event_fd >= 0 and created:
            cleanup_name = snapshot_name if published else partial_name
            with contextlib.suppress(OSError):
                os.rmdir(cleanup_name, dir_fd=event_fd)
        raise
    finally:
        if plan_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(plan_fd)
        if snapshot_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(snapshot_fd)
        if event_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(event_fd)


class ECPAAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__(
            "ecpa",
            MANAGED_ACTIVATION_CONTRACT,
            ("--enable-ecpa-manager", "--disable-entrypoints"),
        )

    def managed_launch(
        self,
        *,
        manager_executable: str,
        plan_path: str | Path,
        launch_id: str,
        controller_instance: str,
        host_event_dir: str | Path,
        target_argv: list[str],
        env: dict[str, str],
        dry_run: bool = False,
    ) -> tuple[list[str], dict[str, str], dict[str, Any]]:
        """Build the real manager-owned formal-run path without spoofable flags."""
        if not isinstance(manager_executable, str) or not manager_executable:
            raise ValueError("managed ECPA launch requires a manager executable")
        if not target_argv or any(
            not isinstance(item, str) or not item for item in target_argv
        ):
            raise ValueError("managed ECPA launch requires a non-empty target argv")
        conflicts = CONTROLLED_ENVIRONMENT.intersection(env)
        if conflicts:
            raise ValueError(
                "runner environment conflicts with manager-owned values: "
                + ", ".join(sorted(conflicts))
            )
        manager_prefix = executable_launch_prefix(manager_executable)
        manager_command = command_fingerprint(manager_prefix[0], manager_prefix[1:])
        target_command = command_fingerprint(target_argv[0], target_argv[1:])
        target_argv = [target_command["executable"], *target_command["arguments"]]
        artifact = read_plan_artifact(plan_path)
        if (
            artifact.plan.host.runtime != "vllm-hust"
            or artifact.plan.host.provider != "vllm"
        ):
            raise ValueError("managed ECPA launch requires a vLLM-HUST plan")
        for value, prefix, name in (
            (launch_id, "launch:", "launch id"),
            (controller_instance, "controller:", "controller instance"),
        ):
            if (
                not isinstance(value, str)
                or not value.startswith(prefix)
                or value == prefix
                or value.strip() != value
                or any(character.isspace() for character in value)
            ):
                raise ValueError(f"{name} is not canonical")
        event_root = Path(host_event_dir)
        if (
            not event_root.is_absolute()
            or event_root.is_symlink()
            or not event_root.is_dir()
            or event_root.resolve(strict=True) != event_root
        ):
            raise ValueError("host event directory is not canonical")
        event_metadata = event_root.stat()
        frozen_path, frozen_artifact = _freeze_plan_snapshot(event_root, artifact)
        plan = str(frozen_path)
        argv = [
            manager_command["executable"],
            *manager_command["arguments"],
            "formal-run",
            "--plan",
            plan,
            "--launch-id",
            launch_id,
            "--controller-instance",
            controller_instance,
            "--host-event-dir",
            str(event_root),
            "--target-executable-device",
            str(target_command["executable_device"]),
            "--target-executable-inode",
            str(target_command["executable_inode"]),
            "--target-executable-sha256",
            target_command["executable_sha256"],
        ]
        if dry_run:
            argv.append("--dry-run")
        argv.extend(("--", *target_argv))
        launched = dict(env)
        launched["ECPA_EVALUATION_ARM"] = self.arm
        binding = {
            "activation_contract": self.activation_contract,
            "controller_instance": controller_instance,
            "host_event_dir": str(event_root),
            "host_event_directory": {
                "device": event_metadata.st_dev,
                "inode": event_metadata.st_ino,
            },
            "launch_id": launch_id,
            "plan_id": artifact.plan_id,
            "plan_path": plan,
            "plan_sha256": digest_bytes(frozen_artifact.raw),
            "target_argv": list(target_argv),
            "target_executable": {
                "device": target_command["executable_device"],
                "inode": target_command["executable_inode"],
                "sha256": target_command["executable_sha256"],
            },
        }
        return argv, launched, binding


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


def measured_identity(
    declared: dict[str, Any],
    arm: str,
    env: dict[str, str],
    activation_contract: str | None = None,
):
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
        "activation_contract": activation_contract
        or env.get("ECPA_ACTIVATION_CONTRACT", "reference-only"),
    }


def _read_events(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        events = json.loads(path.read_text())["events"]
        if not isinstance(events, list):
            raise TypeError("events is not a list")
        return events, None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [], f"observer result unavailable or invalid: {type(exc).__name__}"


def _terminate_process(child: subprocess.Popen[Any] | None) -> None:
    if child is None:
        return
    with contextlib.suppress(ProcessLookupError):
        child.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        child.wait(timeout=CHILD_TERMINATION_GRACE_S)
    if child.poll() is None:
        child.kill()
        child.wait()
    for stream in (child.stdin, child.stdout, child.stderr):
        if stream is not None:
            with contextlib.suppress(OSError):
                stream.close()


def _run_start(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one start while guaranteeing child and descriptor cleanup."""
    resources: dict[str, Any] = {"children": [], "fds": set()}
    try:
        return _run_start_impl(*args, _resources=resources, **kwargs)
    finally:
        for descriptor in tuple(resources["fds"]):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        for child in reversed(resources["children"]):
            with contextlib.suppress(Exception):
                _terminate_process(child)


def _run_start_impl(
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
    activation_contract: str | None = None,
    managed_binding: dict[str, Any] | None = None,
    lifecycle_fact_commands: dict[str, dict[str, Any]] | None = None,
    sut_executable_fingerprint: dict[str, Any] | None = None,
    observer_executable_fingerprint: dict[str, Any] | None = None,
    _resources: dict[str, Any],
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
        sut = popen_pinned(
            argv,
            sut_executable_fingerprint,
            cwd=run_dir,
            env=sut_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        _resources["children"].append(sut)
        try:
            sut_identity = wait_for_linux_process_identity(
                sut, argv, timeout_s, sut_executable_fingerprint
            )
        except BaseException:
            _terminate_process(sut)
            raise
        sut_executable_identity = {
            "device": sut_identity.pop("executable_device"),
            "inode": sut_identity.pop("executable_inode"),
        }
        read_fd, write_fd = os.pipe()
        _resources["fds"].update((read_fd, write_fd))
        observer_env = dict(env)
        observer_env["ECPA_OBSERVER_FD"] = str(write_fd)
        observer_env["ECPA_EXPECTED_ARM"] = arm
        observer_env["ECPA_EXPECTED_CONTRACT"] = (
            activation_contract or env["ECPA_ACTIVATION_CONTRACT"]
        )
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
        observer = None
        try:
            observer = popen_pinned(
                observer_argv,
                observer_executable_fingerprint,
                cwd=run_dir,
                env=observer_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                close_fds=True,
                pass_fds=(write_fd,),
            )
            _resources["children"].append(observer)
            observer_identity = wait_for_linux_process_identity(
                observer,
                observer_argv,
                timeout_s,
                observer_executable_fingerprint,
            )
        except BaseException:
            for descriptor in (read_fd, write_fd):
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            for child in (observer, sut):
                _terminate_process(child)
            raise
        observer_executable_identity = {
            "device": observer_identity.pop("executable_device"),
            "inode": observer_identity.pop("executable_inode"),
        }
        os.close(write_fd)
        _resources["fds"].discard(write_fd)
        phase_bounds: dict[str, list[int]] = {}
        phase_invocations: list[dict[str, Any]] = []
        lifecycle_fact_events: list[dict[str, Any]] = []
        lifecycle_fact_processes: dict[str, dict[str, Any]] = {}
        lifecycle_fact_errors: dict[str, str] = {}
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
            ack_end = time.monotonic_ns()
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
            invocation = {
                "phase": phase,
                "sequence": sequence,
                "challenge": challenge,
                "invocation_id": invocation_id,
                "acknowledged": causal,
                "fact_collected": evidence_class != "formal-real",
            }
            phase_invocations.append(invocation)
            if evidence_class == "formal-real":
                command_fingerprint = (lifecycle_fact_commands or {}).get(phase)
                if causal and command_fingerprint is not None:
                    try:
                        fact_event, fact_process = run_lifecycle_fact_source(
                            phase,
                            command_fingerprint,
                            request={
                                "schema": "ecpa-lifecycle-fact-request/v1",
                                "fact": phase,
                                "source_kind": FORMAL_LIFECYCLE_FACT_SOURCES[phase],
                                "plan_id": execution_identity["plan_id"],
                                "launch_id": execution_identity["launch_id"],
                                "controller_instance": execution_identity[
                                    "controller_instance"
                                ],
                                "invocation_id": invocation_id,
                                "sequence": sequence,
                                "challenge": challenge,
                                "scenario": scenario["id"],
                                "sut_pid": sut.pid,
                                "sut_process_identity": sut_identity,
                                "required_processes": identity["required_processes"],
                            },
                            cwd=run_dir,
                            env=sut_env,
                            timeout_s=timeout_s,
                        )
                        lifecycle_fact_events.append(fact_event)
                        lifecycle_fact_processes[phase] = fact_process
                        invocation["fact_collected"] = True
                    except (OSError, ValueError) as exc:
                        lifecycle_fact_errors[phase] = type(exc).__name__
                        causal = False
                else:
                    lifecycle_fact_errors[phase] = "source-unavailable"
                    causal = False
            elif observer.stdin is not None:
                observer_message = {
                    "phase": phase,
                    "monotonic_ns": ack_end,
                    "scenario": scenario["id"],
                    "sequence": sequence,
                    "challenge": challenge,
                    "runner_acknowledged": causal,
                    **execution_identity,
                    "invocation_id": invocation_id,
                }
                observer_message.update({"signal": line, "causal_ack": causal})
                observer.stdin.write(json.dumps(observer_message) + "\n")
                observer.stdin.flush()
            phase_bounds[phase] = [start, time.monotonic_ns()]
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
        _resources["fds"].discard(read_fd)
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
                "executable_identity": sut_executable_identity,
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
                "executable_identity": observer_executable_identity,
            },
            "phase_bounds": phase_bounds,
            "phase_invocations": phase_invocations,
            "execution_identity": execution_identity,
            "managed_binding": managed_binding,
            "lifecycle_fact_processes": lifecycle_fact_processes,
            "lifecycle_fact_errors": lifecycle_fact_errors,
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
    if evidence_class == "formal-real":
        observations = [*observations, *lifecycle_fact_events]
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
        "activation_contract": activation_contract
        or env.get("ECPA_ACTIVATION_CONTRACT"),
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


def validate_managed_plan_coverage(
    plan_path: str | Path, frozen_targets: tuple[tuple[str, str, int, int], ...]
) -> None:
    """Fail closed for the first single-host formal-real topology."""
    artifact = read_plan_artifact(plan_path)
    hosts = {host for host, _, _, _ in frozen_targets}
    if len(hosts) != 1:
        raise ValueError("managed ECPA formal-real currently requires one host")
    declared = {(role, ordinal) for _, role, ordinal, _ in frozen_targets}
    obligated = {
        (obligation.role, ordinal)
        for obligation in artifact.plan.obligations
        for ordinal in obligation.required_ordinals
    }
    if declared != obligated:
        raise ValueError("execution Plan obligations differ from target snapshot")


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
    manager_executable: str | None = None,
    execution_plan_path: str | Path | None = None,
    host_event_dir: str | Path | None = None,
    lifecycle_fact_commands: dict[str, tuple[str, list[str]]] | None = None,
):
    if protocol != json.loads((HERE / "protocol.json").read_text()):
        raise ValueError("formal protocol differs from frozen protocol")
    identity = copy.deepcopy(identity)
    observer_launch_argv = [observer_executable, *observer_arguments]
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
    identity["fixture_only"] = fixture_mode
    if fixture_mode:
        verification = None
        evidence_class = "interface-fixture"
        measurement_source = "controlled-interface-observer"
        argv, env = adapter.launch(executable, arguments, dict(os.environ))
        plan_material = {
            "protocol_digest": digest_bytes(canonical(protocol)),
            "scenario_digest": digest_bytes(canonical(scenario)),
            "arm": adapter.arm,
            "activation_contract": adapter.activation_contract,
            "declared_identity": identity | {"adapter_verification": verification},
        }
        execution_identity = {
            "plan_id": digest_bytes(canonical(plan_material)),
            "launch_id": "launch:" + secrets.token_hex(16),
            "controller_instance": "controller:" + secrets.token_hex(16),
        }
    else:
        frozen_targets = validate_required_process_snapshot(
            identity.get("required_processes")
        )
        identity["required_processes"] = [
            {
                "host": host,
                "role": role,
                "ordinal": ordinal,
                "process_epoch": process_epoch,
            }
            for host, role, ordinal, process_epoch in frozen_targets
        ]
        if isinstance(adapter, ECPAAdapter):
            if not adapter_verification_id:
                raise ValueError(
                    "real formal execution requires a registry verification id"
                )
            if manager_executable is None:
                raise ValueError("managed ECPA formal-real requires a manager")
            if execution_plan_path is None:
                raise ValueError("managed ECPA formal-real requires an execution Plan")
            if host_event_dir is None:
                raise ValueError(
                    "managed ECPA formal-real requires a host event directory"
                )
            validate_managed_plan_coverage(execution_plan_path, frozen_targets)
            launch_id = "launch:" + secrets.token_hex(16)
            controller_instance = "controller:" + secrets.token_hex(16)
            verification = verified_ecpa_adapter_contract(
                adapter_verification_id,
                adapter,
                manager_executable,
                executable,
                arguments,
                observer_executable,
                observer_arguments,
                lifecycle_fact_commands,
                scenario["id"],
            )
            argv, env, binding = adapter.managed_launch(
                manager_executable=manager_executable,
                plan_path=execution_plan_path,
                launch_id=launch_id,
                controller_instance=controller_instance,
                host_event_dir=host_event_dir,
                target_argv=[
                    verification["target_command"]["executable"],
                    *verification["target_command"]["arguments"],
                ],
                env=dict(os.environ),
            )
            execution_identity = {
                "plan_id": binding["plan_id"],
                "launch_id": binding["launch_id"],
                "controller_instance": binding["controller_instance"],
            }
        else:
            verification = verified_adapter_contract(
                adapter_verification_id,
                adapter,
                executable,
                arguments,
                observer_executable,
                observer_arguments,
                lifecycle_fact_commands,
                scenario["id"],
            )
            _, env = adapter.launch(executable, arguments, dict(os.environ))
            argv = [
                verification["sut_command"]["executable"],
                *verification["sut_command"]["arguments"],
            ]
            plan_material = {
                "protocol_digest": digest_bytes(canonical(protocol)),
                "scenario_digest": digest_bytes(canonical(scenario)),
                "arm": adapter.arm,
                "activation_contract": adapter.activation_contract,
                "declared_identity": identity | {"adapter_verification": verification},
            }
            execution_identity = {
                "plan_id": digest_bytes(canonical(plan_material)),
                "launch_id": "launch:" + secrets.token_hex(16),
                "controller_instance": "controller:" + secrets.token_hex(16),
            }
        evidence_class = "formal-real"
        measurement_source = "registry-pinned-host-evidence-observer"
        observer_launch_argv = [
            verification["observer_command"]["executable"],
            *verification["observer_command"]["arguments"],
        ]
    identity["adapter_verification"] = verification
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
        identity=measured_identity(
            identity, adapter.arm, env, adapter.activation_contract
        ),
        observations_from_stdout=False,
        observer_argv=observer_launch_argv,
        execution_identity=execution_identity,
        activation_contract=adapter.activation_contract,
        managed_binding=(
            binding if not fixture_mode and isinstance(adapter, ECPAAdapter) else None
        ),
        lifecycle_fact_commands=(
            verification.get("lifecycle_fact_commands")
            if verification is not None
            else None
        ),
        sut_executable_fingerprint=(
            verification.get("manager_command") or verification.get("sut_command")
            if verification is not None
            else None
        ),
        observer_executable_fingerprint=(
            verification.get("observer_command") if verification is not None else None
        ),
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
