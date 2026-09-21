#!/usr/bin/env python3
"""Exercise the real vLLM-HUST producer against the ECPA host adapter."""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.host_event_sink import read_events
from vllm_hust_ext.host_evidence import EntryPointBinding, translate_invocation

SCHEMA = "ecpa-vllm-host-adapter-preflight/v1"
PRODUCER_PATHS = (
    "vllm/plugins/evidence.py",
    "vllm/v1/core/sched/preemption.py",
    "vllm/v1/engine/core.py",
    "vllm/v1/executor/multiproc_executor.py",
)
PRODUCER_ORIGINS = {
    "https://github.com/vLLM-HUST/vllm-hust.git",
    "git@github.com:vLLM-HUST/vllm-hust.git",
}


class PreflightError(RuntimeError):
    """The checked producer cannot satisfy the adapter preflight."""


class _Logger:
    def info(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def warning_once(self, *_args: Any, **_kwargs: Any) -> None:
        pass


def _git(checkout: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(checkout), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _git_bytes(checkout: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(checkout), *arguments),
        check=True,
        capture_output=True,
    )
    return result.stdout


def verify_checkout(
    checkout: Path, expected_commit: str, expected_tree: str
) -> dict[str, str]:
    checkout = checkout.resolve(strict=True)
    origin = _git(checkout, "remote", "get-url", "origin")
    if origin not in PRODUCER_ORIGINS:
        raise PreflightError(
            "vLLM-HUST checkout origin is not the canonical repository"
        )
    commit = _git(checkout, "rev-parse", "HEAD")
    tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    if commit != expected_commit or tree != expected_tree:
        raise PreflightError("vLLM-HUST checkout does not match the pinned commit/tree")
    if _git(checkout, "status", "--porcelain"):
        raise PreflightError("vLLM-HUST checkout must be clean")
    blobs = {}
    for relative in PRODUCER_PATHS:
        path = checkout / relative
        if not path.is_file() or path.is_symlink():
            raise PreflightError(f"producer source is unavailable: {relative}")
        blobs[relative] = _git(checkout, "rev-parse", f"HEAD:{relative}")
    return blobs


def materialize_producer_snapshot(
    checkout: Path, destination: Path, source_blobs: dict[str, str]
) -> None:
    destination.mkdir(mode=0o700)
    for relative in PRODUCER_PATHS:
        expected_blob = source_blobs.get(relative)
        if expected_blob is None:
            raise PreflightError("producer source blob set is incomplete")
        object_bytes = _git_bytes(checkout, "cat-file", "blob", f"HEAD:{relative}")
        header = f"blob {len(object_bytes)}\0".encode()
        actual_blob = hashlib.sha1(header + object_bytes).hexdigest()  # noqa: S324
        if actual_blob != expected_blob:
            raise PreflightError("producer object bytes differ from the pinned blob")
        source = checkout / relative
        if source.read_bytes() != object_bytes:
            raise PreflightError("producer worktree changed after identity validation")
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(object_bytes)
        target.chmod(0o400)


def _has_binding(
    path: Path,
    *,
    class_name: str,
    function_name: str,
    role: str,
    ordinal_name: str,
) -> bool:
    tree = ast.parse(path.read_text(), filename=str(path))
    owner = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ),
        None,
    )
    if owner is None:
        return False
    function = next(
        (
            node
            for node in owner.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ),
        None,
    )
    if function is None:
        return False
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "bind_process_identity" or len(node.args) != 2:
            continue
        role_arg, ordinal_arg = node.args
        if (
            isinstance(role_arg, ast.Constant)
            and role_arg.value == role
            and isinstance(ordinal_arg, ast.Name)
            and ordinal_arg.id == ordinal_name
        ):
            return True
    return False


def verify_native_bindings(checkout: Path) -> None:
    if not _has_binding(
        checkout / "vllm/v1/engine/core.py",
        class_name="EngineCoreProc",
        function_name="run_engine_core",
        role="engine-core-scheduler",
        ordinal_name="dp_rank",
    ):
        raise PreflightError("EngineCore does not bind its native data-parallel rank")
    if not _has_binding(
        checkout / "vllm/v1/executor/multiproc_executor.py",
        class_name="WorkerProc",
        function_name="worker_main",
        role="worker",
        ordinal_name="worker_ordinal",
    ):
        raise PreflightError("worker entry does not bind its native global rank")


def _load(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PreflightError(f"cannot load producer module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _producer_modules(checkout: Path) -> Iterator[tuple[Any, Any]]:
    names = (
        "vllm",
        "vllm.logger",
        "vllm.plugins",
        "vllm.plugins.evidence",
        "vllm.utils",
        "vllm.utils.import_utils",
        "vllm.v1",
        "vllm.v1.core",
        "vllm.v1.core.sched",
        "vllm.v1.core.sched.preemption",
    )
    previous = {name: sys.modules.get(name) for name in names}
    try:
        for name in names:
            sys.modules.pop(name, None)
        for name in (
            "vllm",
            "vllm.plugins",
            "vllm.utils",
            "vllm.v1",
            "vllm.v1.core",
            "vllm.v1.core.sched",
        ):
            module = types.ModuleType(name)
            module.__path__ = []  # type: ignore[attr-defined]
            sys.modules[name] = module
        logger_module = types.ModuleType("vllm.logger")
        logger_module.init_logger = lambda _name: _Logger()  # type: ignore[attr-defined]
        sys.modules[logger_module.__name__] = logger_module
        imports_module = types.ModuleType("vllm.utils.import_utils")
        imports_module.resolve_obj_by_qualname = lambda value: value  # type: ignore[attr-defined]
        sys.modules[imports_module.__name__] = imports_module
        evidence = _load("vllm.plugins.evidence", checkout / "vllm/plugins/evidence.py")
        preemption = _load(
            "vllm.v1.core.sched.preemption",
            checkout / "vllm/v1/core/sched/preemption.py",
        )
        yield evidence, preemption
    finally:
        for name in names:
            sys.modules.pop(name, None)
        for name, module in previous.items():
            if module is not None:
                sys.modules[name] = module


@contextlib.contextmanager
def _environment(values: dict[str, str]) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def run_preflight(
    checkout: Path,
    *,
    expected_commit: str,
    expected_tree: str,
) -> dict[str, Any]:
    checkout = checkout.resolve(strict=True)
    source_blobs = verify_checkout(checkout, expected_commit, expected_tree)

    plugin = PluginIdentity("org.vllm-hust", "adapter-preflight", "1", "a" * 64)
    obligation = EvidenceObligation(
        "scheduler-dispatch", "engine-core-scheduler", "invoked", (0,)
    )
    plan = Plan(
        (plugin,),
        HostCompatibility("vllm-hust", "candidate", "vllm", "1"),
        (),
        (obligation,),
        PredecessorSnapshot(0, None, {}),
    )
    launch_id = "launch:adapter-preflight"

    with (
        tempfile.TemporaryDirectory(prefix="ecpa-producer-snapshot-") as snapshot_name,
        tempfile.TemporaryDirectory(prefix="ecpa-host-adapter-") as directory_name,
    ):
        snapshot = Path(snapshot_name).resolve() / "source"
        materialize_producer_snapshot(checkout, snapshot, source_blobs)
        verify_native_bindings(snapshot)
        directory = Path(directory_name).resolve()
        directory.chmod(0o700)
        identity = directory.stat()
        environment = {
            "VLLM_ECPA_EVIDENCE_SINK": "vllm_hust_ext.host_event_sink:append_event",
            "VLLM_ECPA_EVIDENCE_STRICT": "1",
            "VLLM_ECPA_PLAN_ID": plan.plan_id,
            "VLLM_ECPA_LAUNCH_ID": launch_id,
            "ECPA_HOST_EVENT_DIR": str(directory),
            "ECPA_HOST_EVENT_DEVICE": str(identity.st_dev),
            "ECPA_HOST_EVENT_INODE": str(identity.st_ino),
            "ECPA_HOST_EVENT_FSYNC": "1",
        }
        with (
            _environment(environment),
            _producer_modules(snapshot) as (
                evidence,
                preemption,
            ),
        ):
            evidence.bind_process_identity("engine-core-scheduler", 0)

            class SelectFirstPolicy:
                def select_victim(self, context: Any) -> str:
                    return context.candidates[0].request_id

            config = SimpleNamespace(
                scheduler_config=SimpleNamespace(preemption_policy=SelectFirstPolicy)
            )
            candidates = (
                preemption.PreemptionCandidate("first", 1, 1.0, 10, 2, 12, 0, 20),
                preemption.PreemptionCandidate("last", 3, 2.0, 8, 4, 12, 1, 20),
            )
            context = preemption.PreemptionContext(
                candidates, "fcfs", "first", 0.95, 3.0, "last"
            )
            controller = preemption.PreemptionPolicyController(config)
            selected = controller.select_victim(context)
            policy_name = controller.stats.policy_name

        records = read_events(directory, (identity.st_dev, identity.st_ino))
        if selected != "first" or len(records) != 2:
            raise PreflightError(
                "native policy path did not emit resolution and dispatch"
            )
        resolution, dispatch = (record.event for record in records)
        if (
            resolution["observation_kind"] != "scheduler_resolution"
            or dispatch["observation_kind"] != "scheduler_dispatch"
            or dispatch["process"]["assignment_source"] != "host"
            or dispatch["process"]["role"] != "engine-core-scheduler"
            or dispatch["process"]["ordinal"] != 0
            or dispatch["plan_id"] != plan.plan_id
            or dispatch["launch_id"] != launch_id
            or dispatch["detail"] != "engine-core.scheduler:selected"
        ):
            raise PreflightError(
                "native policy evidence is not host-bound dispatch evidence"
            )
        binding = EntryPointBinding(
            "vllm.preemption_policy",
            policy_name,
            policy_name,
            plugin.id,
            obligation.obligation_id,
        )
        receipt = translate_invocation(
            records[1].raw,
            plan=plan,
            launch_id=launch_id,
            process_epoch=dispatch["process"]["process_epoch"],
            binding=binding,
            issuer="urn:ecpa:issuer:adapter-preflight",
            kid="adapter-preflight-key",
            challenge_nonce="adapter-preflight-challenge",
            issued_at=dispatch["observed_at_ns"] // 1_000_000_000,
            expires_at=dispatch["observed_at_ns"] // 1_000_000_000 + 60,
        )
        raw_digest = "sha256:" + hashlib.sha256(records[1].raw).hexdigest()
        if receipt.statement.evidence_digest != raw_digest:
            raise PreflightError(
                "translated receipt does not bind the exact host bytes"
            )

    return {
        "schema": SCHEMA,
        "classification": "cross-repository-adapter-preflight",
        "formal_real_result": False,
        "producer": {
            "repository": "vLLM-HUST/vllm-hust",
            "origin": _git(checkout, "remote", "get-url", "origin"),
            "commit": expected_commit,
            "tree": expected_tree,
            "source_blobs": source_blobs,
        },
        "observed_path": {
            "controller": "vllm.v1.core.sched.preemption.PreemptionPolicyController",
            "selected_victim": selected,
            "events": [resolution["observation_kind"], dispatch["observation_kind"]],
            "process_role": dispatch["process"]["role"],
            "process_ordinal": dispatch["process"]["ordinal"],
            "assignment_source": dispatch["process"]["assignment_source"],
            "dispatch_id": dispatch["dispatch_id"],
        },
        "translation": {
            "plan_id": plan.plan_id,
            "launch_id": launch_id,
            "obligation": receipt.statement.obligation,
            "event": receipt.statement.event,
            "evidence_digest": raw_digest,
        },
        "limitations": [
            "This preflight executes the producer's native policy controller "
            "but not a serving engine or workload.",
            "It is not a formal-real cell, performance result, or evidence of "
            "complete worker coverage.",
            "Producer admission still requires the merged host commit and "
            "repository-required human line review.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vllm-checkout", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    arguments = parser.parse_args()
    print(
        _canonical(
            run_preflight(
                arguments.vllm_checkout,
                expected_commit=arguments.expected_commit,
                expected_tree=arguments.expected_tree,
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
