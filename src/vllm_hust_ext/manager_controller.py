"""Fail-closed manager-owned launch seam for a vLLM-HUST ECPA Plan."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from .ecpa_model import canonical_bytes
from .plan_artifact import ExecutionPlanArtifact, read_plan_artifact

ACTIVATION_CONTRACT = "manager-controlled-activation"
HOST_SINK = "vllm_hust_ext.host_event_sink:append_event"
CONTROLLED_ENVIRONMENT = {
    "VLLM_ECPA_PLAN_ID",
    "VLLM_ECPA_LAUNCH_ID",
    "VLLM_ECPA_EVIDENCE_SINK",
    "VLLM_ECPA_EVIDENCE_STRICT",
    "ECPA_HOST_EVENT_DIR",
    "ECPA_HOST_EVENT_FSYNC",
    "ECPA_HOST_EVENT_DEVICE",
    "ECPA_HOST_EVENT_INODE",
    "ECPA_CONTROLLER_INSTANCE",
    "ECPA_ACTIVATION_CONTRACT",
}


def activation_probe_receipt() -> bytes:
    """Describe the real manager entry point without launching a target."""
    return (
        canonical_bytes(
            {
                "schema": "ecpa-activation-probe/v1",
                "activation_contract": ACTIVATION_CONTRACT,
                "accepted_options": [
                    "--controller-instance",
                    "--host-event-dir",
                    "--launch-id",
                    "--plan",
                    "formal-run",
                ],
            }
        )
        + b"\n"
    )


def _identity(value: Any, name: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(prefix)
        or value == prefix
        or value.strip() != value
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{name} is not a canonical {prefix!r} identity")
    return value


def managed_host_environment(
    base: dict[str, str],
    artifact: ExecutionPlanArtifact,
    launch_id: str,
    controller_instance: str,
    host_event_dir: str | Path,
) -> dict[str, str]:
    """Bind the child to manager-owned Plan, launch, and evidence custody."""
    launch_id = _identity(launch_id, "launch id", "launch:")
    controller_instance = _identity(
        controller_instance, "controller instance", "controller:"
    )
    root = Path(host_event_dir)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError("host event directory must be an existing canonical path")
    metadata = root.stat()
    if (
        root.resolve(strict=True) != root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ValueError("host event directory must be private and owned")
    desired = {
        "VLLM_ECPA_PLAN_ID": artifact.plan_id,
        "VLLM_ECPA_LAUNCH_ID": launch_id,
        "VLLM_ECPA_EVIDENCE_SINK": HOST_SINK,
        "VLLM_ECPA_EVIDENCE_STRICT": "1",
        "ECPA_HOST_EVENT_DIR": str(root),
        "ECPA_HOST_EVENT_FSYNC": "1",
        "ECPA_HOST_EVENT_DEVICE": str(metadata.st_dev),
        "ECPA_HOST_EVENT_INODE": str(metadata.st_ino),
        "ECPA_CONTROLLER_INSTANCE": controller_instance,
        "ECPA_ACTIVATION_CONTRACT": ACTIVATION_CONTRACT,
    }
    conflicts = CONTROLLED_ENVIRONMENT.intersection(base)
    if conflicts:
        raise ValueError(
            "caller environment conflicts with manager-owned values: "
            + ", ".join(sorted(conflicts))
        )
    environment = dict(base)
    environment.update(desired)
    return environment


def launch_managed(
    *,
    plan_path: str | Path,
    launch_id: str,
    controller_instance: str,
    host_event_dir: str | Path,
    command: list[str],
    base_environment: dict[str, str] | None = None,
    dry_run: bool = False,
) -> int:
    """Validate every manager input before starting the target process."""
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise ValueError("formal-run requires a non-empty target after --")
    artifact = read_plan_artifact(plan_path)
    if (
        artifact.plan.host.runtime != "vllm-hust"
        or artifact.plan.host.provider != "vllm"
    ):
        raise ValueError("formal-run requires a vLLM-HUST execution plan")
    environment = managed_host_environment(
        dict(os.environ) if base_environment is None else base_environment,
        artifact,
        launch_id,
        controller_instance,
        host_event_dir,
    )
    if dry_run:
        print(
            json.dumps(
                {
                    "activation_contract": ACTIVATION_CONTRACT,
                    "command": command,
                    "controlled_environment": {
                        key: environment[key] for key in sorted(CONTROLLED_ENVIRONMENT)
                    },
                    "controller_instance": environment["ECPA_CONTROLLER_INSTANCE"],
                    "plan_id": artifact.plan_id,
                    "schema": "ecpa-managed-launch/v1",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    return subprocess.call(command, env=environment)
