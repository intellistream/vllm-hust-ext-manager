#!/usr/bin/env python3
"""Fail-closed compatibility audit for a formal-real deployment candidate."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "ecpa-formal-real-stack-preflight/v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def audit_stack(
    requirements: dict[str, Any], observed: dict[str, Any]
) -> dict[str, Any]:
    """Compare one observed host with one immutable deployment candidate."""
    blockers: list[str] = []
    runtime = requirements["runtime"]
    observed_runtime = observed["runtime"]
    plugin = requirements["accelerator_plugin"]
    observed_plugin = observed["accelerator_plugin"]
    hardware = requirements["hardware"]
    observed_hardware = observed["hardware"]
    model = requirements["model"]
    observed_model = observed["model"]
    execution = requirements["execution"]
    observed_execution = observed["execution"]

    if observed_runtime["commit"] is None or observed_runtime["tree"] is None:
        blockers.append("runtime-checkout-unavailable")
    elif (
        observed_runtime["commit"] != runtime["commit"]
        or observed_runtime["tree"] != runtime["tree"]
    ):
        blockers.append("runtime-identity-mismatch")

    if observed_plugin["commit"] is None:
        blockers.append("accelerator-plugin-checkout-unavailable")
    elif observed_plugin["commit"] != plugin["commit"] or observed_plugin.get(
        "tree"
    ) != plugin.get("tree"):
        blockers.append("accelerator-plugin-identity-mismatch")

    if plugin["verified_runtime_commit"] != runtime["upstream_commit"]:
        blockers.append("accelerator-plugin-runtime-unverified")
    if observed["cann_version"] != plugin["required_cann_version"]:
        blockers.append("cann-version-mismatch")
    if (
        observed_hardware["device_family"] != hardware["device_family"]
        or observed_hardware["device_count"] < hardware["minimum_devices"]
    ):
        blockers.append("hardware-topology-mismatch")

    if execution["container_required"]:
        if not observed_execution["container_server_accessible"]:
            blockers.append("container-server-unavailable")
        if execution["image_digest"] is None:
            blockers.append("container-image-unfrozen")
        elif observed_execution["image_digest"] != execution["image_digest"]:
            blockers.append("container-image-mismatch")
        if observed_execution.get("image_source_commits") != execution.get(
            "image_source_commits"
        ):
            blockers.append("container-source-binary-mismatch")
        if observed_execution.get("runtime_mode") != execution.get("runtime_mode"):
            blockers.append("runtime-mode-mismatch")

    if (
        observed_model["repository"] != model["repository"]
        or observed_model["revision"] != model["revision"]
    ):
        blockers.append("model-identity-mismatch")
    available_files = set(observed_model["files"])
    if not set(model["required_files"]).issubset(available_files):
        blockers.append("model-files-incomplete")
    if not any(
        fnmatch.fnmatch(path, pattern)
        for pattern in model["weight_patterns"]
        for path in available_files
    ):
        blockers.append("model-weights-missing")
    required_digests = model.get("file_sha256", {})
    observed_digests = observed_model.get("file_sha256", {})
    if any(
        observed_digests.get(path) != digest
        for path, digest in required_digests.items()
    ):
        blockers.append("model-content-mismatch")

    return {
        "schema": SCHEMA,
        "classification": "deployment-stack-preflight",
        "formal_real_result": False,
        "registration_authority": False,
        "candidate_id": requirements["candidate_id"],
        "observed_at": observed["observed_at"],
        "requirements_digest": _digest(requirements),
        "observation_digest": _digest(observed),
        "status": "blocked" if blockers else "ready-for-registration-review",
        "blockers": blockers,
        "non_claims": [
            "A ready preflight is not a registered adapter or formal-real result.",
            "This audit does not establish model correctness, worker coverage, "
            "or policy effect.",
            "Compatibility metadata does not replace a real serving launch and "
            "independent observations.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    arguments = parser.parse_args()
    requirements = json.loads(arguments.requirements.read_text())
    observed = json.loads(arguments.observation.read_text())
    print(_canonical(audit_stack(requirements, observed)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
