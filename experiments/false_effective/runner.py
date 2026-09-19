"""External-command and reference runner."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from harness import ARMS, canonical, digest_file, oracle, run_command, validate_record


def run_reference_start(
    root: Path,
    scenario: dict[str, Any],
    arm: str,
    repetition: int,
    arm_order: int,
    *,
    fail: bool = False,
    timeout_s: float = 5,
) -> dict[str, Any]:
    start_id = f"{scenario['id']}-r{repetition}-{arm}"
    run_dir = root / "starts" / start_id
    helper = Path(__file__).with_name("helper_service.py").resolve()
    argv = [sys.executable, str(helper), "--arm", arm, "--scenario", scenario["id"]]
    if fail:
        argv.append("--fail")
    command = run_command(run_dir, argv, env=dict(os.environ), timeout_s=timeout_s)
    stdout = (run_dir / command["stdout"]).read_text()
    observations = []
    if stdout.strip():
        observations = json.loads(stdout)["events"]
    status = (
        "complete" if command["exit_code"] == 0 and not command["timeout"] else "failed"
    )
    artifacts = {
        "raw_log": command["stdout"],
        "environment": "environment.json",
        "command": "command.json",
        "oracle": "oracle.json",
        "evidence_bytes": len(stdout.encode()),
        "message_bytes": len(canonical(observations)),
        "digests": {
            command["stdout"]: command["stdout_sha256"],
            command["stderr"]: command["stderr_sha256"],
            "environment.json": command["environment_sha256"],
            "command.json": command["command_sha256"],
        },
    }
    record = {
        "schema": "ecpa-false-effective-start/v1",
        "status": status,
        "evidence_class": "reference-synthetic",
        "measurement_source": "reference-helper-subprocess",
        "cell_id": scenario["id"],
        "scenario": scenario["id"],
        "arm": arm,
        "start_id": start_id,
        "repetition": repetition,
        "arm_order": arm_order,
        "identity": {
            "arm": arm,
            "model": "reference-helper",
            "workload": "deterministic-selftest",
            "hardware": None,
            "runtime_commit": "01d9ac1ebcc1493fe45e31696a2636b3960c1d15",
            "plugin_commits": [],
            "topology": "one helper process",
            "fault": scenario["id"],
            "warm_state": "cold",
            "git_dirty": None,
            "container_digest": None,
            "cpu": None,
            "gpu": None,
            "npu": None,
            "driver": None,
            "runtime": sys.version.split()[0],
        },
        "command": command,
        "artifacts": artifacts,
        "observations": observations,
        "missing_reason": None,
    }
    result = oracle(scenario, record)
    (run_dir / "oracle.json").write_bytes(canonical(result) + b"\n")
    artifacts["digests"]["oracle.json"] = digest_file(run_dir / "oracle.json")
    record["oracle"] = result
    (run_dir / "record.json").write_bytes(canonical(record) + b"\n")
    validate_record(record, run_dir)
    return record


def planned_records(scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for scenario in scenarios:
        for arm in ARMS:
            rows.append(
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
                    "missing_reason": (
                        "real service command and raw observer not configured"
                    ),
                }
            )
    return rows
