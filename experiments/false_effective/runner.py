"""External-command and reference runner."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness import (
    ARMS,
    canonical,
    digest_bytes,
    digest_file,
    oracle,
    run_command,
    validate_record,
)

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class FormalArmAdapter:
    arm: str

    def argv(self, executable: str, arguments: list[str]) -> list[str]:
        return [executable, *arguments]


class VanillaVLLMAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__("vanilla-vllm-entry-points")


class ManualIntegrationAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__("manual-integration")


class ECPAAdapter(FormalArmAdapter):
    def __init__(self):
        super().__init__("ecpa")


def run_reference_start(
    root: Path,
    scenario: dict[str, Any],
    arm: str,
    repetition: int,
    arm_order: int,
    *,
    fail: bool = False,
    timeout_s: float = 5,
    adapter: FormalArmAdapter | None = None,
    executable: str | None = None,
    arguments: list[str] | None = None,
    formal_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    start_id = f"{scenario['id']}-r{repetition}-{arm}"
    run_dir = root / "starts" / start_id
    helper = Path(__file__).with_name("helper_service.py").resolve()
    argv = [sys.executable, str(helper), "--arm", arm, "--scenario", scenario["id"]]
    evidence_class = "reference-synthetic"
    measurement_source = "reference-helper-subprocess"
    if adapter is not None:
        if adapter.arm != arm or executable is None or formal_identity is None:
            raise ValueError("formal adapter, arm, executable, and identity must match")
        argv = adapter.argv(executable, arguments or [])
        evidence_class = "formal-real"
        measurement_source = "external-command-formal"
    if fail:
        argv.append("--fail")
    command = run_command(run_dir, argv, env=dict(os.environ), timeout_s=timeout_s)
    stdout = (run_dir / command["stdout"]).read_text()
    observations = []
    if stdout.strip():
        observations = json.loads(stdout)["events"]
    protocol = json.loads((HERE / "protocol.json").read_text())
    schema = json.loads((HERE / "raw-record.schema.json").read_text())
    (run_dir / "observations.json").write_bytes(
        canonical({"events": observations}) + b"\n"
    )
    (run_dir / "scenario.json").write_bytes(canonical(scenario) + b"\n")
    (run_dir / "protocol.json").write_bytes(canonical(protocol) + b"\n")
    status = (
        "complete" if command["exit_code"] == 0 and not command["timeout"] else "failed"
    )
    artifacts = {
        "raw_log": command["stdout"],
        "environment": "environment.json",
        "command": "command.json",
        "oracle": "oracle.json",
        "intake": "intake.json",
        "observations": "observations.json",
        "scenario": "scenario.json",
        "protocol": "protocol.json",
        "evidence_bytes": len(stdout.encode()),
        "message_bytes": len(canonical(observations)),
        "digests": {
            command["stdout"]: command["stdout_sha256"],
            command["stderr"]: command["stderr_sha256"],
            "environment.json": command["environment_sha256"],
            "command.json": command["command_sha256"],
            "observations.json": digest_file(run_dir / "observations.json"),
            "scenario.json": digest_file(run_dir / "scenario.json"),
            "protocol.json": digest_file(run_dir / "protocol.json"),
        },
    }
    identity = formal_identity or {
        "arm": arm,
        "model": "reference-helper",
        "dataset": "reference-events-v1",
        "workload": "deterministic-selftest",
        "hardware": "reference-local-process",
        "software": {"python": sys.version.split()[0]},
        "observer": "helper-json-events/v1",
        "runtime_commit": "01d9ac1ebcc1493fe45e31696a2636b3960c1d15",
        "plugin_commits": [],
        "topology": "one helper process",
        "fault_plan": scenario["id"],
        "fault": scenario["id"],
        "semantic_environment": "reference-only",
        "warm_state": "cold",
        "git_dirty": False,
        "container_digest": "not-containerized",
        "cpu": "unmeasured-reference",
        "gpu": "not-applicable",
        "npu": "not-applicable",
        "driver": "not-applicable",
        "runtime": sys.version.split()[0],
    }
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
    }
    (run_dir / "intake.json").write_bytes(canonical(intake) + b"\n")
    artifacts["digests"]["intake.json"] = digest_file(run_dir / "intake.json")
    record = {
        "schema": "ecpa-false-effective-start/v1",
        "status": status,
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
        "missing_reason": None,
        "intake_digest": artifacts["digests"]["intake.json"],
        "artifact_root": f"starts/{start_id}",
    }
    result = oracle(scenario, record)
    if result["verdict"] != "PASS" and record["status"] == "complete":
        record["status"] = "failed"
        record["missing_reason"] = "; ".join(result["reasons"])
        result = oracle(scenario, record)
    (run_dir / "oracle.json").write_bytes(canonical(result) + b"\n")
    artifacts["digests"]["oracle.json"] = digest_file(run_dir / "oracle.json")
    chain = {
        "schema": "ecpa-runner-content-chain/v1",
        "intake_digest": record["intake_digest"],
        "artifact_digests": dict(sorted(artifacts["digests"].items())),
    }
    (run_dir / "chain.json").write_bytes(canonical(chain) + b"\n")
    artifacts["chain"] = "chain.json"
    record["chain_digest"] = digest_file(run_dir / "chain.json")
    record["oracle"] = result
    (run_dir / "record.json").write_bytes(canonical(record) + b"\n")
    validate_record(record, root, scenario=scenario, protocol=protocol, schema=schema)
    return record


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
    identity: dict[str, Any],
    timeout_s: float,
) -> dict[str, Any]:
    frozen = json.loads((HERE / "protocol.json").read_text())
    if protocol != frozen:
        raise ValueError("formal protocol differs from frozen protocol")
    if any(value is None for value in identity.values()):
        raise ValueError("formal identity fields must not be null")
    return run_reference_start(
        root,
        scenario,
        adapter.arm,
        repetition,
        arm_order,
        timeout_s=timeout_s,
        adapter=adapter,
        executable=executable,
        arguments=arguments,
        formal_identity=identity,
    )


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
