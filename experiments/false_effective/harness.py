"""False-effective experiment control plane; no production-result defaults."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import time
from pathlib import Path
from typing import Any

ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
RULE_VERSION = "ecpa-false-effective-oracle/v1"
ALLOW_ENV = {"LANG", "LC_ALL", "PATH", "PYTHONPATH"}


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
        "events": ["service-start-attempt", "service-shutdown-observed"],
    }
    command_path.write_bytes(canonical(command) + b"\n")
    return {
        **command,
        "stdout": stdout_path.name,
        "stdout_sha256": digest_file(stdout_path),
        "stderr": stderr_path.name,
        "stderr_sha256": digest_file(stderr_path),
        "environment_sha256": digest_file(env_path),
        "command_sha256": digest_file(command_path),
    }


def oracle(scenario: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    observations = record["observations"]
    forbidden = {"truth", "false_effective", "conflict_truth"}
    if any(forbidden.intersection(item) for item in observations):
        raise ValueError("SUT observations contain oracle-owned truth fields")
    events = {item["event"]: item for item in observations}
    truth = scenario["truth"]
    claimed = bool(events.get("effective-claim", {}).get("value", False))
    invoked = bool(events.get("plugin-invoked", {}).get("value", False))
    covered = events.get("coverage", {}).get("value")
    decision = events.get("conflict-decision", {}).get("value")
    rollback = events.get("rollback-class", {}).get("value")
    false_effective = claimed and (not truth["activation_possible"] or not invoked)
    rollback_success = None
    if truth["rollback_required"]:
        rollback_success = rollback in {"RESTORED_STRONG", "BEHAVIORAL", "FAILED_SAFE"}
    outcome = {
        "false_effective": false_effective,
        "activation_event_coverage": covered,
        "conflict_truth": truth["conflict"],
        "conflict_decision": decision,
        "rollback_class": rollback,
        "rollback_success": rollback_success,
        "startup_ms": None,
        "recovery_ms": None,
        "throughput": None,
        "latency_p99_ms": None,
        "evidence_bytes": record["artifacts"].get("evidence_bytes"),
        "message_bytes": record["artifacts"].get("message_bytes"),
    }
    inputs = {"scenario": scenario, "observations": observations}
    return {
        "schema": RULE_VERSION,
        "input_digest": digest_bytes(canonical(inputs)),
        "record_digest": digest_bytes(canonical(record)),
        "verdict": "PASS",
        "reasons": [],
        "outcome": outcome,
    }


def validate_record(record: dict[str, Any], root: Path) -> None:
    canonical(record)
    if record["status"] == "planned":
        if record["missing_reason"] is None:
            raise ValueError("planned record requires missing reason")
        return
    command = record.get("command")
    artifacts = record.get("artifacts", {})
    if record["status"] == "complete" and record["evidence_class"] == "formal-real":
        identity_fields = {
            "model",
            "workload",
            "hardware",
            "runtime_commit",
            "plugin_commits",
            "topology",
            "fault",
            "warm_state",
            "git_dirty",
            "container_digest",
            "cpu",
            "gpu",
            "npu",
            "driver",
            "runtime",
        }
        missing_identity = identity_fields.difference(record["identity"])
        if missing_identity:
            raise ValueError(
                f"formal complete missing identity: {sorted(missing_identity)}"
            )
        for field in ("raw_log", "environment", "command", "oracle"):
            if not artifacts.get(field):
                raise ValueError(f"formal complete missing {field}")
            name = artifacts[field]
            if name not in artifacts.get("digests", {}):
                raise ValueError(f"formal complete missing digest for {field}")
    if command is None:
        raise ValueError("executed record requires command")
    for name, expected in artifacts.get("digests", {}).items():
        path = safe_path(root, name)
        if not path.is_file() or digest_file(path) != expected:
            raise ValueError(f"artifact digest mismatch: {name}")


def validate_batch(records: list[dict[str, Any]], root: Path, *, formal: bool) -> None:
    ids = [item["start_id"] for item in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate start_id")
    for record in records:
        validate_record(record, root)
        if formal and record["evidence_class"] != "formal-real":
            raise ValueError("synthetic evidence cannot enter formal aggregate")
    complete = [item for item in records if item["status"] == "complete"]
    if formal and complete:
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in complete:
            groups.setdefault(item["cell_id"], []).append(item)
        for cell, rows in groups.items():
            if len(rows) < 9 or {row["arm"] for row in rows} != set(ARMS):
                raise ValueError(f"cell {cell} lacks 3 starts x 3 arms")
            if any(sum(row["arm"] == arm for row in rows) < 3 for arm in ARMS):
                raise ValueError(f"cell {cell} has fewer than 3 starts per arm")
            identities = [
                {k: v for k, v in row["identity"].items() if k != "arm"} for row in rows
            ]
            if any(value != identities[0] for value in identities[1:]):
                raise ValueError(f"cell {cell} matched-arm metadata mismatch")
            orders = {(row["repetition"], row["arm_order"]) for row in rows}
            if len(orders) != 9:
                raise ValueError(f"cell {cell} order schedule is unbalanced")


def wilson(numerator: int, denominator: int) -> list[float] | None:
    if denominator < 3:
        return None
    z = 1.959963984540054
    p = numerator / denominator
    d = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / d
    half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / d
    return [center - half, center + half]


def aggregate(
    records: list[dict[str, Any]], root: Path, *, formal: bool
) -> dict[str, Any]:
    validate_batch(records, root, formal=formal)
    complete = [row for row in records if row["status"] == "complete"]
    if not complete:
        return {
            "schema": "ecpa-false-effective-aggregate/v1",
            "formal": formal,
            "completed_cells": 0,
            "metrics": None,
            "reason": "no validator-approved complete formal-real cells",
        }
    false_values = [row["oracle"]["outcome"]["false_effective"] for row in complete]
    numerator = sum(false_values)
    coverage = [
        row["oracle"]["outcome"]["activation_event_coverage"] for row in complete
    ]
    coverage = [value for value in coverage if value is not None]
    conflict_rows = [
        row["oracle"]["outcome"]
        for row in complete
        if row["oracle"]["outcome"]["conflict_truth"] != "not-applicable"
    ]
    tp = sum(
        row["conflict_truth"] == "conflict" and row["conflict_decision"] == "reject"
        for row in conflict_rows
    )
    fp = sum(
        row["conflict_truth"] != "conflict" and row["conflict_decision"] == "reject"
        for row in conflict_rows
    )
    fn = sum(
        row["conflict_truth"] == "conflict" and row["conflict_decision"] != "reject"
        for row in conflict_rows
    )
    rollback_classes = [row["oracle"]["outcome"]["rollback_class"] for row in complete]
    rollback_classes = [value for value in rollback_classes if value is not None]
    startup_samples = [
        (row["command"]["monotonic_end_ns"] - row["command"]["monotonic_start_ns"])
        / 1_000_000
        for row in complete
    ]
    return {
        "schema": "ecpa-false-effective-aggregate/v1",
        "formal": formal,
        "completed_cells": len({row["cell_id"] for row in complete}),
        "metrics": {
            "n_starts": len(complete),
            "false_effective": {
                "numerator": numerator,
                "denominator": len(false_values),
                "rate": numerator / len(false_values),
                "wilson95": wilson(numerator, len(false_values)),
            },
            "coverage": {
                "samples": coverage,
                "mean": statistics.fmean(coverage) if len(coverage) >= 3 else None,
                "ci95": [min(coverage), max(coverage)] if len(coverage) >= 3 else None,
                "reason": None if len(coverage) >= 3 else "fewer than 3 samples",
            },
            "conflict": {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "not_applicable": len(complete) - len(conflict_rows),
                "precision": tp / (tp + fp) if tp + fp >= 3 else None,
                "recall": tp / (tp + fn) if tp + fn >= 3 else None,
                "reason": None
                if min(tp + fp, tp + fn) >= 3
                else "fewer than 3 applicable decisions",
            },
            "rollback": {
                "class_counts": {
                    value: rollback_classes.count(value)
                    for value in sorted(set(rollback_classes))
                },
                "success_rate": (
                    sum(
                        value in {"RESTORED_STRONG", "BEHAVIORAL", "FAILED_SAFE"}
                        for value in rollback_classes
                    )
                    / len(rollback_classes)
                    if len(rollback_classes) >= 3
                    else None
                ),
                "recovery_samples": [
                    row["oracle"]["outcome"]["recovery_ms"]
                    for row in complete
                    if row["oracle"]["outcome"]["recovery_ms"] is not None
                ],
            },
            "startup": {
                "samples_ms": startup_samples,
                "median_ms": statistics.median(startup_samples)
                if len(startup_samples) >= 3
                else None,
                "ci95": (
                    [min(startup_samples), max(startup_samples)]
                    if len(startup_samples) >= 3
                    else None
                ),
                "ci_method": "conservative observed range",
            },
            "evidence_bytes_samples": [
                row["oracle"]["outcome"]["evidence_bytes"] for row in complete
            ],
            "message_bytes_samples": [
                row["oracle"]["outcome"]["message_bytes"] for row in complete
            ],
            "throughput": None,
            "latency_p99_ms": None,
        },
    }
