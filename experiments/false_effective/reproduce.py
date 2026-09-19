#!/usr/bin/env python3
"""Generate planned formal outputs and execute reference lifecycle self-tests."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import ARMS, aggregate, canonical  # noqa: E402
from runner import planned_records, run_reference_start  # noqa: E402


def generate(output: Path) -> dict:
    scenarios = json.loads((HERE / "scenarios.json").read_text())["scenarios"]
    protocol = json.loads((HERE / "protocol.json").read_text())
    output.mkdir(parents=True, exist_ok=True)
    formal = planned_records(scenarios)
    formal_path = output / "formal-planned.jsonl"
    formal_path.write_bytes(b"".join(canonical(row) + b"\n" for row in formal))
    formal_aggregate = aggregate(formal, output, formal=True)
    (output / "formal-aggregate.json").write_bytes(canonical(formal_aggregate) + b"\n")
    with (output / "paper-table.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            [
                "completed_formal_cells",
                "false_effective_rate",
                "coverage_mean",
                "throughput",
                "latency_p99_ms",
                "reason",
            ]
        )
        writer.writerow([0, "", "", "", "", formal_aggregate["reason"]])

    selected = [
        next(row for row in scenarios if row["id"] == name)
        for name in (
            "namespace-mismatch",
            "partial-worker-coverage",
            "rollback-failure",
        )
    ]
    reference_records = []
    for scenario in selected:
        for repetition, order in enumerate(protocol["schedule"], 1):
            for arm_order, arm in enumerate(order, 1):
                reference_records.append(
                    run_reference_start(
                        output / "reference-raw",
                        scenario,
                        arm,
                        repetition,
                        arm_order,
                    )
                )
    summary = {
        "schema": "ecpa-false-effective-selftest-summary/v1",
        "evidence_class": "reference-synthetic",
        "seed": protocol["seed"],
        "scenarios": [row["id"] for row in selected],
        "arms": list(ARMS),
        "starts": len(reference_records),
        "starts_per_arm_per_scenario": 3,
        "failed_starts": sum(row["status"] != "complete" for row in reference_records),
        "oracle_failures": sum(
            row["oracle"]["verdict"] != "PASS" for row in reference_records
        ),
        "formal_completed_cells": 0,
        "timing_summary": None,
        "timing_reason": (
            "raw real timings retained per start; nondeterministic durations "
            "excluded from checked summary"
        ),
    }
    (output / "reference-summary.json").write_bytes(canonical(summary) + b"\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output is None:
        with tempfile.TemporaryDirectory(prefix="ecpa-false-effective-") as directory:
            print(json.dumps(generate(Path(directory)), sort_keys=True))
    else:
        generate(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
