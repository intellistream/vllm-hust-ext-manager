#!/usr/bin/env python3
"""Generate planned formal outputs and execute reference lifecycle self-tests."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from harness import ARMS, aggregate, canonical, project_paper_result  # noqa: E402
from runner import (  # noqa: E402
    load_formal_manifest,
    planned_records,
    run_reference_start,
)


def _generate(output: Path, records_path: Path | None = None) -> dict:
    scenarios = json.loads((HERE / "scenarios.json").read_text())["scenarios"]
    protocol = json.loads((HERE / "protocol.json").read_text())
    output.mkdir(parents=True, exist_ok=True)
    if records_path is not None:
        formal, validation_root = load_formal_manifest(records_path)
    else:
        formal, validation_root = planned_records(scenarios), output
    formal_path = output / "formal-planned.jsonl"
    formal_path.write_bytes(b"".join(canonical(row) + b"\n" for row in formal))
    # Reload the serialized boundary so the CLI exercises raw -> validate -> aggregate.
    formal = [json.loads(line) for line in formal_path.read_text().splitlines() if line]
    formal_aggregate = aggregate(formal, validation_root, formal=True)
    paper_schema = json.loads(
        (HERE.parent.parent / "paper/artifacts/results.schema.json").read_text()
    )
    paper_results = [project_paper_result(row, paper_schema) for row in formal]
    (output / "paper-results.jsonl").write_bytes(
        b"".join(canonical(row) + b"\n" for row in paper_results)
    )
    (output / "formal-aggregate.json").write_bytes(canonical(formal_aggregate) + b"\n")
    formal_summary = {
        "schema": formal_aggregate["schema"],
        "completed_cells": formal_aggregate["completed_cells"],
        "planned_records": formal_aggregate["failure_missing_modes"]["planned"],
        "metrics": formal_aggregate["metrics"],
        "paired_contrasts": formal_aggregate["paired_contrasts"],
        "reason": formal_aggregate.get("reason"),
    }
    (output / "formal-aggregate-summary.json").write_bytes(
        canonical(formal_summary) + b"\n"
    )
    with (output / "paper-table.csv").open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            [
                "scenario",
                "arm",
                "complete_starts",
                "false_effective_rate",
                "wilson95_low",
                "wilson95_high",
                "reason",
            ]
        )
        for cell in formal_aggregate["cells"]:
            metric = cell["false_effective"]
            interval = metric["wilson95"] if metric else None
            writer.writerow(
                [
                    cell["scenario"],
                    cell["arm"],
                    cell["status_counts"]["complete"],
                    "" if metric is None else metric["rate"],
                    "" if interval is None else interval[0],
                    "" if interval is None else interval[1],
                    cell["null_reason"] or "",
                ]
            )

    selected = [
        next(row for row in scenarios if row["id"] == name)
        for name in (
            "namespace-mismatch",
            "partial-worker-coverage",
            "rollback-failure",
            "compatible-resource-pair",
            "conditional-resource-pair",
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
        "formal_completed_cells": formal_aggregate["completed_cells"],
        "timing_summary": None,
        "timing_reason": (
            "raw real timings retained per start; nondeterministic durations "
            "excluded from checked summary"
        ),
    }
    (output / "reference-summary.json").write_bytes(canonical(summary) + b"\n")
    return summary


def generate(output: Path, records_path: Path | None = None) -> dict:
    """Validate completely in staging, then atomically publish a new output tree."""
    if output.exists():
        raise FileExistsError(f"refusing to replace existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        result = _generate(staging, records_path)
        os.replace(staging, output)
        return result
    except BaseException:
        import shutil

        shutil.rmtree(staging)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--records",
        type=Path,
        help="runner-owned formal-record-index.json manifest",
    )
    args = parser.parse_args()
    if args.output is None:
        with tempfile.TemporaryDirectory(prefix="ecpa-false-effective-") as directory:
            print(
                json.dumps(
                    generate(Path(directory) / "result", args.records), sort_keys=True
                )
            )
    else:
        generate(args.output, args.records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
