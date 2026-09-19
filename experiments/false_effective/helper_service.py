"""Tiny subprocess used only to exercise the harness lifecycle."""

from __future__ import annotations

import argparse
import json
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--fail", action="store_true")
    args = parser.parse_args()
    false_claim_arms = {"vanilla-vllm-entry-points", "manual-integration"}
    scenario_events = {
        "namespace-mismatch": ["service_started", "plugin_not_invoked"],
        "resource-conflict": ["conflict_inputs", "decision"],
        "partial-worker-coverage": ["worker_inventory", "worker_evidence"],
        "rollback-failure": ["rollback_attempt", "rollback_class"],
        "compatible-resource-pair": ["conflict_inputs", "decision"],
        "conditional-resource-pair": ["conflict_inputs", "decision"],
    }
    now = time.monotonic_ns()
    conflict_decision = {
        "resource-conflict": "reject",
        "compatible-resource-pair": "accept",
        "conditional-resource-pair": "conditional",
    }.get(args.scenario, "not-applicable")
    observations = [
        {"event": "service-ready", "value": True, "monotonic_ns": now},
        {"event": "fault-injected", "value": args.scenario, "monotonic_ns": now},
        {"event": "effective-claim", "value": args.arm in false_claim_arms},
        {"event": "plugin-invoked", "value": False},
        {"event": "coverage", "value": 0.0},
        {"event": "conflict-decision", "value": conflict_decision},
        {
            "event": "rollback-class",
            "value": "FAILED_SAFE" if args.scenario == "rollback-failure" else None,
        },
    ]
    observations.extend(
        {"event": event, "value": True}
        for event in scenario_events.get(args.scenario, [])
    )
    observations.append(
        {
            "event": "service-shutdown",
            "value": True,
            "monotonic_ns": time.monotonic_ns(),
        }
    )
    print(json.dumps({"schema": "ecpa-helper-observations/v1", "events": observations}))
    return 7 if args.fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
