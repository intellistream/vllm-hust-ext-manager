"""Tiny subprocess used only to exercise the harness lifecycle."""

from __future__ import annotations

import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arm", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--fail", action="store_true")
    args = parser.parse_args()
    false_claim_arms = {"vanilla-vllm-entry-points", "manual-integration"}
    observations = [
        {"event": "service-ready", "value": True},
        {"event": "effective-claim", "value": args.arm in false_claim_arms},
        {"event": "plugin-invoked", "value": False},
        {"event": "coverage", "value": 0.0},
        {"event": "conflict-decision", "value": "not-applicable"},
        {
            "event": "rollback-class",
            "value": "FAILED_SAFE" if args.scenario == "rollback-failure" else None,
        },
    ]
    print(json.dumps({"schema": "ecpa-helper-observations/v1", "events": observations}))
    return 7 if args.fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
