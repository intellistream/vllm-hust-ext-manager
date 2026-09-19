"""Test-only trusted observer process."""

import json
import os
from pathlib import Path

bounds = json.loads(os.environ["ECPA_RUNNER_PHASE_BOUNDS"])
scenario = os.environ["ECPA_FROZEN_SCENARIO"]
expected = {"namespace-mismatch": ["service_started", "plugin_not_invoked"]}.get(
    scenario, []
)
events = []
for name in [
    "service-ready",
    "workload-complete",
    "fault-injected",
    "observer-captured",
    "service-shutdown",
]:
    events.append(
        {
            "event": name,
            "value": scenario if name == "fault-injected" else True,
            "source_role": "trusted-observer",
            "clock": "monotonic",
            "monotonic_ns": bounds[name][0],
        }
    )
events.extend(
    {
        "event": name,
        "value": True,
        "source_role": "trusted-observer",
        "clock": "monotonic",
        "monotonic_ns": bounds["observer-captured"][0],
    }
    for name in expected
)
for name, value in (
    ("effective-claim", False),
    ("plugin-invoked", False),
    ("coverage", 0.0),
    ("conflict-decision", "not-applicable"),
    ("rollback-class", None),
):
    events.append(
        {
            "event": name,
            "value": value,
            "source_role": "trusted-observer",
            "clock": "monotonic",
            "monotonic_ns": bounds["observer-captured"][0],
        }
    )
Path(os.environ["ECPA_OBSERVER_RESULT_FILE"]).write_text(json.dumps({"events": events}))
