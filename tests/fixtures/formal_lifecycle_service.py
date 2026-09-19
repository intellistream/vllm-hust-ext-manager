"""Test-only independent result-file lifecycle producer; never formal evidence."""

import json
import os
import sys
import time
from pathlib import Path

scenario = sys.argv[1]
expected = {
    "namespace-mismatch": ["service_started", "plugin_not_invoked"],
}.get(scenario, [])
now = time.monotonic_ns()
events = [
    {"event": "service-ready", "value": True, "monotonic_ns": now},
    {"event": "workload-complete", "value": True, "monotonic_ns": now},
    {"event": "fault-injected", "value": scenario, "monotonic_ns": now},
    {"event": "effective-claim", "value": False},
    {"event": "plugin-invoked", "value": False},
    {"event": "coverage", "value": 0.0},
    {"event": "conflict-decision", "value": "not-applicable"},
    {"event": "rollback-class", "value": None},
    *({"event": event, "value": True} for event in expected),
    {"event": "observer-captured", "value": True, "monotonic_ns": time.monotonic_ns()},
    {"event": "service-shutdown", "value": True, "monotonic_ns": time.monotonic_ns()},
]
Path(os.environ["ECPA_OBSERVER_RESULT_FILE"]).write_text(json.dumps({"events": events}))
print("ordinary service log, deliberately not JSON")
