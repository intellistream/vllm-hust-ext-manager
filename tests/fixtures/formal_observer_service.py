"""Trusted test observer translating independently received process signals."""

import json
import os
import sys
from pathlib import Path

events = []
expected = os.environ["ECPA_EXPECTED_CONTRACT"]
source_role = os.environ["ECPA_OBSERVER_SOURCE_ROLE"]
target_pid = int(os.environ["ECPA_SUT_PID"])
target_argv = Path(f"/proc/{target_pid}/cmdline").read_bytes().split(b"\0")
for raw in sys.stdin:
    message = json.loads(raw)
    phase = message["phase"]
    common = {
        "source_role": source_role,
        "clock": "monotonic",
        "monotonic_ns": message["monotonic_ns"],
        "plan_id": message["plan_id"],
        "launch_id": message["launch_id"],
        "controller_instance": message["controller_instance"],
        "invocation_id": message["invocation_id"],
    }
    valid = message["causal_ack"]
    if valid:
        value = message["scenario"] if phase == "fault-injected" else True
        events.append({"event": phase, "value": value, **common})
    if phase == "observer-captured" and valid:
        if expected == "manager-controlled-activation":
            assert b"--enable-ecpa-manager" in target_argv
        elif expected == "explicit-manual-hooks":
            assert b"--manual-hooks" in target_argv
        else:
            assert b"--enable-entrypoints" in target_argv
        values = (
            ("activation-path", expected),
            ("effective-claim", False),
            ("plugin-invoked", False),
            ("coverage", 1.0),
            ("conflict-decision", "not-applicable"),
            ("rollback-class", None),
            ("service_started", True),
            ("plugin_not_invoked", True),
        )
        events.extend(
            {"event": name, "value": value, **common} for name, value in values
        )
os.write(int(os.environ["ECPA_OBSERVER_FD"]), json.dumps({"events": events}).encode())
assert any(
    item["event"] == "activation-path" and item["value"] == expected for item in events
)
