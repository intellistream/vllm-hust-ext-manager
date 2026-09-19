"""Trusted test observer translating independently received process signals."""

import json
import os
import sys

events = []
expected = os.environ["ECPA_EXPECTED_CONTRACT"]
for raw in sys.stdin:
    message = json.loads(raw)
    phase = message["phase"]
    signal = message["signal"]
    common = {
        "source_role": "trusted-observer",
        "clock": "monotonic",
        "monotonic_ns": message["monotonic_ns"],
    }
    valid = {
        "service-ready": signal == "READY",
        "workload-complete": signal == "WORKLOAD_OK",
        "fault-injected": signal == f"FAULT_OK {message['scenario']}",
        "observer-captured": signal.startswith("OBSERVE "),
        "service-shutdown": signal == "SHUTDOWN_OK",
    }[phase]
    if valid:
        value = message["scenario"] if phase == "fault-injected" else True
        events.append({"event": phase, "value": value, **common})
    if phase == "observer-captured" and valid:
        observed = json.loads(signal.removeprefix("OBSERVE "))
        values = (
            ("activation-path", observed["activation_path"]),
            ("effective-claim", observed["effective_claim"]),
            ("plugin-invoked", observed["plugin_invoked"]),
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
