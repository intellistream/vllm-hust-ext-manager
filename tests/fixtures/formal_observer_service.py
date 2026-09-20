"""Trusted test observer translating independently received process signals."""

import json
import os
import sys
from pathlib import Path


def start_ticks(stat: str) -> int:
    close = stat.rfind(")")
    return int(stat[close + 2 :].split()[19])


def process_identity(pid: int) -> dict:
    stat_path = Path(f"/proc/{pid}/stat")
    before = start_ticks(stat_path.read_text())
    argv = [
        part.decode(errors="surrogateescape")
        for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if part
    ]
    after = start_ticks(stat_path.read_text())
    assert before == after
    return {"pid": pid, "start_ticks": before, "argv": argv}


events = []
expected = os.environ["ECPA_EXPECTED_CONTRACT"]
source_role = os.environ["ECPA_OBSERVER_SOURCE_ROLE"]
target_pid = int(os.environ["ECPA_SUT_PID"])
target_identity = process_identity(target_pid)
target_argv = target_identity["argv"]
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
        "sequence": message["sequence"],
        "challenge": message["challenge"],
        "causal_ack": message["causal_ack"],
        "sut_process_identity": target_identity,
    }
    valid = message["causal_ack"]
    if valid:
        value = message["scenario"] if phase == "fault-injected" else True
        events.append({"event": phase, "value": value, **common})
    if phase == "observer-captured" and valid:
        if expected == "manager-controlled-activation":
            assert "--enable-ecpa-manager" in target_argv
        elif expected == "explicit-manual-hooks":
            assert "--manual-hooks" in target_argv
        else:
            assert "--enable-entrypoints" in target_argv
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
