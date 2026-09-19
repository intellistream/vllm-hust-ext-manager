"""Interactive controlled service for interface tests; never real vLLM evidence."""

import json
import os
import sys
from pathlib import Path

Path("sut-environment.json").write_text(json.dumps(sorted(os.environ)))
contract = (
    "manager-controlled-activation"
    if "--enable-ecpa-manager" in sys.argv
    else (
        "explicit-manual-hooks"
        if "--manual-hooks" in sys.argv
        else "entry-points-unmanaged"
    )
)
for raw in sys.stdin:
    request = json.loads(raw)
    command = request["command"]
    if command == "observe":
        Path("sut-telemetry.json").write_text(
            json.dumps(
                {
                    "activation_path": contract,
                    "effective_claim": False,
                    "plugin_invoked": False,
                }
            )
        )
    print(
        json.dumps(
            {
                "ack": True,
                "phase": request["phase"],
                "sequence": request["sequence"],
                "challenge": request["challenge"],
            }
        ),
        flush=True,
    )
    if command == "shutdown":
        break
