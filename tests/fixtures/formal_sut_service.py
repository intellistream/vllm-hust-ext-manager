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
print("READY", flush=True)
for command in sys.stdin:
    command = command.strip()
    if command == "workload":
        print("WORKLOAD_OK", flush=True)
    elif command.startswith("fault "):
        print(f"FAULT_OK {command[6:]}", flush=True)
    elif command == "observe":
        print(
            "OBSERVE "
            + json.dumps(
                {
                    "activation_path": contract,
                    "effective_claim": False,
                    "plugin_invoked": False,
                }
            ),
            flush=True,
        )
    elif command == "shutdown":
        print("SHUTDOWN_OK", flush=True)
        break
