"""Interactive controlled service for interface tests; never real vLLM evidence."""

import json
import os
import sys
from pathlib import Path

Path("sut-environment.json").write_text(json.dumps(sorted(os.environ)))
for raw in sys.stdin:
    request = json.loads(raw)
    command = request["command"]
    print(
        json.dumps(
            {
                "ack": True,
                "phase": request["phase"],
                "sequence": request["sequence"],
                "challenge": request["challenge"],
                "plan_id": request["plan_id"],
                "launch_id": request["launch_id"],
                "controller_instance": request["controller_instance"],
                "invocation_id": request["invocation_id"],
            }
        ),
        flush=True,
    )
    if command == "shutdown":
        break
