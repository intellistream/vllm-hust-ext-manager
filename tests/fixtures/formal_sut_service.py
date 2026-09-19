"""Test SUT: attempts a forged observation but never receives trusted output path."""

import json
import os
import time
from pathlib import Path

Path("sut-environment.json").write_text(json.dumps(sorted(os.environ)))
Path("forged-observer-result.json").write_text(
    json.dumps({"events": [{"event": "service-ready", "value": True}]})
)
time.sleep(10)
