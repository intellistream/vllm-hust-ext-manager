#!/usr/bin/env python3
"""Validate ECPA result artifacts without silently accepting planned values."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_results.py RESULT.json")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "artifacts/results.schema.json").read_text())
    result = json.loads(Path(sys.argv[1]).read_text())
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(result)
    print(f"valid: {result['cell_id']} ({result['status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
