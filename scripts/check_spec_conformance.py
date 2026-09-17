#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path):
    return json.loads(path.read_text())


def main() -> int:
    spec = ROOT / "spec/0.1"
    validator = jsonschema.Draft7Validator(load(spec / "manifest.schema.json"))
    validator.validate(load(spec / "examples/minimal-valid.json"))
    for name in ("invalid-namespace.json", "invalid-missing-process-evidence.json"):
        errors = list(validator.iter_errors(load(spec / "examples" / name)))
        if not errors:
            raise SystemExit(f"expected invalid fixture to fail: {name}")
    corpus_schema = load(ROOT / "docs/corpus/plugins.schema.json")
    corpus = load(ROOT / "docs/corpus/plugins.json")
    jsonschema.Draft7Validator(corpus_schema).validate(corpus)
    jsonschema.Draft7Validator(load(spec / "protocol.schema.json")).validate(
        load(spec / "protocol-instance.json")
    )
    assert corpus["counts"]["registered_extensions"] == len(corpus["plugins"])
    assert corpus["counts"]["adaptation_candidates"] == len(corpus["candidates"])
    print(
        "ECPA 0.1 draft: manifest and protocol examples valid, "
        "2 invalid examples rejected, corpus valid"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
