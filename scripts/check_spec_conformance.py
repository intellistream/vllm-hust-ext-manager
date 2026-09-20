#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
from pathlib import Path

import jsonschema

from vllm_hust_ext.host_evidence import parse_host_event

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
    jsonschema.Draft7Validator.check_schema(load(spec / "execution-plan.schema.json"))
    host_validator = jsonschema.Draft7Validator(
        load(spec / "host-plugin-evidence.schema.json")
    )
    for name in ("host-plugin-invoked.json", "host-preemption-dispatch.json"):
        path = spec / "examples" / name
        host_validator.validate(load(path))
        parse_host_event(path.read_bytes())
    attestation_schema = load(spec / "attestation.schema.json")
    vectors = load(spec / "attestation-vectors.json")
    for case in vectors["cases"]:
        if case["expected"] == "OK":
            payload = base64.urlsafe_b64decode(
                case["payload_b64"] + "=" * (-len(case["payload_b64"]) % 4)
            )
            jsonschema.Draft7Validator(attestation_schema).validate(json.loads(payload))
    assert corpus["counts"]["registered_extensions"] == len(corpus["plugins"])
    assert corpus["counts"]["adaptation_candidates"] == len(corpus["candidates"])
    print(
        "ECPA 0.1 draft: manifest and protocol examples valid, "
        f"2 invalid examples rejected, 2 host events valid, corpus valid, "
        f"{len(vectors['cases'])} attestation vectors indexed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
