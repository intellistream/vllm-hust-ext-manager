#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import jsonschema

from vllm_hust_ext.host_evidence import parse_host_event

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path):
    return json.loads(path.read_text())


def corpus_evidence_path(value: str) -> str:
    return re.sub(r":[0-9]+(?:-[0-9]+)?$", "", value).rstrip("/")


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
    source_snapshots_path = ROOT / corpus["source_snapshots"]
    source_snapshots_schema = load(ROOT / "docs/corpus/source-snapshots.schema.json")
    source_snapshots = load(source_snapshots_path)
    jsonschema.Draft7Validator.check_schema(source_snapshots_schema)
    jsonschema.Draft7Validator(source_snapshots_schema).validate(source_snapshots)
    snapshots_by_repository = {
        item["requested_repository"]: item for item in source_snapshots["sources"]
    }
    assert len(snapshots_by_repository) == len(source_snapshots["sources"])
    corpus_records = [*corpus["plugins"], *corpus["candidates"]]
    assert set(snapshots_by_repository) == {
        item["repository"] for item in corpus_records
    }
    expected_paths_by_repository: dict[str, set[str]] = {}
    for item in corpus_records:
        paths = {corpus_evidence_path(value) for value in item["evidence"]}
        expected_paths_by_repository.setdefault(item["repository"], set()).update(paths)
        snapshot_objects = snapshots_by_repository[item["repository"]][
            "evidence_objects"
        ]
        object_paths = [value["path"] for value in snapshot_objects]
        assert len(object_paths) == len(set(object_paths))
        assert paths <= set(object_paths)
    for repository, paths in expected_paths_by_repository.items():
        assert paths == {
            value["path"]
            for value in snapshots_by_repository[repository]["evidence_objects"]
        }
    planner = ROOT / "experiments/contract_planner"
    for schema_path, artifact_path in (
        (spec / "contract-taxonomy.schema.json", spec / "contract-taxonomy.json"),
        (planner / "cases.schema.json", planner / "cases.json"),
        (planner / "oracle.schema.json", planner / "oracle.json"),
    ):
        schema = load(schema_path)
        jsonschema.Draft7Validator.check_schema(schema)
        jsonschema.Draft7Validator(schema).validate(load(artifact_path))
    planner_cases = load(planner / "cases.json")
    planner_oracle = load(planner / "oracle.json")
    assert (
        planner_oracle["cases_sha256"]
        == hashlib.sha256((planner / "cases.json").read_bytes()).hexdigest()
    )
    assert (
        planner_oracle["taxonomy_sha256"]
        == hashlib.sha256((spec / "contract-taxonomy.json").read_bytes()).hexdigest()
    )
    assert (
        planner_oracle["source_corpus_sha256"]
        == hashlib.sha256((ROOT / "docs/corpus/plugins.json").read_bytes()).hexdigest()
    )
    assert (
        planner_oracle["source_snapshots_sha256"]
        == hashlib.sha256(source_snapshots_path.read_bytes()).hexdigest()
    )
    decisions_path = planner / "results/decisions.jsonl"
    decisions = [json.loads(line) for line in decisions_path.read_text().splitlines()]
    decision_validator = jsonschema.Draft7Validator(
        load(planner / "decision.schema.json")
    )
    for decision in decisions:
        decision_validator.validate(decision)
    planner_metrics = load(planner / "results/metrics.json")
    jsonschema.Draft7Validator(load(planner / "metrics.schema.json")).validate(
        planner_metrics
    )
    assert planner_metrics["case_count"] == len(decisions)
    assert (
        planner_metrics["decisions_sha256"]
        == hashlib.sha256(decisions_path.read_bytes()).hexdigest()
    )
    assert planner_metrics["inputs"] == {
        "cases_sha256": planner_oracle["cases_sha256"],
        "taxonomy_sha256": planner_oracle["taxonomy_sha256"],
        "source_corpus_sha256": planner_oracle["source_corpus_sha256"],
        "source_snapshots_sha256": planner_oracle["source_snapshots_sha256"],
        "oracle_sha256": hashlib.sha256(
            (planner / "oracle.json").read_bytes()
        ).hexdigest(),
    }
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
        f"{len(vectors['cases'])} attestation vectors indexed, "
        f"{len(planner_cases['cases'])} L2 cases structurally validated "
        f"with status {planner_oracle['status']}; modeled decisions indexed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
