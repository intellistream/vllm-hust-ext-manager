#!/usr/bin/env python3
"""Evaluate the frozen L2 corpus without deriving its oracle labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import vllm_hust_ext.contract_compiler as compiler_module
from vllm_hust_ext.contract_compiler import (
    AuthorityContract,
    Capability,
    ContractPlanningError,
    ContractResource,
    ExtensionContract,
    RollbackContract,
    compile_contracts,
    parse_contract_taxonomy,
)
from vllm_hust_ext.ecpa_model import canonical_bytes

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES = ROOT / "experiments/contract_planner/cases.json"
DEFAULT_ORACLE = ROOT / "experiments/contract_planner/oracle.json"
DEFAULT_TAXONOMY = ROOT / "spec/0.1/contract-taxonomy.json"
DEFAULT_CORPUS = ROOT / "docs/corpus/plugins.json"
DEFAULT_OUTPUT = ROOT / "experiments/contract_planner/results"
REVIEWED_ORACLE_SHA256 = (
    "06de27ae23c99db674d0d145d86ec1aff846c4b00c46b86227e412b4ac2ad99e"
)
REVIEWED_ORACLE_CONTENT_COMMIT = "4a87f99d47b7e0bf87a58417ba1bfb372344c22a"
REVIEWED_ORACLE_ARTIFACT_COMMIT = "ed248e12df24695bb0ddf2bb90acebf529e937f8"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _static_contract(
    descriptor: dict[str, Any], host: dict[str, str]
) -> ExtensionContract:
    """Build an L2-only object without inventing L3 evidence obligations."""
    host_major = int(host["version"].split(".")[0])
    return ExtensionContract(
        extension_id=descriptor["id"],
        version="1.0",
        manifest_sha256=hashlib.sha256(canonical_bytes(descriptor)).hexdigest(),
        host_runtime=host["runtime"],
        host_version_range=f">={host['version']},<{host_major + 1}",
        provides=tuple(
            Capability(item["name"], item["version"]) for item in descriptor["provides"]
        ),
        requires=tuple(
            Capability(item["name"], item["version"]) for item in descriptor["requires"]
        ),
        resources=tuple(
            ContractResource(item["name"], item["mode"], item.get("mediator"))
            for item in descriptor["resources"]
        ),
        process_obligations=(),
        rollback=RollbackContract((), ()),
        authority=AuthorityContract((), (), ()),
    )


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": round(numerator / denominator, 6) if denominator else None,
    }


def _confusion(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(
        record["expected_decision"] == record["observed_decision"] == "reject"
        for record in records
    )
    tn = sum(
        record["expected_decision"] == record["observed_decision"] == "admit"
        for record in records
    )
    fp = sum(
        record["expected_decision"] == "admit"
        and record["observed_decision"] == "reject"
        for record in records
    )
    fn = sum(
        record["expected_decision"] == "reject"
        and record["observed_decision"] == "admit"
        for record in records
    )
    return {
        "true_reject": tp,
        "true_admit": tn,
        "false_reject": fp,
        "false_admit": fn,
        "reject_precision": _ratio(tp, tp + fp),
        "reject_recall": _ratio(tp, tp + fn),
        "admit_recall": _ratio(tn, tn + fp),
        "accuracy": _ratio(tp + tn, len(records)),
    }


def decision_bytes(records: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_bytes(record) + b"\n" for record in records)


def evaluate(
    cases_path: Path,
    oracle_path: Path,
    taxonomy_path: Path,
    corpus_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases = _load(cases_path)
    oracle = _load(oracle_path)
    taxonomy = parse_contract_taxonomy(_load(taxonomy_path))
    if _digest(oracle_path) != REVIEWED_ORACLE_SHA256:
        raise ValueError(
            "oracle bytes do not match the independently reviewed artifact"
        )
    if oracle["status"] != "independently-reviewed":
        raise ValueError("oracle must be independently reviewed before evaluation")
    if oracle["review"]["verdict"] != "MERGE":
        raise ValueError("oracle review must have a MERGE verdict")
    if oracle["review"]["reviewed_commit"] != REVIEWED_ORACLE_CONTENT_COMMIT:
        raise ValueError("oracle receipt does not name the reviewed content commit")
    input_digests = {
        "cases_sha256": _digest(cases_path),
        "taxonomy_sha256": _digest(taxonomy_path),
        "source_corpus_sha256": _digest(corpus_path),
    }
    for field, digest in input_digests.items():
        if oracle[field] != digest or oracle["review"][field] != digest:
            raise ValueError(f"oracle {field} does not bind the evaluated input")
    result_inputs = {**input_digests, "oracle_sha256": REVIEWED_ORACLE_SHA256}

    descriptors = {item["id"]: item for item in cases["contracts"]}
    labels = {item["case_id"]: item for item in oracle["labels"]}
    case_ids = [item["id"] for item in cases["cases"]]
    if len(descriptors) != len(cases["contracts"]):
        raise ValueError("contract ids must be unique")
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("case ids must be unique")
    if len(labels) != len(oracle["labels"]):
        raise ValueError("oracle label ids must be unique")
    if set(case_ids) != set(labels):
        raise ValueError("oracle labels must exactly cover cases")
    known_capabilities = set(taxonomy.capabilities)
    for descriptor in descriptors.values():
        for capability in [*descriptor["provides"], *descriptor["requires"]]:
            if capability["name"] not in known_capabilities:
                raise ValueError(
                    f"{descriptor['id']} uses capability absent from reviewed taxonomy"
                )
    records: list[dict[str, Any]] = []
    for case in cases["cases"]:
        contracts = tuple(
            _static_contract(descriptors[item], cases["host"])
            for item in case["members"]
        )
        observed_decision = "admit"
        observed_error = None
        plan_id = None
        try:
            plan = compile_contracts(
                contracts,
                host_runtime=cases["host"]["runtime"],
                host_version=cases["host"]["version"],
                resource_taxonomy=taxonomy,
            )
            plan_id = plan.plan_id
        except ContractPlanningError as error:
            observed_decision = "reject"
            observed_error = error.code.value
        expected = labels[case["id"]]
        records.append(
            {
                "case_id": case["id"],
                "dimension": case["dimension"],
                "members": case["members"],
                "expected_decision": expected["decision"],
                "expected_error": expected["expected_error"],
                "observed_decision": observed_decision,
                "observed_error": observed_error,
                "decision_match": observed_decision == expected["decision"],
                "error_match": observed_error == expected["expected_error"],
                "plan_id": plan_id,
            }
        )

    by_dimension: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_dimension[record["dimension"]].append(record)
    serialized_decisions = decision_bytes(records)
    rejects = [record for record in records if record["expected_decision"] == "reject"]
    metrics = {
        "schema": "ecpa-contract-planner-results/0.1",
        "classification": "modeled-static-contract-corpus",
        "generator": "ecpa-l2-evaluator/0.1",
        "implementation": {
            "evaluator_sha256": _digest(Path(__file__)),
            "contract_compiler_sha256": _digest(Path(compiler_module.__file__)),
        },
        "inputs": result_inputs,
        "oracle": {
            "sha256": REVIEWED_ORACLE_SHA256,
            "content_review_commit": REVIEWED_ORACLE_CONTENT_COMMIT,
            "artifact_review_commit": REVIEWED_ORACLE_ARTIFACT_COMMIT,
        },
        "decisions_sha256": hashlib.sha256(serialized_decisions).hexdigest(),
        "case_count": len(records),
        "overall": _confusion(records),
        "by_dimension": {
            dimension: _confusion(items)
            for dimension, items in sorted(by_dimension.items())
        },
        "degenerate_baselines": {
            "admit-all": _confusion(
                [{**record, "observed_decision": "admit"} for record in records]
            ),
            "reject-all": _confusion(
                [{**record, "observed_decision": "reject"} for record in records]
            ),
        },
        "reject_error_code_accuracy": _ratio(
            sum(record["error_match"] for record in rejects), len(rejects)
        ),
        "all_decisions_match": all(record["decision_match"] for record in records),
        "all_errors_match": all(record["error_match"] for record in records),
    }
    return records, metrics


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--taxonomy", type=Path, default=DEFAULT_TAXONOMY)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    records, metrics = evaluate(args.cases, args.oracle, args.taxonomy, args.corpus)
    serialized_decisions = decision_bytes(records)
    _atomic_write(args.output_dir / "decisions.jsonl", serialized_decisions)
    _atomic_write(args.output_dir / "metrics.json", canonical_bytes(metrics) + b"\n")
    print(
        f"evaluated {metrics['case_count']} modeled cases: "
        f"precision={metrics['overall']['reject_precision']['value']}, "
        f"recall={metrics['overall']['reject_recall']['value']}, "
        f"admit_recall={metrics['overall']['admit_recall']['value']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
