from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

import experiments.contract_planner.evaluate as evaluator_module
import vllm_hust_ext.contract_compiler as compiler_module
from experiments.contract_planner.evaluate import (
    DEFAULT_CASES,
    DEFAULT_CORPUS,
    DEFAULT_ORACLE,
    DEFAULT_SOURCE_SNAPSHOTS,
    DEFAULT_TAXONOMY,
    REVIEWED_ORACLE_ARTIFACT_COMMIT,
    REVIEWED_ORACLE_CONTENT_COMMIT,
    REVIEWED_ORACLE_SHA256,
    _static_contract,
    decision_bytes,
    evaluate,
)
from vllm_hust_ext.ecpa_model import canonical_bytes

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/contract_planner"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_evaluator_matches_independent_oracle_and_preserves_raw_decisions() -> None:
    records, metrics = evaluate(
        DEFAULT_CASES, DEFAULT_ORACLE, DEFAULT_TAXONOMY, DEFAULT_CORPUS
    )

    assert len(records) == metrics["case_count"] == 31
    assert metrics["all_decisions_match"]
    assert metrics["all_errors_match"]
    assert metrics["implementation"] == {
        "evaluator_sha256": hashlib.sha256(
            Path(evaluator_module.__file__).read_bytes()
        ).hexdigest(),
        "contract_compiler_sha256": hashlib.sha256(
            Path(compiler_module.__file__).read_bytes()
        ).hexdigest(),
    }
    assert metrics["inputs"]["oracle_sha256"] == REVIEWED_ORACLE_SHA256
    assert (
        metrics["inputs"]["source_snapshots_sha256"]
        == hashlib.sha256(DEFAULT_SOURCE_SNAPSHOTS.read_bytes()).hexdigest()
    )
    assert metrics["oracle"] == {
        "sha256": REVIEWED_ORACLE_SHA256,
        "content_review_commit": REVIEWED_ORACLE_CONTENT_COMMIT,
        "artifact_review_commit": REVIEWED_ORACLE_ARTIFACT_COMMIT,
    }
    assert metrics["overall"] == {
        "true_reject": 10,
        "true_admit": 21,
        "false_reject": 0,
        "false_admit": 0,
        "reject_precision": {"numerator": 10, "denominator": 10, "value": 1.0},
        "reject_recall": {"numerator": 10, "denominator": 10, "value": 1.0},
        "admit_recall": {"numerator": 21, "denominator": 21, "value": 1.0},
        "accuracy": {"numerator": 31, "denominator": 31, "value": 1.0},
    }
    assert metrics["degenerate_baselines"]["reject-all"]["reject_precision"] == {
        "numerator": 10,
        "denominator": 31,
        "value": 0.322581,
    }
    assert metrics["degenerate_baselines"]["reject-all"]["admit_recall"] == {
        "numerator": 0,
        "denominator": 21,
        "value": 0.0,
    }

    raw = decision_bytes(records)
    assert metrics["decisions_sha256"] == hashlib.sha256(raw).hexdigest()
    decision_validator = jsonschema.Draft7Validator(
        _load(EXPERIMENT / "decision.schema.json")
    )
    for record in records:
        decision_validator.validate(record)
    jsonschema.Draft7Validator(_load(EXPERIMENT / "metrics.schema.json")).validate(
        metrics
    )


def test_checked_in_results_are_exactly_reproducible() -> None:
    records, metrics = evaluate(
        DEFAULT_CASES, DEFAULT_ORACLE, DEFAULT_TAXONOMY, DEFAULT_CORPUS
    )
    assert (EXPERIMENT / "results/decisions.jsonl").read_bytes() == decision_bytes(
        records
    )
    assert (EXPERIMENT / "results/metrics.json").read_bytes() == (
        canonical_bytes(metrics) + b"\n"
    )


def test_evaluator_rejects_oracle_with_unbound_input(tmp_path: Path) -> None:
    oracle = _load(DEFAULT_ORACLE)
    oracle["taxonomy_sha256"] = "0" * 64
    tampered = tmp_path / "oracle.json"
    tampered.write_text(json.dumps(oracle))

    with pytest.raises(ValueError, match="reviewed artifact"):
        evaluate(DEFAULT_CASES, tampered, DEFAULT_TAXONOMY, DEFAULT_CORPUS)


def test_evaluator_rejects_unbound_source_snapshot(tmp_path: Path) -> None:
    snapshots = _load(DEFAULT_SOURCE_SNAPSHOTS)
    snapshots["sources"][0]["commit_sha"] = "0" * 40
    tampered = tmp_path / "source-snapshots.json"
    tampered.write_text(json.dumps(snapshots))

    with pytest.raises(
        ValueError,
        match="oracle source_snapshots_sha256 does not bind the evaluated input",
    ):
        evaluate(
            DEFAULT_CASES,
            DEFAULT_ORACLE,
            DEFAULT_TAXONOMY,
            DEFAULT_CORPUS,
            tampered,
        )


def test_evaluator_does_not_invent_capabilities_for_resource_only_controls() -> None:
    cases = _load(DEFAULT_CASES)
    descriptor = next(
        item for item in cases["contracts"] if item["id"] == "control.lifecycle-reader"
    )
    contract = _static_contract(descriptor, cases["host"])

    assert contract.provides == ()
    assert contract.requires == ()
    assert contract.process_obligations == ()
    assert all(
        not capability.name.endswith(".lifecycle")
        for capability in [*contract.provides, *contract.requires]
    )
