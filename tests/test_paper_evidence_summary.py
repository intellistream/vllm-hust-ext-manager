from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "paper/scripts/generate_evidence_summary.py"
INPUTS = (
    "docs/corpus/plugins.json",
    "docs/corpus/plugins.schema.json",
    "docs/corpus/source-snapshots.json",
    "docs/corpus/source-snapshots.schema.json",
    "docs/research/claims-to-experiment-matrix.json",
    "docs/research/claims-to-experiment-matrix.schema.json",
    "experiments/contract_planner/cases.json",
    "experiments/contract_planner/cases.schema.json",
    "experiments/contract_planner/decision.schema.json",
    "experiments/contract_planner/oracle.json",
    "experiments/contract_planner/oracle.schema.json",
    "experiments/contract_planner/evaluate.py",
    "experiments/contract_planner/metrics.schema.json",
    "experiments/contract_planner/results/decisions.jsonl",
    "experiments/contract_planner/results/metrics.json",
    "experiments/false_effective/artifacts/formal-aggregate-summary.json",
    "experiments/false_effective/artifacts/reference-summary.json",
    "experiments/false_effective/first-formal-real-study.json",
    "experiments/false_effective/first-formal-real-study.schema.json",
    "experiments/false_effective/scenarios.json",
    "experiments/false_effective/protocol.json",
    "experiments/false_effective/verified-adapters.json",
    "spec/0.1/contract-taxonomy.json",
    "spec/0.1/contract-taxonomy.schema.json",
    "src/vllm_hust_ext/contract_compiler.py",
)


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "paper_evidence_summary", GENERATOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_inputs(destination: Path) -> None:
    for relative in INPUTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def rewrite_json(path: Path, update) -> None:
    value = json.loads(path.read_text())
    update(value)
    path.write_text(json.dumps(value, indent=2) + "\n")


def test_checked_summary_matches_all_authoritative_inputs() -> None:
    generator = load_generator()
    summary = generator.collect_summary(ROOT)

    assert summary == {
        "corpus_extensions": 11,
        "adaptation_candidates": 5,
        "planner_cases": 31,
        "planner_admits": 21,
        "planner_rejects": 10,
        "planner_reject_precision": "1.0",
        "planner_reject_recall": "1.0",
        "planner_admit_recall": "1.0",
        "source_repositories": 15,
        "source_objects": 41,
        "formal_completed": 0,
        "formal_planned": 30,
        "verified_adapters": 0,
        "reference_starts": 45,
        "formal_arms": 3,
        "minimum_starts": 3,
        "schedule_rows": 3,
        "research_claims": 4,
        "first_study_starts": 9,
    }
    assert (
        generator.render(summary)
        == (ROOT / "paper/generated/evidence-summary.tex").read_text()
    )


def test_generator_rejects_inconsistent_formal_plan_count(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    aggregate = (
        tmp_path / "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    rewrite_json(aggregate, lambda value: value.__setitem__("planned_records", 29))

    with pytest.raises(ValueError, match="scenarios times arms"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_planner_classification_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    metrics = tmp_path / "experiments/contract_planner/results/metrics.json"
    rewrite_json(
        metrics,
        lambda value: value["overall"].__setitem__("false_admit", 1),
    )

    with pytest.raises(ValueError, match="planner evidence is internally inconsistent"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_unregistered_formal_completion(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    aggregate = (
        tmp_path / "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    rewrite_json(aggregate, lambda value: value.__setitem__("completed_cells", 1))

    with pytest.raises(ValueError, match="require a verified adapter"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_planner_input_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    cases = tmp_path / "experiments/contract_planner/cases.json"
    rewrite_json(
        cases,
        lambda value: value["cases"][0].__setitem__(
            "rationale", value["cases"][0]["rationale"] + " tampered"
        ),
    )

    with pytest.raises(ValueError, match="oracle does not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_declared_corpus_count_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/plugins.json"
    rewrite_json(
        corpus,
        lambda value: value["counts"].__setitem__("registered_extensions", 999),
    )

    with pytest.raises(ValueError, match="declared counts"):
        generator.collect_summary(tmp_path)


def test_generator_applies_checked_json_schemas(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    corpus = tmp_path / "docs/corpus/plugins.json"
    rewrite_json(corpus, lambda value: value["plugins"][0].pop("id"))

    with pytest.raises(ValidationError, match="'id' is a required property"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_candidate_identity_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    cases = tmp_path / "experiments/contract_planner/cases.json"
    rewrite_json(
        cases,
        lambda value: value["excluded_candidates"].__setitem__(
            0, "intellistream/not-the-reviewed-candidate"
        ),
    )

    with pytest.raises(ValueError, match="exclusions do not exactly match"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_reference_start_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    summary = tmp_path / "experiments/false_effective/artifacts/reference-summary.json"
    rewrite_json(summary, lambda value: value.__setitem__("starts", 44))

    with pytest.raises(ValueError, match="reference summary is inconsistent"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_decision_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    decisions = tmp_path / "experiments/contract_planner/results/decisions.jsonl"
    lines = decisions.read_text().splitlines()
    lines[0] = json.dumps(json.loads(lines[0]), sort_keys=True)
    decisions.write_text("\n".join(lines) + "\n")

    with pytest.raises(ValueError, match="metrics do not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_stale_implementation_digest(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    evaluator = tmp_path / "experiments/contract_planner/evaluate.py"
    evaluator.write_text(evaluator.read_text() + "\n")

    with pytest.raises(ValueError, match="metrics do not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_source_identity_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0].__setitem__(
            "repository_id", value["sources"][0]["repository_id"] + 1
        ),
    )

    with pytest.raises(ValueError, match="oracle does not bind"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_coordinated_source_repository_drift(
    tmp_path: Path,
) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0].__setitem__(
            "requested_repository", "evil/not-corpus"
        ),
    )

    with pytest.raises(ValueError, match="exactly cover corpus repositories"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_snapshot_evidence_path_drift(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    snapshots = tmp_path / "docs/corpus/source-snapshots.json"
    rewrite_json(
        snapshots,
        lambda value: value["sources"][0]["evidence_objects"][0].__setitem__(
            "path", "not-the-corpus-evidence.txt"
        ),
    )

    with pytest.raises(ValueError, match="exactly cover corpus evidence paths"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_taxonomy_schema_violation(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    taxonomy = tmp_path / "spec/0.1/contract-taxonomy.json"
    rewrite_json(taxonomy, lambda value: value.pop("scope"))

    with pytest.raises(ValidationError, match="'scope' is a required property"):
        generator.collect_summary(tmp_path)


def test_generator_rejects_unbalanced_protocol_schedule(tmp_path: Path) -> None:
    generator = load_generator()
    copy_inputs(tmp_path)
    protocol = tmp_path / "experiments/false_effective/protocol.json"
    rewrite_json(
        protocol,
        lambda value: value["schedule"].__setitem__(1, value["schedule"][0]),
    )

    with pytest.raises(ValueError, match="square balanced arm schedule"):
        generator.collect_summary(tmp_path)
