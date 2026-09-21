from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_research_matrix.py"
INPUTS = (
    "docs/research/claims-to-experiment-matrix.json",
    "docs/research/claims-to-experiment-matrix.schema.json",
    "experiments/false_effective/first-formal-real-study.json",
    "experiments/false_effective/first-formal-real-study.schema.json",
    "experiments/false_effective/protocol.json",
    "experiments/false_effective/scenarios.json",
    "experiments/false_effective/verified-adapters.json",
    "experiments/false_effective/artifacts/formal-aggregate-summary.json",
    "experiments/false_effective/harness.py",
    "experiments/contract_planner/results/metrics.json",
    "paper/main.tex",
    "src/vllm_hust_ext/formal_lifecycle_source.py",
)


def load_validator():
    spec = importlib.util.spec_from_file_location("research_matrix", VALIDATOR_PATH)
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


def test_current_research_matrix_is_pre_admission() -> None:
    validator = load_validator()

    assert validator.validate(ROOT) == {
        "claims": 4,
        "experiments": 5,
        "first_study_starts": 9,
        "first_study_status": "pre-admission",
    }


def test_empty_registry_rejects_completed_study(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    rewrite_json(
        study,
        lambda value: (
            value.__setitem__("status", "complete"),
            value.__setitem__("admissible", True),
        ),
    )

    with pytest.raises(ValueError, match="claim graph or protocol|pre-admission"):
        validator.validate(tmp_path)


def test_schedule_drift_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    rewrite_json(
        study,
        lambda value: value["schedule"].__setitem__(1, value["schedule"][0]),
    )

    with pytest.raises(ValueError, match="differs from claim graph or protocol"):
        validator.validate(tmp_path)


def test_nonreciprocal_claim_link_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: value["experiments"][0]["supports"].__setitem__(
            0, "CLM-BOUNDED-COST"
        ),
    )

    with pytest.raises(ValueError, match="links must be reciprocal"):
        validator.validate(tmp_path)


def test_lifecycle_source_swap_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    rewrite_json(
        study,
        lambda value: value["phase_authorities"][0].__setitem__(
            "source_subcommand", "workload-http"
        ),
    )

    with pytest.raises(ValueError, match="five lifecycle sources"):
        validator.validate(tmp_path)


def test_unknown_scenario_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: value["experiments"][2]["scenarios"].append("not-preregistered"),
    )

    with pytest.raises(ValueError, match="unknown scenario"):
        validator.validate(tmp_path)


def test_pre_admission_rejects_partially_frozen_identity(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    rewrite_json(
        study,
        lambda value: value["fixed_identity"].__setitem__(
            "manager_commit", "238df9c620db2154c84a47cccca38f1a3fdb2ff9"
        ),
    )

    with pytest.raises(ValueError, match="must remain explicitly null"):
        validator.validate(tmp_path)


def test_hypothesis_contribution_swap_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: (
            value["claims"][0].__setitem__("paper_hypothesis", "H1"),
            value["claims"][1].__setitem__("paper_hypothesis", "H2"),
        ),
    )

    with pytest.raises(ValueError, match="hypothesis and contribution mappings"):
        validator.validate(tmp_path)


def test_runner_observable_drift_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    harness = tmp_path / "experiments/false_effective/harness.py"
    harness.write_text(harness.read_text().replace('    "coverage",\n', "", 1))

    with pytest.raises(ValueError, match="observables differ from the runner"):
        validator.validate(tmp_path)


def test_claim_evidence_class_cannot_cross_experiment_kind(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: value["claims"][1].__setitem__(
            "evidence_class", "modeled-static"
        ),
    )

    with pytest.raises(ValueError, match="evidence class differs"):
        validator.validate(tmp_path)


def test_open_producer_rejects_fake_registry_entry(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    registry = tmp_path / "experiments/false_effective/verified-adapters.json"
    rewrite_json(registry, lambda value: value["adapters"].append({"id": "fake"}))

    with pytest.raises(ValueError, match="unadmitted producer"):
        validator.validate(tmp_path)


def test_reciprocal_h3_h4_experiment_swap_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"

    def swap(value):
        h3 = value["claims"][2]
        h4 = value["claims"][3]
        recovery = value["experiments"][3]
        performance = value["experiments"][4]
        h3["experiments"], h4["experiments"] = h4["experiments"], h3["experiments"]
        recovery["supports"], performance["supports"] = (
            performance["supports"],
            recovery["supports"],
        )

    rewrite_json(matrix, swap)

    with pytest.raises(ValueError, match="hypothesis differs from experiment kind"):
        validator.validate(tmp_path)


def test_coordinated_source_kind_collapse_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    harness = tmp_path / "experiments/false_effective/harness.py"
    harness.write_text(
        harness.read_text().replace(
            '"workload-complete": "workload-driver"',
            '"workload-complete": "readiness-probe"',
            1,
        )
    )
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    rewrite_json(
        study,
        lambda value: value["phase_authorities"][1].__setitem__(
            "source_kind", "readiness-probe"
        ),
    )

    with pytest.raises(ValueError, match="runner, and source kinds differ"):
        validator.validate(tmp_path)


def test_coordinated_runner_study_source_kind_swap_is_rejected(
    tmp_path: Path,
) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    harness = tmp_path / "experiments/false_effective/harness.py"
    harness_text = harness.read_text()
    harness_text = (
        harness_text.replace(
            '"service-ready": "readiness-probe"',
            '"service-ready": "temporary-kind"',
            1,
        )
        .replace(
            '"workload-complete": "workload-driver"',
            '"workload-complete": "readiness-probe"',
            1,
        )
        .replace(
            '"service-ready": "temporary-kind"',
            '"service-ready": "workload-driver"',
            1,
        )
    )
    harness.write_text(harness_text)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"

    def swap_study_kinds(value):
        ready = value["phase_authorities"][0]
        workload = value["phase_authorities"][1]
        ready["source_kind"], workload["source_kind"] = (
            workload["source_kind"],
            ready["source_kind"],
        )

    rewrite_json(study, swap_study_kinds)

    with pytest.raises(ValueError, match="runner, and source kinds differ"):
        validator.validate(tmp_path)


def test_phase_authority_swap_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study = tmp_path / "experiments/false_effective/first-formal-real-study.json"

    def swap_authorities(value):
        ready = value["phase_authorities"][0]
        shutdown = value["phase_authorities"][4]
        ready["authority"], shutdown["authority"] = (
            shutdown["authority"],
            ready["authority"],
        )

    rewrite_json(study, swap_authorities)

    with pytest.raises(ValueError, match="authority differs from its source kind"):
        validator.validate(tmp_path)


def test_source_cli_subcommand_drift_is_rejected(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    source = tmp_path / "src/vllm_hust_ext/formal_lifecycle_source.py"
    source.write_text(
        source.read_text().replace(
            'add_parser("readiness-http")', 'add_parser("changed-http")', 1
        )
    )

    with pytest.raises(ValueError, match="subcommands differ from the source CLI"):
        validator.validate(tmp_path)
