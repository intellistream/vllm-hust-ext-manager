#!/usr/bin/env python3
"""Validate the paper claim graph and first formal-real preregistration."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]

CLAIMS_PATH = "docs/research/claims-to-experiment-matrix.json"
CLAIMS_SCHEMA_PATH = "docs/research/claims-to-experiment-matrix.schema.json"
STUDY_PATH = "experiments/false_effective/first-formal-real-study.json"
STUDY_SCHEMA_PATH = "experiments/false_effective/first-formal-real-study.schema.json"

PHASE_COMMANDS = {
    "service-ready": "readiness-http",
    "workload-complete": "workload-http",
    "fault-injected": "partial-coverage-quarantine",
    "observer-captured": "journal-capture",
    "service-shutdown": "shutdown-process",
}
HYPOTHESIS_CONTRIBUTIONS = {
    "H1": "host-evidence",
    "H2": "contract-model",
    "H3": "transactional-runtime",
    "H4": "bounded-cost",
}


def load(root: Path, relative: str) -> dict[str, Any]:
    value = json.loads((root / relative).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain one JSON object")
    return value


def validate_schema(root: Path, value: dict[str, Any], relative: str) -> None:
    schema = load(root, relative)
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(value)


def require_unique(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed = {row["id"]: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError(f"{label} ids must be unique")
    return indexed


def python_literal(root: Path, relative: str, name: str) -> Any:
    module = ast.parse((root / relative).read_text(), filename=relative)
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"{relative} does not define literal {name}")


def validate(root: Path = ROOT) -> dict[str, int | str]:
    claims_matrix = load(root, CLAIMS_PATH)
    study = load(root, STUDY_PATH)
    protocol = load(root, "experiments/false_effective/protocol.json")
    scenarios = load(root, "experiments/false_effective/scenarios.json")
    registry = load(root, "experiments/false_effective/verified-adapters.json")
    aggregate = load(
        root, "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    metrics = load(root, "experiments/contract_planner/results/metrics.json")
    paper = (root / "paper/main.tex").read_text()

    validate_schema(root, claims_matrix, CLAIMS_SCHEMA_PATH)
    validate_schema(root, study, STUDY_SCHEMA_PATH)

    claims = require_unique(claims_matrix["claims"], "claim")
    experiments = require_unique(claims_matrix["experiments"], "experiment")
    if {claim["paper_hypothesis"] for claim in claims.values()} != {
        "H1",
        "H2",
        "H3",
        "H4",
    }:
        raise ValueError("claim graph must cover paper hypotheses H1 through H4")
    if any(
        claim["contribution"] != HYPOTHESIS_CONTRIBUTIONS[claim["paper_hypothesis"]]
        for claim in claims.values()
    ):
        raise ValueError("paper hypothesis and contribution mappings differ")
    for hypothesis in ("H1", "H2", "H3", "H4"):
        if f"\\textbf{{{hypothesis}:}}" not in paper:
            raise ValueError(f"paper no longer contains {hypothesis}")

    for claim_id, claim in claims.items():
        for experiment_id in claim["experiments"]:
            experiment = experiments.get(experiment_id)
            if experiment is None or claim_id not in experiment["supports"]:
                raise ValueError("claim and experiment links must be reciprocal")
            if (
                claim["evidence_class"] == "modeled-static"
                and experiment["kind"] != "modeled-static"
            ) or (
                claim["evidence_class"] == "formal-real"
                and not experiment["kind"].startswith("formal-")
            ):
                raise ValueError("claim evidence class differs from experiment kind")
    for experiment_id, experiment in experiments.items():
        for claim_id in experiment["supports"]:
            claim = claims.get(claim_id)
            if claim is None or experiment_id not in claim["experiments"]:
                raise ValueError("experiment and claim links must be reciprocal")

    scenario_ids = [row["id"] for row in scenarios["scenarios"]]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("scenario ids must be unique")
    formal_arms = protocol["arms"]
    for experiment in experiments.values():
        if not set(experiment["scenarios"]) <= set(scenario_ids):
            raise ValueError("experiment references an unknown scenario")
        if experiment["kind"] != "modeled-static" and (
            experiment["arms"] != formal_arms
            or experiment["repetitions"] != protocol["minimum_starts"]
        ):
            raise ValueError("formal experiment differs from frozen protocol")

    first_experiment = experiments[study["experiment_id"]]
    if (
        first_experiment["scenarios"] != [study["scenario"]]
        or first_experiment["arms"] != study["arms"]
        or first_experiment["repetitions"] != study["repetitions"]
        or first_experiment["status"] != study["status"]
        or study["arms"] != formal_arms
        or study["repetitions"] != protocol["minimum_starts"]
        or study["schedule"] != protocol["schedule"]
        or study["planned_starts"] != len(study["arms"]) * study["repetitions"]
        or study["acceptance"]["complete_starts_per_arm"] != study["repetitions"]
    ):
        raise ValueError("first formal study differs from claim graph or protocol")

    phase_commands = {
        row["phase"]: row["source_subcommand"] for row in study["phase_authorities"]
    }
    if len(phase_commands) != len(study["phase_authorities"]):
        raise ValueError("first formal study phase authorities must be unique")
    if phase_commands != PHASE_COMMANDS:
        raise ValueError("first formal study does not bind the five lifecycle sources")
    runner_observables = python_literal(
        root, "experiments/false_effective/harness.py", "FORMAL_HOST_OBSERVABLES"
    )
    if set(study["required_host_observables"]) != runner_observables:
        raise ValueError("first formal study host observables differ from the runner")

    static_claim = claims["CLM-CONTRACT-COMPOSITION"]
    if (
        static_claim["status"] != "modeled-evaluated"
        or static_claim["evidence_class"] != "modeled-static"
        or metrics.get("classification") != "modeled-static-contract-corpus"
        or metrics.get("all_decisions_match") is not True
        or metrics.get("all_errors_match") is not True
    ):
        raise ValueError("modeled contract claim lacks matching planner evidence")
    if any(
        claim["evidence_class"] == "formal-real"
        and claim["status"] == "modeled-evaluated"
        for claim in claims.values()
    ):
        raise ValueError("formal-real claims cannot use modeled-evaluated status")

    adapters = registry.get("adapters")
    if registry.get("schema") != "ecpa-formal-adapter-registry/v2" or not isinstance(
        adapters, list
    ):
        raise ValueError("verified adapter registry must contain an adapters array")
    pre_admission_blockers = {
        "producer-not-merged",
        "human-line-review-absent",
        "adapter-registry-empty",
        "deployment-identity-unfrozen",
        "commands-not-deployment-reviewed",
    }
    producer = study["producer_candidate"]
    producer_unadmitted = (
        producer["observed_state"] != "merged"
        or producer["merge_commit"] is None
        or producer["human_line_review"] is not True
    )
    if producer_unadmitted and adapters:
        raise ValueError("unadmitted producer cannot have verified adapter entries")
    if (producer_unadmitted or not adapters) and (
        study["status"] != "pre-admission"
        or study["admissible"] is not False
        or set(study["blockers"]) != pre_admission_blockers
        or aggregate["completed_cells"] != 0
    ):
        raise ValueError("unadmitted study must remain exactly pre-admission")

    if study["status"] == "pre-admission" and any(
        value is not None for value in study["fixed_identity"].values()
    ):
        raise ValueError(
            "pre-admission deployment identity must remain explicitly null"
        )

    return {
        "claims": len(claims),
        "experiments": len(experiments),
        "first_study_starts": study["planned_starts"],
        "first_study_status": study["status"],
    }


def main() -> int:
    summary = validate()
    print(
        "research matrix valid: "
        f"{summary['claims']} claims, {summary['experiments']} experiments, "
        f"first study {summary['first_study_status']} "
        f"({summary['first_study_starts']} planned starts)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
