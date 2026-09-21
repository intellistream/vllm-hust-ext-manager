#!/usr/bin/env python3
"""Generate fail-closed LaTeX evidence macros from checked artifacts."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "paper/generated/evidence-summary.tex"


def load_json(root: Path, relative: str) -> dict[str, Any]:
    value = json.loads((root / relative).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain one JSON object")
    return value


def require_schema(value: dict[str, Any], expected: str, source: str) -> None:
    if value.get("schema") != expected:
        raise ValueError(f"{source} has an unsupported schema")


def require_count(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def digest(root: Path, relative: str) -> str:
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()


def validate_schema(root: Path, artifact: dict[str, Any], relative: str) -> None:
    schema = load_json(root, relative)
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(artifact)


def load_jsonl(root: Path, relative: str) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate((root / relative).read_text().splitlines(), 1):
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{relative}:{line_number} must be one JSON object")
        records.append(value)
    return records


def corpus_evidence_path(value: str) -> str:
    return re.sub(r":[0-9]+(?:-[0-9]+)?$", "", value).rstrip("/")


def collect_summary(root: Path = ROOT) -> dict[str, int | str]:
    plugins = load_json(root, "docs/corpus/plugins.json")
    snapshots = load_json(root, "docs/corpus/source-snapshots.json")
    cases = load_json(root, "experiments/contract_planner/cases.json")
    taxonomy = load_json(root, "spec/0.1/contract-taxonomy.json")
    oracle = load_json(root, "experiments/contract_planner/oracle.json")
    metrics = load_json(root, "experiments/contract_planner/results/metrics.json")
    decisions = load_jsonl(root, "experiments/contract_planner/results/decisions.jsonl")
    aggregate = load_json(
        root, "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    scenarios = load_json(root, "experiments/false_effective/scenarios.json")
    protocol = load_json(root, "experiments/false_effective/protocol.json")
    registry = load_json(root, "experiments/false_effective/verified-adapters.json")
    reference = load_json(
        root, "experiments/false_effective/artifacts/reference-summary.json"
    )
    claims_matrix = load_json(root, "docs/research/claims-to-experiment-matrix.json")
    first_study = load_json(
        root, "experiments/false_effective/first-formal-real-study.json"
    )
    deployment = load_json(
        root, "experiments/false_effective/first-formal-real-deployment.json"
    )

    for artifact, schema in (
        (plugins, "docs/corpus/plugins.schema.json"),
        (snapshots, "docs/corpus/source-snapshots.schema.json"),
        (cases, "experiments/contract_planner/cases.schema.json"),
        (taxonomy, "spec/0.1/contract-taxonomy.schema.json"),
        (oracle, "experiments/contract_planner/oracle.schema.json"),
        (metrics, "experiments/contract_planner/metrics.schema.json"),
        (
            claims_matrix,
            "docs/research/claims-to-experiment-matrix.schema.json",
        ),
        (
            first_study,
            "experiments/false_effective/first-formal-real-study.schema.json",
        ),
        (
            deployment,
            "experiments/false_effective/first-formal-real-deployment.schema.json",
        ),
    ):
        validate_schema(root, artifact, schema)
    decision_schema = load_json(
        root, "experiments/contract_planner/decision.schema.json"
    )
    jsonschema.Draft7Validator.check_schema(decision_schema)
    decision_validator = jsonschema.Draft7Validator(decision_schema)
    for decision in decisions:
        decision_validator.validate(decision)

    require_schema(plugins, "ecpa-plugin-corpus/v1", "plugin corpus")
    require_schema(
        snapshots, "ecpa-corpus-source-snapshots/0.1", "source snapshot corpus"
    )
    require_schema(cases, "ecpa-contract-planner-cases/0.1", "planner cases")
    require_schema(taxonomy, "ecpa-contract-taxonomy/0.1-draft", "taxonomy")
    require_schema(oracle, "ecpa-contract-planner-oracle/0.1", "planner oracle")
    require_schema(metrics, "ecpa-contract-planner-results/0.1", "planner metrics")
    require_schema(aggregate, "ecpa-false-effective-aggregate/v1", "formal aggregate")
    require_schema(scenarios, "ecpa-false-effective-scenarios/v1", "scenarios")
    require_schema(protocol, "ecpa-false-effective-protocol/v1", "protocol")
    require_schema(registry, "ecpa-formal-adapter-registry/v2", "adapter registry")
    require_schema(
        reference, "ecpa-false-effective-selftest-summary/v1", "reference summary"
    )
    require_schema(
        claims_matrix, "ecpa-claims-to-experiments/v1", "research claim graph"
    )
    require_schema(first_study, "ecpa-first-formal-real-study/v1", "first formal study")
    require_schema(
        deployment,
        "ecpa-formal-real-deployment-registration/v1",
        "first formal deployment registration",
    )

    plugin_rows = plugins.get("plugins")
    source_rows = snapshots.get("sources")
    case_rows = cases.get("cases")
    excluded_rows = cases.get("excluded_candidates")
    scenario_rows = scenarios.get("scenarios")
    arms = protocol.get("arms")
    adapters = registry.get("adapters")
    claim_rows = claims_matrix.get("claims")
    if not all(
        isinstance(rows, list)
        for rows in (
            plugin_rows,
            source_rows,
            case_rows,
            excluded_rows,
            scenario_rows,
            arms,
            adapters,
            claim_rows,
        )
    ):
        raise ValueError("paper evidence inputs must contain arrays")

    counts = plugins.get("counts")
    if not isinstance(counts, dict) or counts != {
        "registered_extensions": len(plugin_rows),
        "adaptation_candidates": len(plugins["candidates"]),
    }:
        raise ValueError("plugin corpus declared counts differ from its rows")
    candidate_repositories = [row["repository"] for row in plugins["candidates"]]
    if (
        len(candidate_repositories) != len(set(candidate_repositories))
        or candidate_repositories != excluded_rows
    ):
        raise ValueError("planner exclusions do not exactly match corpus candidates")

    corpus_records = [*plugin_rows, *plugins["candidates"]]
    snapshot_repositories = [row["requested_repository"] for row in source_rows]
    expected_repositories = {row["repository"] for row in corpus_records}
    if (
        len(snapshot_repositories) != len(set(snapshot_repositories))
        or set(snapshot_repositories) != expected_repositories
    ):
        raise ValueError("source snapshots do not exactly cover corpus repositories")
    snapshots_by_repository = {row["requested_repository"]: row for row in source_rows}
    expected_paths_by_repository: dict[str, set[str]] = {}
    for row in corpus_records:
        expected_paths_by_repository.setdefault(row["repository"], set()).update(
            corpus_evidence_path(path) for path in row["evidence"]
        )
    for repository, expected_paths in expected_paths_by_repository.items():
        object_paths = [
            item["path"]
            for item in snapshots_by_repository[repository]["evidence_objects"]
        ]
        if (
            len(object_paths) != len(set(object_paths))
            or set(object_paths) != expected_paths
        ):
            raise ValueError(
                "source snapshot objects do not exactly cover corpus evidence paths"
            )

    plugin_ids = [row["id"] for row in plugin_rows]
    evidence_contract_sources = [
        row["source_plugin"]
        for row in cases["contracts"]
        if row["model_kind"] == "evidence-backed-abstraction"
    ]
    if (
        len(plugin_ids) != len(set(plugin_ids))
        or len(evidence_contract_sources) != len(set(evidence_contract_sources))
        or set(evidence_contract_sources) != set(plugin_ids)
        or any(
            row["source_plugin"] is not None
            for row in cases["contracts"]
            if row["model_kind"] == "synthetic-control"
        )
    ):
        raise ValueError("planner source contracts do not exactly cover corpus plugins")

    input_digests = {
        "cases_sha256": digest(root, "experiments/contract_planner/cases.json"),
        "taxonomy_sha256": digest(root, "spec/0.1/contract-taxonomy.json"),
        "source_corpus_sha256": digest(root, "docs/corpus/plugins.json"),
        "source_snapshots_sha256": digest(root, "docs/corpus/source-snapshots.json"),
    }
    oracle_digest = digest(root, "experiments/contract_planner/oracle.json")
    if (
        oracle.get("status") != "independently-reviewed"
        or oracle.get("review", {}).get("verdict") != "MERGE"
        or any(oracle.get(field) != value for field, value in input_digests.items())
        or any(
            oracle.get("review", {}).get(field) != value
            for field, value in input_digests.items()
        )
    ):
        raise ValueError("planner oracle does not bind every current input")
    expected_metric_inputs = {**input_digests, "oracle_sha256": oracle_digest}
    expected_implementation = {
        "evaluator_sha256": digest(root, "experiments/contract_planner/evaluate.py"),
        "contract_compiler_sha256": digest(
            root, "src/vllm_hust_ext/contract_compiler.py"
        ),
    }
    if (
        metrics.get("inputs") != expected_metric_inputs
        or metrics.get("oracle", {}).get("sha256") != oracle_digest
        or metrics.get("implementation") != expected_implementation
        or metrics.get("decisions_sha256")
        != digest(root, "experiments/contract_planner/results/decisions.jsonl")
    ):
        raise ValueError("planner metrics do not bind current inputs and outputs")

    overall = metrics.get("overall")
    if not isinstance(overall, dict):
        raise ValueError("planner metrics are missing overall counts")
    planner_cases = require_count(metrics.get("case_count"), "planner case count")
    planner_admits = require_count(overall.get("true_admit"), "true admits")
    planner_rejects = require_count(overall.get("true_reject"), "true rejects")
    if (
        metrics.get("classification") != "modeled-static-contract-corpus"
        or len(case_rows) != planner_cases
        or len(decisions) != planner_cases
        or planner_admits + planner_rejects != planner_cases
        or overall.get("false_admit") != 0
        or overall.get("false_reject") != 0
        or metrics.get("all_decisions_match") is not True
        or metrics.get("all_errors_match") is not True
    ):
        raise ValueError("modeled planner evidence is internally inconsistent")

    source_objects = 0
    for row in source_rows:
        if not isinstance(row, dict) or not isinstance(
            row.get("evidence_objects"), list
        ):
            raise ValueError("source snapshot evidence objects are malformed")
        source_objects += len(row["evidence_objects"])

    completed = require_count(aggregate.get("completed_cells"), "completed cells")
    planned = require_count(aggregate.get("planned_records"), "planned records")
    expected_planned = len(scenario_rows) * len(arms)
    if planned != expected_planned:
        raise ValueError("formal planned records differ from scenarios times arms")
    if completed > planned:
        raise ValueError("formal completed cells exceed the preregistered plan")
    if completed and not adapters:
        raise ValueError("formal completed cells require a verified adapter")
    if completed:
        raise ValueError(
            "formal completed cells require record-level validation before rendering"
        )
    if (
        aggregate.get("metrics") is not None
        or aggregate.get("paired_contrasts") is not None
    ):
        raise ValueError("an empty formal aggregate must not contain metrics")

    minimum_starts = require_count(protocol.get("minimum_starts"), "minimum starts")
    schedule = protocol.get("schedule")
    if (
        len(arms) != len(set(arms))
        or not isinstance(schedule, list)
        or len(schedule) != minimum_starts
        or any(
            not isinstance(row, list) or sorted(row) != sorted(arms) for row in schedule
        )
        or any(
            len({schedule[row][column] for row in range(len(schedule))}) != len(arms)
            for column in range(len(arms))
        )
    ):
        raise ValueError("formal protocol is not a square balanced arm schedule")
    first_study_starts = require_count(
        first_study.get("planned_starts"), "first study starts"
    )
    study_status = first_study.get("status")
    if (
        study_status not in {"pre-admission", "admitted", "running", "complete"}
        or (study_status == "pre-admission") != (first_study.get("admissible") is False)
        or first_study.get("scenario") != "partial-worker-coverage"
        or first_study.get("arms") != arms
        or first_study.get("repetitions") != minimum_starts
        or first_study.get("schedule") != schedule
        or first_study_starts != len(arms) * minimum_starts
    ):
        raise ValueError("first formal study differs from the frozen protocol")
    deployment_arms = deployment.get("arm_registrations")
    deployment_sources = deployment.get("source_registrations")
    deployment_blockers = deployment.get("blockers")
    common_deployment_invalid = (
        deployment.get("study_id") != first_study.get("study_id")
        or deployment.get("producer_candidate") != first_study.get("producer_candidate")
        or not isinstance(deployment_arms, list)
        or [row.get("arm") for row in deployment_arms] != arms
        or not isinstance(deployment_sources, list)
        or len(deployment_sources) != 5
        or not isinstance(deployment_blockers, list)
        or len(deployment_blockers) != len(set(deployment_blockers))
    )
    unregistered_invalid = deployment.get("registration_state") == "unregistered" and (
        deployment.get("admissible") is not False
        or deployment.get("producer_admission_receipt") is not None
        or any(
            value is not None
            for value in deployment.get("deployment_identity", {}).values()
        )
        or any(row.get("registration") is not None for row in deployment_arms)
        or any(row.get("registration") is not None for row in deployment_sources)
        or any(deployment.get("reviews", {}).values())
        or set(deployment_blockers) != set(first_study.get("blockers", []))
        or study_status != "pre-admission"
    )
    registered_invalid = deployment.get("registration_state") == "registered" and (
        deployment.get("admissible") is not True
        or not isinstance(deployment.get("producer_admission_receipt"), dict)
        or any(
            value is None
            for value in deployment.get("deployment_identity", {}).values()
        )
        or any(row.get("registration") is None for row in deployment_arms)
        or any(row.get("registration") is None for row in deployment_sources)
        or not all(deployment.get("reviews", {}).values())
        or deployment_blockers
        or study_status == "pre-admission"
    )
    if common_deployment_invalid or unregistered_invalid or registered_invalid:
        raise ValueError("first formal deployment registration is not fail closed")
    reference_starts = require_count(reference.get("starts"), "reference starts")
    reference_scenarios = reference.get("scenarios")
    if (
        reference.get("evidence_class") != "reference-synthetic"
        or reference.get("seed") != protocol.get("seed")
        or reference.get("arms") != arms
        or not isinstance(reference_scenarios, list)
        or len(reference_scenarios) != len(set(reference_scenarios))
        or not set(reference_scenarios)
        <= {scenario.get("id") for scenario in scenario_rows}
        or reference.get("starts_per_arm_per_scenario") != minimum_starts
        or reference_starts != len(reference_scenarios) * len(arms) * minimum_starts
        or reference.get("formal_completed_cells") != completed
        or reference.get("timing_summary") is not None
    ):
        raise ValueError("reference summary is inconsistent with protocol and status")

    reject_precision = overall.get("reject_precision")
    reject_recall = overall.get("reject_recall")
    admit_recall = overall.get("admit_recall")
    formatted_metrics: dict[str, str] = {}
    for label, metric in (
        ("reject precision", reject_precision),
        ("reject recall", reject_recall),
        ("admit recall", admit_recall),
    ):
        if not isinstance(metric, dict) or metric.get("value") != 1:
            raise ValueError(f"{label} differs from the reviewed modeled result")
        formatted_metrics[label] = f"{float(metric['value']):.1f}"

    return {
        "corpus_extensions": len(plugin_rows),
        "adaptation_candidates": len(excluded_rows),
        "planner_cases": planner_cases,
        "planner_admits": planner_admits,
        "planner_rejects": planner_rejects,
        "planner_reject_precision": formatted_metrics["reject precision"],
        "planner_reject_recall": formatted_metrics["reject recall"],
        "planner_admit_recall": formatted_metrics["admit recall"],
        "source_repositories": len(source_rows),
        "source_objects": source_objects,
        "formal_completed": completed,
        "formal_planned": planned,
        "verified_adapters": len(adapters),
        "reference_starts": reference_starts,
        "formal_arms": len(arms),
        "minimum_starts": minimum_starts,
        "schedule_rows": len(schedule),
        "research_claims": len(claim_rows),
        "first_study_starts": first_study_starts,
        "deployment_blockers": len(deployment_blockers),
        "registered_deployment_arms": sum(
            row["registration"] is not None for row in deployment_arms
        ),
    }


def render(summary: dict[str, int | str]) -> str:
    macros = (
        ("ECPACorpusExtensions", "corpus_extensions"),
        ("ECPAAdaptationCandidates", "adaptation_candidates"),
        ("ECPAPlannerCases", "planner_cases"),
        ("ECPAPlannerAdmits", "planner_admits"),
        ("ECPAPlannerRejects", "planner_rejects"),
        ("ECPAPlannerRejectPrecision", "planner_reject_precision"),
        ("ECPAPlannerRejectRecall", "planner_reject_recall"),
        ("ECPAPlannerAdmitRecall", "planner_admit_recall"),
        ("ECPASourceRepositories", "source_repositories"),
        ("ECPASourceObjects", "source_objects"),
        ("ECPAFormalCompleted", "formal_completed"),
        ("ECPAFormalPlanned", "formal_planned"),
        ("ECPAVerifiedAdapters", "verified_adapters"),
        ("ECPAReferenceStarts", "reference_starts"),
        ("ECPAFormalArms", "formal_arms"),
        ("ECPAMinimumStarts", "minimum_starts"),
        ("ECPAScheduleRows", "schedule_rows"),
        ("ECPAResearchClaims", "research_claims"),
        ("ECPAFirstStudyStarts", "first_study_starts"),
        ("ECPADeploymentBlockers", "deployment_blockers"),
        ("ECPARegisteredDeploymentArms", "registered_deployment_arms"),
    )
    lines = [
        "% Generated by paper/scripts/generate_evidence_summary.py; do not edit.",
        "% Values are modeled/static or status evidence unless the paper says",
        "% otherwise.",
    ]
    lines.extend(
        f"\\newcommand{{\\{macro}}}{{{summary[key]}}}" for macro, key in macros
    )
    return "\n".join(lines) + "\n"


def write_atomic(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".evidence-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the checked-in summary equals the artifact-derived output",
    )
    args = parser.parse_args()
    content = render(collect_summary())
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text() != content:
            raise SystemExit("paper evidence summary is stale; regenerate it")
        return 0
    write_atomic(OUTPUT, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
