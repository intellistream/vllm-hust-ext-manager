#!/usr/bin/env python3
"""Generate fail-closed LaTeX evidence macros from checked artifacts."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "paper/generated/evidence-summary.tex"
WORKSHOP_SOURCE_IDENTITY = {
    "repository": "vLLM-HUST/vllm-hust-website",
    "repository_id": 1141990731,
    "node_id": "R_kgDORBFlSw",
    "default_branch": "main",
    "commit_sha": "8336f5b67c69910aa7d5dfc3b5b94407e99928bd",
    "metadata_path": "data/plugin-workshop-metadata.json",
    "metadata_snapshot_path": "docs/corpus/plugin-workshop-metadata.snapshot.json",
    "metadata_blob_sha": "04b6d4a23f62ba5fc4b3d53dff5a712b117560f2",
    "metadata_sha256": (
        "94164486d075671dde0e2992557d5117073644c402054be518673cea68bbd08e"
    ),
    "source_rows_sha256": (
        "aabd0a6dbd49e2314c816e115fe90307a1e2e085e91665eb5a8ec672c2625adf"
    ),
    "audit_rows_sha256": (
        "be253c011bc72e159a8390cea9cc1ba3d615468672ce1019c8c4475358301c4e"
    ),
    "mod_count": 24,
}
WORKSHOP_SOURCE_FIELDS = (
    "id",
    "repository",
    "repository_id",
    "node_id",
    "visibility",
    "default_branch",
    "head_commit",
)


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


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def recompute_transaction_model(root: Path) -> dict[str, Any]:
    path = root / "experiments/transaction_model/explore.py"
    module_name = "ecpa_paper_transaction_model"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load bounded transaction model")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        result = module.explore()
    finally:
        sys.modules.pop(module_name, None)
    if not isinstance(result, dict):
        raise ValueError("bounded transaction model did not return an object")
    return result


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
    workshop = load_json(root, "docs/corpus/workshop-mods.json")
    workshop_metadata = load_json(
        root, "docs/corpus/plugin-workshop-metadata.snapshot.json"
    )
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
    transaction_model = load_json(
        root, "experiments/transaction_model/artifacts/result-summary.json"
    )

    for artifact, schema in (
        (workshop, "docs/corpus/workshop-mods.schema.json"),
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
        (
            transaction_model,
            "experiments/transaction_model/result-summary.schema.json",
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

    require_schema(workshop, "ecpa-workshop-mod-corpus/v1", "workshop MOD corpus")
    require_schema(plugins, "ecpa-plugin-corpus/v1", "planner seed corpus")
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
    require_schema(
        transaction_model,
        "ecpa-bounded-transaction-model/v1",
        "bounded transaction model",
    )

    workshop_rows = workshop.get("mods")
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
            workshop_rows,
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

    workshop_counts = workshop.get("counts")
    if not isinstance(workshop_counts, dict):
        raise ValueError("workshop MOD corpus is missing derived counts")
    integration_counts: dict[str, int] = {}
    test_counts: dict[str, int] = {}
    build_counts: dict[str, int] = {}
    for row in workshop_rows:
        integration = row["integration_class"]
        local_test = row["local_test"]
        package_build = row["package_build"]
        integration_counts[integration] = integration_counts.get(integration, 0) + 1
        test_counts[local_test] = test_counts.get(local_test, 0) + 1
        build_counts[package_build] = build_counts.get(package_build, 0) + 1
    expected_workshop_counts = {
        "mods": len(workshop_rows),
        "ecpa_bundle_namespace": integration_counts.get("ecpa_bundle_namespace", 0),
        "namespace_mismatch": integration_counts.get("namespace_mismatch", 0),
        "general_plugin_only": integration_counts.get("general_plugin_only", 0),
        "direct_or_non_entry_integration": integration_counts.get(
            "direct_or_non_entry_integration", 0
        ),
        "source_only": integration_counts.get("source_only", 0),
        "package_projects": build_counts.get("pass", 0)
        + build_counts.get("qualified_staging_required", 0),
        "local_package_build_pass": build_counts.get("pass", 0),
        "local_tests_pass": test_counts.get("pass", 0),
        "environment_blocked": test_counts.get("environment_blocked", 0),
        "no_automated_tests": test_counts.get("no_automated_tests", 0),
    }
    population = workshop.get("population")
    workshop_source_rows = [
        {field: row[field] for field in WORKSHOP_SOURCE_FIELDS} for row in workshop_rows
    ]
    metadata_plugins = workshop_metadata.get("plugins")
    if not isinstance(population, dict) or population != WORKSHOP_SOURCE_IDENTITY:
        raise ValueError(
            "workshop page source identity differs from the frozen authority"
        )
    if (
        digest(root, population["metadata_snapshot_path"])
        != population["metadata_sha256"]
        or canonical_digest(workshop_source_rows) != population["source_rows_sha256"]
        or canonical_digest(workshop_rows) != population["audit_rows_sha256"]
        or workshop_metadata.get("schema_version") != "plugin-workshop-metadata/v1"
        or not isinstance(metadata_plugins, dict)
        or list(metadata_plugins) != [row["id"] for row in workshop_rows]
        or any(
            metadata_plugins[row["id"]].get("repository") != row["repository"]
            for row in workshop_rows
        )
    ):
        raise ValueError("workshop rows are not bound to the frozen page snapshot")
    if (
        workshop_counts != expected_workshop_counts
        or len(workshop_rows) != 24
        or workshop.get("population", {}).get("mod_count") != len(workshop_rows)
        or len({row["id"] for row in workshop_rows}) != len(workshop_rows)
        or len({row["repository_id"] for row in workshop_rows}) != len(workshop_rows)
        or any(not row["repository"].startswith("vLLM-HUST/") for row in workshop_rows)
    ):
        raise ValueError("workshop MOD population or derived counts are inconsistent")

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
    transaction_states = require_count(
        transaction_model.get("reachable_states"), "transaction-model states"
    )
    transaction_edges = require_count(
        transaction_model.get("valid_edges"), "transaction-model edges"
    )
    transaction_rejections = require_count(
        transaction_model.get("rejected_state_action_pairs"),
        "transaction-model rejected pairs",
    )
    if (
        transaction_model != recompute_transaction_model(root)
        or transaction_model.get("classification") != "exhaustive-finite-abstract-model"
        or transaction_model.get("implementation_sha256")
        != digest(root, "experiments/transaction_model/explore.py")
        or transaction_model.get("formal_real_result") is not False
        or transaction_model.get("fixed_point_reached") is not True
        or transaction_model.get("counterexamples") != []
        or transaction_states == 0
        or transaction_edges == 0
        or transaction_rejections == 0
    ):
        raise ValueError("bounded transaction model is not valid modeled evidence")
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
        "workshop_mods": len(workshop_rows),
        "workshop_bundle_namespace": workshop_counts["ecpa_bundle_namespace"],
        "workshop_test_pass": workshop_counts["local_tests_pass"],
        "workshop_environment_blocked": workshop_counts["environment_blocked"],
        "planner_seed_extensions": len(plugin_rows),
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
        "transaction_model_states": transaction_states,
        "transaction_model_edges": transaction_edges,
        "transaction_model_rejections": transaction_rejections,
        "transaction_model_invariants": len(transaction_model["invariants"]),
    }


def render(summary: dict[str, int | str]) -> str:
    macros = (
        ("ECPAWorkshopMods", "workshop_mods"),
        ("ECPAWorkshopBundleNamespace", "workshop_bundle_namespace"),
        ("ECPAWorkshopTestPass", "workshop_test_pass"),
        ("ECPAWorkshopEnvironmentBlocked", "workshop_environment_blocked"),
        ("ECPAPlannerSeedExtensions", "planner_seed_extensions"),
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
        ("ECPATransactionModelStates", "transaction_model_states"),
        ("ECPATransactionModelEdges", "transaction_model_edges"),
        ("ECPATransactionModelRejections", "transaction_model_rejections"),
        ("ECPATransactionModelInvariants", "transaction_model_invariants"),
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
