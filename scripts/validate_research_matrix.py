#!/usr/bin/env python3
"""Validate the paper claim graph and first formal-real preregistration."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]

CLAIMS_PATH = "docs/research/claims-to-experiment-matrix.json"
CLAIMS_SCHEMA_PATH = "docs/research/claims-to-experiment-matrix.schema.json"
STUDY_PATH = "experiments/false_effective/first-formal-real-study.json"
STUDY_SCHEMA_PATH = "experiments/false_effective/first-formal-real-study.schema.json"
DEPLOYMENT_PATH = "experiments/false_effective/first-formal-real-deployment.json"
DEPLOYMENT_SCHEMA_PATH = (
    "experiments/false_effective/first-formal-real-deployment.schema.json"
)

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
HYPOTHESIS_EXPERIMENT_KINDS = {
    "H1": {"formal-comparison"},
    "H2": {"modeled-static"},
    "H3": {"formal-recovery"},
    "H4": {"formal-performance"},
}
SOURCE_KIND_AUTHORITIES = {
    "readiness-probe": "lifecycle-source",
    "workload-driver": "lifecycle-source",
    "fault-actuator": "lifecycle-source",
    "host-observer": "vllm-hust-host",
    "process-monitor": "process-monitor",
}
REGISTRATION_DESIGN_BASE = {
    "repository": "intellistream/vllm-hust-ext-manager",
    "commit": "a26ded6b169a25001b03500e7b252740aeabce8b",
    "tree": "3476f88bc18e295d2e56988ce6af3963d397e5c9",
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


def parser_subcommands(root: Path, relative: str) -> set[str]:
    module = ast.parse((root / relative).read_text(), filename=relative)
    commands = set()
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            commands.add(node.args[0].value)
    return commands


def adapter_profiles(root: Path) -> dict[str, dict[str, Any]]:
    relative = "experiments/false_effective/runner.py"
    module = ast.parse((root / relative).read_text(), filename=relative)
    class_names = {
        "VanillaVLLMAdapter",
        "ManualIntegrationAdapter",
        "ECPAAdapter",
    }
    profiles = {}
    managed_contract = python_literal(
        root, "src/vllm_hust_ext/manager_controller.py", "ACTIVATION_CONTRACT"
    )
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or node.name not in class_names:
            continue
        calls = [
            item
            for item in ast.walk(node)
            if isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute)
            and item.func.attr == "__init__"
            and len(item.args) == 3
        ]
        if len(calls) != 1:
            raise ValueError(f"{relative} adapter profile is ambiguous")
        call = calls[0]
        arm = ast.literal_eval(call.args[0])
        contract = (
            managed_contract
            if isinstance(call.args[1], ast.Name)
            and call.args[1].id == "MANAGED_ACTIVATION_CONTRACT"
            else ast.literal_eval(call.args[1])
        )
        profiles[arm] = {
            "activation_contract": contract,
            "activation_arguments": list(ast.literal_eval(call.args[2])),
        }
    if set(profiles) != {
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    }:
        raise ValueError(f"{relative} does not define the three formal adapters")
    return profiles


def file_sha256(root: Path, relative: str) -> str:
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()


def object_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate(root: Path = ROOT) -> dict[str, int | str]:
    claims_matrix = load(root, CLAIMS_PATH)
    study = load(root, STUDY_PATH)
    deployment = load(root, DEPLOYMENT_PATH)
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
    validate_schema(root, deployment, DEPLOYMENT_SCHEMA_PATH)

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
            if (
                experiment["kind"]
                not in HYPOTHESIS_EXPERIMENT_KINDS[claim["paper_hypothesis"]]
            ):
                raise ValueError("paper hypothesis differs from experiment kind")
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
    if any(
        experiment_id != study["experiment_id"]
        and experiment["kind"] != "modeled-static"
        and experiment["status"] != "planned"
        for experiment_id, experiment in experiments.items()
    ):
        raise ValueError("non-executable formal experiments must remain planned")

    phase_commands = {
        row["phase"]: row["source_subcommand"] for row in study["phase_authorities"]
    }
    phase_source_kinds = {
        row["phase"]: row["source_kind"] for row in study["phase_authorities"]
    }
    phase_authorities = {
        row["phase"]: row["authority"] for row in study["phase_authorities"]
    }
    if len(phase_commands) != len(study["phase_authorities"]):
        raise ValueError("first formal study phase authorities must be unique")
    if phase_commands != PHASE_COMMANDS:
        raise ValueError("first formal study does not bind the five lifecycle sources")
    runner_source_kinds = python_literal(
        root, "experiments/false_effective/harness.py", "FORMAL_LIFECYCLE_FACT_SOURCES"
    )
    source_accepted_kinds = python_literal(
        root, "src/vllm_hust_ext/formal_lifecycle_source.py", "SOURCE_KINDS"
    )
    if (
        len(runner_source_kinds) != 5
        or len(set(runner_source_kinds.values())) != 5
        or phase_source_kinds != runner_source_kinds
        or source_accepted_kinds != runner_source_kinds
    ):
        raise ValueError("formal study, runner, and source kinds differ")
    if any(
        phase_authorities[phase] != SOURCE_KIND_AUTHORITIES[source_kind]
        for phase, source_kind in phase_source_kinds.items()
    ):
        raise ValueError("formal study authority differs from its source kind")
    source_subcommands = parser_subcommands(
        root, "src/vllm_hust_ext/formal_lifecycle_source.py"
    )
    if set(phase_commands.values()) != source_subcommands:
        raise ValueError("first formal study subcommands differ from the source CLI")
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
    canonical_registry = (
        json.dumps(registry, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()
    if (root / "experiments/false_effective/verified-adapters.json").read_bytes() != (
        canonical_registry
    ):
        raise ValueError("verified adapter registry must be canonical")
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

    if deployment["study_id"] != study["study_id"]:
        raise ValueError("deployment registration names a different study")
    bindings = deployment["bindings"]
    if bindings["study_sha256"] != file_sha256(root, STUDY_PATH) or bindings[
        "protocol_sha256"
    ] != file_sha256(root, "experiments/false_effective/protocol.json"):
        raise ValueError("deployment registration bindings are stale")
    if bindings["registration_design_base"] != REGISTRATION_DESIGN_BASE:
        raise ValueError("deployment registration design base is not authoritative")
    if deployment["producer_candidate"] != producer:
        raise ValueError("deployment registration producer differs from study")

    arm_registrations = deployment["arm_registrations"]
    if [row["arm"] for row in arm_registrations] != study["arms"]:
        raise ValueError("deployment registration arms differ from study")
    source_registrations = deployment["source_registrations"]
    expected_sources = [
        {
            key: row[key]
            for key in ("phase", "source_kind", "source_subcommand", "authority")
        }
        for row in study["phase_authorities"]
    ]
    actual_sources = [
        {
            key: row[key]
            for key in ("phase", "source_kind", "source_subcommand", "authority")
        }
        for row in source_registrations
    ]
    if actual_sources != expected_sources:
        raise ValueError("deployment registration sources differ from study")

    if deployment["registration_state"] == "unregistered":
        if (
            deployment["admissible"] is not False
            or deployment["producer_admission_receipt"] is not None
            or any(
                value is not None
                for value in deployment["deployment_identity"].values()
            )
            or any(row["registration"] is not None for row in arm_registrations)
            or any(row["registration"] is not None for row in source_registrations)
            or any(deployment["reviews"].values())
            or set(deployment["blockers"]) != pre_admission_blockers
            or adapters
            or study["status"] != "pre-admission"
        ):
            raise ValueError(
                "unregistered deployment must retain null slots and every blocker"
            )
    else:
        identity = deployment["deployment_identity"]
        admission = deployment["producer_admission_receipt"]
        if (
            deployment["admissible"] is not True
            or deployment["blockers"]
            or any(value is None for value in identity.values())
            or any(row["registration"] is None for row in arm_registrations)
            or any(row["registration"] is None for row in source_registrations)
            or not all(deployment["reviews"].values())
            or not isinstance(admission, dict)
            or admission.get("state") != "merged"
            or admission.get("human_line_review") is not True
            or study["status"] == "pre-admission"
            or study["admissible"] is not True
            or study["blockers"]
        ):
            raise ValueError("registered deployment is not fully admitted")
        validate_schema(
            root,
            admission,
            "experiments/false_effective/formal-adapter-admission.schema.json",
        )
        admission_producer_fields = {
            "repository": "repository",
            "pull_request": "pull_request",
            "reviewed_head": "reviewed_head",
            "reviewed_tree": "reviewed_tree",
            "base": "base",
            "state": "observed_state",
            "merge_commit": "merge_commit",
            "human_line_review": "human_line_review",
            "observed_at": "observed_at",
        }
        if any(
            admission[receipt_field] != producer[producer_field]
            for receipt_field, producer_field in admission_producer_fields.items()
        ):
            raise ValueError("producer admission receipt differs from study")
        study_identity = study["fixed_identity"]
        if any(study_identity[field] != identity[field] for field in study_identity):
            raise ValueError("registered deployment identity differs from study")

        registry_by_id = {row["id"]: row for row in adapters}
        if len(registry_by_id) != len(adapters):
            raise ValueError("verified adapter registry contains duplicate ids")
        registration_ids = [
            row["registration"]["registry_id"] for row in arm_registrations
        ]
        if set(registration_ids) != set(registry_by_id):
            raise ValueError("deployment arms differ from adapter registry")
        profiles = adapter_profiles(root)
        lifecycle_sources = python_literal(
            root,
            "experiments/false_effective/harness.py",
            "FORMAL_LIFECYCLE_FACT_SOURCES",
        )
        lifecycle_transport = python_literal(
            root,
            "experiments/false_effective/harness.py",
            "FORMAL_LIFECYCLE_FACT_TRANSPORT",
        )
        ecpa_probe_options = sorted(
            python_literal(
                root,
                "experiments/false_effective/runner.py",
                "ECPA_FORMAL_ACTIVATION_OPTIONS",
            )
        )
        lifecycle_schema_digest = "sha256:" + file_sha256(
            root, "experiments/false_effective/formal-lifecycle-fact.schema.json"
        )
        launch_command_digests = set()
        for row in arm_registrations:
            registration = row["registration"]
            entry = registry_by_id[registration["registry_id"]]
            profile = profiles[row["arm"]]
            launch_digest_fields = (
                {
                    "manager_command_digest",
                    "target_command_digest",
                    "observer_command_digest",
                }
                if row["arm"] == "ecpa"
                else {"sut_command_digest", "observer_command_digest"}
            )
            expected_entry_fields = {
                "id",
                "admission",
                "arm",
                "activation_contract",
                "evidence_owner",
                "evidence_channel",
                "host_event_schema",
                "lifecycle_fact_schema",
                "lifecycle_fact_schema_digest",
                "lifecycle_fact_sources",
                "lifecycle_fact_transport",
                "required_observables",
                "lifecycle_fact_command_digests",
                "scenario_bindings",
                "activation_probe",
                *launch_digest_fields,
            }
            expected_probe_options = (
                ecpa_probe_options
                if row["arm"] == "ecpa"
                else sorted(profile["activation_arguments"])
            )
            if (
                set(entry) != expected_entry_fields
                or entry.get("arm") != row["arm"]
                or entry.get("activation_contract") != profile["activation_contract"]
                or entry.get("evidence_owner") != "vllm-hust-host"
                or entry.get("evidence_channel") != "host-owned-event-stream"
                or entry.get("host_event_schema") != "ecpa-host-runtime-evidence/v1"
                or entry.get("lifecycle_fact_schema") != "ecpa-formal-lifecycle-fact/v1"
                or entry.get("lifecycle_fact_schema_digest") != lifecycle_schema_digest
                or entry.get("lifecycle_fact_sources") != lifecycle_sources
                or entry.get("lifecycle_fact_transport") != lifecycle_transport
                or set(entry.get("required_observables", [])) != runner_observables
                or entry.get("lifecycle_fact_command_digests")
                != {
                    source["phase"]: source["registration"]["command_digest"]
                    for source in source_registrations
                }
                or entry.get("scenario_bindings")
                != {
                    study["scenario"]: {
                        "descriptor_sha256": identity["fault_descriptor_sha256"],
                        "entry_point": identity["plugin_entry_point"],
                        "fault_source_subcommand": PHASE_COMMANDS["fault-injected"],
                    }
                }
                or set(entry.get("activation_probe", {}))
                != {"command_digest", "required_options", "timeout_s"}
                or entry["activation_probe"].get("required_options")
                != expected_probe_options
                or isinstance(entry["activation_probe"].get("timeout_s"), bool)
                or not isinstance(entry["activation_probe"].get("timeout_s"), int)
                or not 1 <= entry["activation_probe"]["timeout_s"] <= 30
                or registration["registry_entry_sha256"] != object_sha256(entry)
                or entry.get("admission") != admission
                or registration["activation_probe_digest"]
                != entry.get("activation_probe", {}).get("command_digest")
            ):
                raise ValueError("deployment arm differs from adapter registry")
            registered_commands = {
                command["role"]: command["command_digest"]
                for command in registration["commands"]
            }
            expected_commands = {
                role.removesuffix("_command_digest"): value
                for role, value in entry.items()
                if role
                in {
                    "sut_command_digest",
                    "manager_command_digest",
                    "target_command_digest",
                    "observer_command_digest",
                }
            }
            if (
                len(registered_commands) != len(registration["commands"])
                or registered_commands != expected_commands
            ):
                raise ValueError("deployment command roles differ from registry")
            launch_command_digests.update(registered_commands.values())

        expected_registry_ids = set(registration_ids)
        source_digests = []
        for row in source_registrations:
            registration = row["registration"]
            if set(registration["registry_ids"]) != expected_registry_ids:
                raise ValueError("deployment source does not cover every arm")
            expected_digests = {
                registry_by_id[registry_id]
                .get("lifecycle_fact_command_digests", {})
                .get(row["phase"])
                for registry_id in registration["registry_ids"]
            }
            if expected_digests != {registration["command_digest"]}:
                raise ValueError("deployment source command differs from registry")
            source_digests.append(registration["command_digest"])
        if len(source_digests) != len(set(source_digests)):
            raise ValueError("deployment lifecycle source commands must be distinct")
        if launch_command_digests.intersection(source_digests):
            raise ValueError("deployment source and launch commands must be distinct")

    return {
        "claims": len(claims),
        "experiments": len(experiments),
        "first_study_starts": study["planned_starts"],
        "first_study_status": study["status"],
        "deployment_registration": deployment["registration_state"],
    }


def main() -> int:
    summary = validate()
    print(
        "research matrix valid: "
        f"{summary['claims']} claims, {summary['experiments']} experiments, "
        f"first study {summary['first_study_status']} "
        f"({summary['first_study_starts']} planned starts), deployment "
        f"{summary['deployment_registration']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
