from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_research_matrix.py"
INPUTS = (
    "docs/research/claims-to-experiment-matrix.json",
    "docs/research/claims-to-experiment-matrix.schema.json",
    "experiments/false_effective/first-formal-real-study.json",
    "experiments/false_effective/first-formal-real-study.schema.json",
    "experiments/false_effective/first-formal-real-deployment.json",
    "experiments/false_effective/first-formal-real-deployment.schema.json",
    "experiments/false_effective/formal-adapter-admission.schema.json",
    "experiments/false_effective/protocol.json",
    "experiments/false_effective/scenarios.json",
    "experiments/false_effective/verified-adapters.json",
    "experiments/false_effective/artifacts/formal-aggregate-summary.json",
    "experiments/false_effective/harness.py",
    "experiments/false_effective/runner.py",
    "experiments/false_effective/formal-lifecycle-fact.schema.json",
    "experiments/contract_planner/results/metrics.json",
    "paper/main.tex",
    "src/vllm_hust_ext/formal_lifecycle_source.py",
    "src/vllm_hust_ext/manager_controller.py",
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


def write_canonical_json(path: Path, value) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    )


def test_current_research_matrix_is_pre_admission() -> None:
    validator = load_validator()

    assert validator.validate(ROOT) == {
        "claims": 4,
        "experiments": 5,
        "first_study_starts": 9,
        "first_study_status": "pre-admission",
        "deployment_registration": "unregistered",
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


def test_unregistered_deployment_rejects_partially_frozen_command(
    tmp_path: Path,
) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["arm_registrations"][0].__setitem__(
            "registration",
            {
                "registry_id": "not-admitted",
                "registry_entry_sha256": "0" * 64,
                "commands": [
                    {"role": "sut", "command_digest": "sha256:" + "1" * 64},
                    {
                        "role": "observer",
                        "command_digest": "sha256:" + "2" * 64,
                    },
                ],
                "activation_probe_digest": "sha256:" + "3" * 64,
            },
        ),
    )

    with pytest.raises(ValueError, match="retain null slots"):
        validator.validate(tmp_path)


def test_deployment_registration_rejects_stale_study_digest(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["bindings"].__setitem__("study_sha256", "0" * 64),
    )

    with pytest.raises(ValueError, match="bindings are stale"):
        validator.validate(tmp_path)


def test_deployment_registration_rejects_unbound_design_base(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["bindings"]["registration_design_base"].update(
            {"commit": "f" * 40, "tree": "e" * 40}
        ),
    )

    with pytest.raises(ValueError, match="design base is not authoritative"):
        validator.validate(tmp_path)


def test_deployment_registration_rejects_missing_arm(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["arm_registrations"][2].__setitem__(
            "arm", "manual-integration"
        ),
    )

    with pytest.raises(ValueError, match="arms differ from study"):
        validator.validate(tmp_path)


def test_deployment_registration_rejects_source_authority_drift(
    tmp_path: Path,
) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value["source_registrations"][0].__setitem__(
            "authority", "process-monitor"
        ),
    )

    with pytest.raises(ValueError, match="sources differ from study"):
        validator.validate(tmp_path)


def test_deployment_registration_rejects_premature_admission(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    deployment = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    rewrite_json(
        deployment,
        lambda value: value.__setitem__("admissible", True),
    )

    with pytest.raises(ValueError, match="retain null slots"):
        validator.validate(tmp_path)


def test_formal_claim_cannot_be_promoted_without_results(tmp_path: Path) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: value["claims"][1].__setitem__("status", "complete"),
    )

    with pytest.raises(ValidationError, match="is not one of"):
        validator.validate(tmp_path)


def test_unregistered_formal_experiment_cannot_be_promoted(
    tmp_path: Path,
) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    matrix = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    rewrite_json(
        matrix,
        lambda value: value["experiments"][2].__setitem__("status", "admitted"),
    )

    with pytest.raises(ValueError, match="must remain planned"):
        validator.validate(tmp_path)


def test_complete_deployment_registration_matches_runtime_registry(
    tmp_path: Path,
) -> None:
    validator = load_validator()
    copy_inputs(tmp_path)
    study_path = tmp_path / "experiments/false_effective/first-formal-real-study.json"
    deployment_path = (
        tmp_path / "experiments/false_effective/first-formal-real-deployment.json"
    )
    matrix_path = tmp_path / "docs/research/claims-to-experiment-matrix.json"
    registry_path = tmp_path / "experiments/false_effective/verified-adapters.json"

    producer = {
        "repository": "vLLM-HUST/vllm-hust",
        "pull_request": 27,
        "reviewed_head": "1" * 40,
        "reviewed_tree": "2" * 40,
        "base": "3" * 40,
        "observed_state": "merged",
        "merge_commit": "4" * 40,
        "human_line_review": True,
        "observed_at": "2026-09-21T10:00:00+08:00",
    }
    admission = {
        "schema": "ecpa-formal-adapter-admission/v1",
        "repository": producer["repository"],
        "repository_id": 1360701120,
        "node_id": "R_kgDOURE3QwA",
        "default_branch": "main",
        "pull_request": producer["pull_request"],
        "reviewed_head": producer["reviewed_head"],
        "reviewed_tree": producer["reviewed_tree"],
        "base": producer["base"],
        "state": producer["observed_state"],
        "merge_commit": producer["merge_commit"],
        "human_line_review": True,
        "commands_reviewed": True,
        "activation_path_reviewed": True,
        "observer_independence_reviewed": True,
        "observed_at": producer["observed_at"],
    }
    study_identity = {
        "runtime_commit": "4" * 40,
        "manager_commit": "5" * 40,
        "model": "reviewed-model",
        "workload_request_sha256": "sha256:" + "6" * 64,
        "hardware": "reviewed-host",
        "topology": "one-controller-two-workers",
        "container_digest": "sha256:" + "7" * 64,
        "fault_descriptor_sha256": "sha256:" + "8" * 64,
        "plugin_entry_point": {
            "group": "vllm.general_plugins",
            "name": "reviewed-plugin",
            "value": "reviewed.plugin:register",
        },
        "warm_state": "cold",
    }

    def admit_study(value):
        value["status"] = "admitted"
        value["admissible"] = True
        value["producer_candidate"] = producer
        value["blockers"] = []
        value["fixed_identity"] = study_identity

    rewrite_json(study_path, admit_study)
    rewrite_json(
        matrix_path,
        lambda value: value["experiments"][1].__setitem__("status", "admitted"),
    )

    phase_digests = {
        phase: "sha256:" + f"{index:x}" * 64
        for index, phase in enumerate(
            (
                "service-ready",
                "workload-complete",
                "fault-injected",
                "observer-captured",
                "service-shutdown",
            ),
            10,
        )
    }
    arms = [
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    ]
    profiles = validator.adapter_profiles(tmp_path)
    lifecycle_sources = validator.python_literal(
        tmp_path,
        "experiments/false_effective/harness.py",
        "FORMAL_LIFECYCLE_FACT_SOURCES",
    )
    lifecycle_transport = validator.python_literal(
        tmp_path,
        "experiments/false_effective/harness.py",
        "FORMAL_LIFECYCLE_FACT_TRANSPORT",
    )
    required_observables = sorted(
        validator.python_literal(
            tmp_path,
            "experiments/false_effective/harness.py",
            "FORMAL_HOST_OBSERVABLES",
        )
    )
    ecpa_probe_options = sorted(
        validator.python_literal(
            tmp_path,
            "experiments/false_effective/runner.py",
            "ECPA_FORMAL_ACTIVATION_OPTIONS",
        )
    )
    lifecycle_schema_digest = "sha256:" + validator.file_sha256(
        tmp_path, "experiments/false_effective/formal-lifecycle-fact.schema.json"
    )
    entries = []
    for index, arm in enumerate(arms, 1):
        command_fields = {
            "observer_command_digest": "sha256:" + f"{index + 2:x}" * 64,
        }
        if arm == "ecpa":
            command_fields.update(
                {
                    "manager_command_digest": "sha256:" + "f" * 64,
                    "target_command_digest": "sha256:" + "0" * 64,
                }
            )
        else:
            command_fields["sut_command_digest"] = "sha256:" + f"{index:x}" * 64
        entries.append(
            {
                "id": f"reviewed-{index}",
                "arm": arm,
                "admission": admission,
                "activation_contract": profiles[arm]["activation_contract"],
                "evidence_owner": "vllm-hust-host",
                "evidence_channel": "host-owned-event-stream",
                "host_event_schema": "ecpa-host-runtime-evidence/v1",
                "lifecycle_fact_schema": "ecpa-formal-lifecycle-fact/v1",
                "lifecycle_fact_schema_digest": lifecycle_schema_digest,
                "lifecycle_fact_sources": lifecycle_sources,
                "lifecycle_fact_transport": lifecycle_transport,
                "required_observables": required_observables,
                "activation_probe": {
                    "command_digest": "sha256:" + f"{index + 5:x}" * 64,
                    "required_options": (
                        ecpa_probe_options
                        if arm == "ecpa"
                        else sorted(profiles[arm]["activation_arguments"])
                    ),
                    "timeout_s": 5,
                },
                "lifecycle_fact_command_digests": phase_digests,
                "scenario_bindings": {
                    "partial-worker-coverage": {
                        "descriptor_sha256": study_identity["fault_descriptor_sha256"],
                        "entry_point": study_identity["plugin_entry_point"],
                        "fault_source_subcommand": "partial-coverage-quarantine",
                    }
                },
                **command_fields,
            }
        )
    write_canonical_json(
        registry_path,
        {"schema": "ecpa-formal-adapter-registry/v2", "adapters": entries},
    )

    def register_deployment(value):
        value["registration_state"] = "registered"
        value["admissible"] = True
        value["producer_candidate"] = producer
        value["producer_admission_receipt"] = admission
        value["deployment_identity"] = {
            **study_identity,
            "runtime_tree": "9" * 40,
            "manager_tree": "a" * 40,
        }
        for row, entry in zip(value["arm_registrations"], entries, strict=True):
            command_fields = {
                key.removesuffix("_command_digest"): digest
                for key, digest in entry.items()
                if key.endswith("_command_digest")
                and key != "lifecycle_fact_command_digests"
            }
            row["registration"] = {
                "registry_id": entry["id"],
                "registry_entry_sha256": validator.object_sha256(entry),
                "commands": [
                    {"role": role, "command_digest": digest}
                    for role, digest in command_fields.items()
                ],
                "activation_probe_digest": entry["activation_probe"]["command_digest"],
            }
        registry_ids = [entry["id"] for entry in entries]
        for row in value["source_registrations"]:
            row["registration"] = {
                "registry_ids": registry_ids,
                "command_digest": phase_digests[row["phase"]],
            }
        value["reviews"] = {key: True for key in value["reviews"]}
        value["blockers"] = []

    rewrite_json(deployment_path, register_deployment)
    deployment = json.loads(deployment_path.read_text())
    deployment["bindings"]["study_sha256"] = validator.file_sha256(
        tmp_path, "experiments/false_effective/first-formal-real-study.json"
    )
    deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")

    assert validator.validate(tmp_path)["deployment_registration"] == "registered"

    registry_path.write_text(
        json.dumps(json.loads(registry_path.read_text()), indent=2) + "\n"
    )
    with pytest.raises(ValueError, match="registry must be canonical"):
        validator.validate(tmp_path)

    write_canonical_json(
        registry_path,
        {"schema": "ecpa-formal-adapter-registry/v2", "adapters": entries},
    )
    entries[0].pop("evidence_owner")
    write_canonical_json(
        registry_path,
        {"schema": "ecpa-formal-adapter-registry/v2", "adapters": entries},
    )
    deployment = json.loads(deployment_path.read_text())
    deployment["arm_registrations"][0]["registration"]["registry_entry_sha256"] = (
        validator.object_sha256(entries[0])
    )
    deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")
    with pytest.raises(ValueError, match="deployment arm differs"):
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
    value = json.loads(registry.read_text())
    value["adapters"].append({"id": "fake"})
    write_canonical_json(registry, value)

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
