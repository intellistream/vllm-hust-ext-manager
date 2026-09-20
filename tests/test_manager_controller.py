import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

import vllm_hust_ext.manager_controller as controller
from vllm_hust_ext.cli import main
from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ResourceClaim,
    canonical_bytes,
)
from vllm_hust_ext.manager_controller import (
    ACTIVATION_CONTRACT,
    HOST_SINK,
    activation_probe_receipt,
    launch_managed,
    managed_host_environment,
)
from vllm_hust_ext.plan_artifact import (
    PlanArtifactError,
    plan_artifact_bytes,
    read_plan_artifact,
)


def plan() -> Plan:
    return Plan(
        (
            PluginIdentity(
                "org.vllm-hust",
                "bidkv",
                "0.2.0",
                "a" * 64,
            ),
        ),
        HostCompatibility("vllm-hust", "0.11.0", "vllm", "1"),
        (
            ResourceClaim(
                "urn:ecpa:resource:vllm.scheduler.preemption",
                "org.vllm-hust.bidkv",
            ),
        ),
        (
            EvidenceObligation(
                "engine-dispatch", "engine-core-scheduler", "invoked", (0,)
            ),
            EvidenceObligation("worker-load", "worker", "resolved", (0, 1)),
        ),
        PredecessorSnapshot(4, "plan:sha256:" + "b" * 64, {"route": "old"}),
        True,
    )


def write_plan(tmp_path, value: Plan | None = None):
    path = (tmp_path / "plan.json").resolve()
    path.write_bytes(plan_artifact_bytes(value or plan()))
    path.chmod(0o600)
    return path


def test_plan_artifact_round_trip_recomputes_identity(tmp_path) -> None:
    expected = plan()
    artifact = read_plan_artifact(write_plan(tmp_path, expected))

    assert artifact.plan == expected
    assert artifact.plan_id == expected.plan_id
    assert artifact.raw == plan_artifact_bytes(expected)


def test_plan_artifact_matches_candidate_schema() -> None:
    schema_path = Path(__file__).parents[1] / "spec/0.1/execution-plan.schema.json"
    Draft7Validator(json.loads(schema_path.read_text())).validate(
        json.loads(plan_artifact_bytes(plan()))
    )


@pytest.mark.parametrize("mutation", ["identity", "unknown", "noncanonical"])
def test_plan_artifact_rejects_tampering_and_ambiguous_bytes(
    tmp_path, mutation
) -> None:
    path = write_plan(tmp_path)
    value = json.loads(path.read_bytes())
    if mutation == "identity":
        value["plan_id"] = "plan:sha256:" + "0" * 64
        path.write_bytes(canonical_bytes(value) + b"\n")
    elif mutation == "unknown":
        value["plan"]["unreviewed"] = True
        path.write_bytes(canonical_bytes(value) + b"\n")
    else:
        path.write_text(json.dumps(value, indent=2) + "\n")

    with pytest.raises(PlanArtifactError):
        read_plan_artifact(path)


def test_plan_artifact_rejects_symlink_and_unsorted_target_ordinals(tmp_path) -> None:
    path = write_plan(tmp_path)
    link = (tmp_path / "plan-link.json").resolve()
    link.symlink_to(path)
    with pytest.raises(PlanArtifactError, match="absolute and real"):
        read_plan_artifact(link)

    value = json.loads(path.read_bytes())
    value["plan"]["obligations"][1]["required_ordinals"] = [1, 0]
    path.write_bytes(canonical_bytes(value) + b"\n")
    with pytest.raises(PlanArtifactError, match="unique and sorted"):
        read_plan_artifact(path)


def test_plan_artifact_rejects_public_file_and_malformed_plugin_digest(
    tmp_path,
) -> None:
    path = write_plan(tmp_path)
    path.chmod(0o666)
    with pytest.raises(PlanArtifactError, match="private owned"):
        read_plan_artifact(path)

    path.chmod(0o600)
    value = json.loads(path.read_bytes())
    value["plan"]["plugins"][0]["artifact_sha256"] = "not-a-digest"
    path.write_bytes(canonical_bytes(value) + b"\n")
    with pytest.raises(PlanArtifactError, match="SHA-256"):
        read_plan_artifact(path)


def test_manager_owns_host_binding_and_rejects_conflicting_caller_values(
    tmp_path,
) -> None:
    artifact = read_plan_artifact(write_plan(tmp_path))
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o700)
    environment = managed_host_environment(
        {"PATH": "/bin"},
        artifact,
        "launch:one",
        "controller:one",
        journal,
    )

    assert environment["VLLM_ECPA_PLAN_ID"] == artifact.plan_id
    assert environment["VLLM_ECPA_LAUNCH_ID"] == "launch:one"
    assert environment["VLLM_ECPA_EVIDENCE_SINK"] == HOST_SINK
    assert environment["VLLM_ECPA_EVIDENCE_STRICT"] == "1"
    assert environment["ECPA_HOST_EVENT_DIR"] == str(journal)
    assert environment["ECPA_HOST_EVENT_FSYNC"] == "1"
    assert environment["ECPA_CONTROLLER_INSTANCE"] == "controller:one"
    assert environment["ECPA_ACTIVATION_CONTRACT"] == ACTIVATION_CONTRACT

    with pytest.raises(ValueError, match="manager-owned"):
        managed_host_environment(
            {"VLLM_ECPA_PLAN_ID": "caller-value"},
            artifact,
            "launch:one",
            "controller:one",
            journal,
        )
    with pytest.raises(ValueError, match="canonical 'launch:'"):
        managed_host_environment({}, artifact, "launch:", "controller:one", journal)


def test_manager_rejects_public_event_directory_and_wrong_host_plan(tmp_path) -> None:
    artifact = read_plan_artifact(write_plan(tmp_path))
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o777)
    journal.chmod(0o777)
    with pytest.raises(ValueError, match="private and owned"):
        managed_host_environment({}, artifact, "launch:one", "controller:one", journal)

    journal.chmod(0o700)
    wrong = replace(plan(), host=HostCompatibility("other", "1", "other", "1"))
    path = write_plan(tmp_path, wrong)
    with pytest.raises(ValueError, match="vLLM-HUST"):
        launch_managed(
            plan_path=path,
            launch_id="launch:one",
            controller_instance="controller:one",
            host_event_dir=journal,
            command=["true"],
            base_environment={},
        )


def test_invalid_plan_fails_before_target_launch(tmp_path, monkeypatch) -> None:
    path = write_plan(tmp_path)
    value = json.loads(path.read_bytes())
    value["plan_id"] = "forged"
    path.write_bytes(canonical_bytes(value) + b"\n")
    journal = (tmp_path / "events").resolve()
    journal.mkdir()
    monkeypatch.setattr(
        controller.subprocess,
        "call",
        lambda *_args, **_kwargs: pytest.fail("target launched before validation"),
    )

    with pytest.raises(PlanArtifactError, match="does not match"):
        launch_managed(
            plan_path=path,
            launch_id="launch:one",
            controller_instance="controller:one",
            host_event_dir=journal,
            command=["vllm", "serve", "model"],
            base_environment={},
        )


def test_managed_launch_uses_validated_target_and_environment(
    tmp_path, monkeypatch
) -> None:
    path = write_plan(tmp_path)
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o700)
    calls = []
    monkeypatch.setattr(
        controller.subprocess,
        "call",
        lambda command, *, env: calls.append((command, env)) or 17,
    )

    result = launch_managed(
        plan_path=path,
        launch_id="launch:one",
        controller_instance="controller:one",
        host_event_dir=journal,
        command=["vllm", "serve", "model"],
        base_environment={"PATH": "/bin"},
    )

    assert result == 17
    assert calls[0][0] == ["vllm", "serve", "model"]
    assert calls[0][1]["VLLM_ECPA_PLAN_ID"] == plan().plan_id


def test_formal_run_probe_is_canonical_and_does_not_require_launch_inputs(
    capsys,
) -> None:
    assert main(["formal-run", "--ecpa-formal-activation-probe"]) == 0

    assert capsys.readouterr().out.encode() == activation_probe_receipt()


def test_formal_run_dry_run_keeps_manager_options_before_target(
    tmp_path, capsys
) -> None:
    path = write_plan(tmp_path)
    journal = (tmp_path / "events").resolve()
    journal.mkdir(mode=0o700)

    assert (
        main(
            [
                "formal-run",
                "--plan",
                str(path),
                "--launch-id",
                "launch:one",
                "--controller-instance",
                "controller:one",
                "--host-event-dir",
                str(journal),
                "--dry-run",
                "--",
                "vllm",
                "serve",
                "model",
                "--tensor-parallel-size",
                "2",
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)

    assert receipt["schema"] == "ecpa-managed-launch/v1"
    assert receipt["plan_id"] == plan().plan_id
    assert receipt["command"] == [
        "vllm",
        "serve",
        "model",
        "--tensor-parallel-size",
        "2",
    ]
