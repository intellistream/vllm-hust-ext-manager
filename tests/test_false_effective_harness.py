import base64
import copy
import importlib.util
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.plan_artifact import plan_artifact_bytes

ROOT = Path("experiments/false_effective").resolve()
sys.path.insert(0, str(ROOT))

import harness as harness_module  # noqa: E402
import runner as runner_module  # noqa: E402
from harness import (  # noqa: E402
    aggregate,
    canonical,
    conflict_metrics,
    digest_file,
    oracle,
    project_paper_result,
    run_command,
    safe_path,
    sanitized_env,
    validate_batch,
    validate_record,
)
from runner import (  # noqa: E402
    ECPAAdapter,
    ManualIntegrationAdapter,
    VanillaVLLMAdapter,
    command_fingerprint,
    command_references_fixture,
    parse_proc_stat_start_ticks,
    planned_records,
    run_formal_start,
    run_reference_start,
    write_formal_manifest,
)


def scenarios():
    return json.loads((ROOT / "scenarios.json").read_text())["scenarios"]


def planned():
    return planned_records(scenarios())


def activation_probe(adapter, arguments):
    probe_arguments = [
        *arguments,
        *adapter.activation_arguments,
        "--ecpa-formal-activation-probe",
    ]
    fingerprint = command_fingerprint(sys.executable, probe_arguments)
    return {
        "required_options": list(adapter.activation_arguments),
        "timeout_s": 2,
        "command_digest": fingerprint["digest"],
    }


def test_formal_planned_aggregate_has_zero_cells_and_null_metrics(tmp_path):
    result = aggregate(planned(), tmp_path, formal=True)
    assert result["completed_cells"] == 0
    assert result["metrics"] is None


def test_planned_to_complete_without_artifacts_is_rejected(tmp_path):
    record = planned()[0]
    record["status"] = "complete"
    with pytest.raises(ValueError, match="formal complete missing"):
        validate_record(record, tmp_path)


def test_synthetic_cannot_enter_formal_aggregate(tmp_path):
    record = planned()[0]
    record["evidence_class"] = "reference-synthetic"
    with pytest.raises(ValueError, match="synthetic evidence"):
        validate_batch([record], tmp_path, formal=True)


def test_fewer_than_three_starts_and_missing_arm_are_rejected(tmp_path):
    records = planned()[:2]
    for record in records:
        record["status"] = "complete"
        record["command"] = {}
        record["artifacts"] = {
            key: key for key in ("raw_log", "environment", "command", "oracle")
        }
    with pytest.raises(ValueError):
        validate_batch(records, tmp_path, formal=True)


def test_duplicate_start_id_is_rejected(tmp_path):
    records = planned()[:2]
    records[1]["start_id"] = records[0]["start_id"]
    with pytest.raises(ValueError, match="duplicate start_id"):
        validate_batch(records, tmp_path, formal=True)


def formal_complete_records(tmp_path):
    records = []
    protocol = json.loads((ROOT / "protocol.json").read_text())
    scenario = scenarios()[0]
    sut = str(Path("tests/fixtures/formal_sut_service.py").resolve())
    observer = str(Path("tests/fixtures/formal_observer_service.py").resolve())
    adapters = {
        "vanilla-vllm-entry-points": VanillaVLLMAdapter(),
        "manual-integration": ManualIntegrationAdapter(),
        "ecpa": ECPAAdapter(),
    }
    schedule = (
        ("vanilla-vllm-entry-points", "manual-integration", "ecpa"),
        ("manual-integration", "ecpa", "vanilla-vllm-entry-points"),
        ("ecpa", "vanilla-vllm-entry-points", "manual-integration"),
    )
    for repetition, order in enumerate(schedule, 1):
        for arm_order, arm in enumerate(order, 1):
            identity = {
                "arm": arm,
                "model": "same",
                "dataset": "same",
                "workload": "same",
                "hardware": "same",
                "software": {"runtime": "same"},
                "observer": "same",
                "runtime_commit": "same",
                "plugin_commits": [],
                "topology": "same",
                "fault_plan": "same",
                "fault": "same",
                "warm_state": "cold",
                "git_dirty": False,
                "container_digest": "sha256:test",
                "cpu": "test",
                "gpu": "not-applicable",
                "npu": "not-applicable",
                "driver": "test",
                "runtime": "same",
                "semantic_environment": "same",
            }
            record = run_formal_start(
                tmp_path / "formal",
                scenario,
                protocol,
                adapters[arm],
                repetition,
                arm_order,
                executable=sys.executable,
                arguments=[sut],
                observer_executable=sys.executable,
                observer_arguments=[observer],
                identity=identity,
                timeout_s=5,
                fixture_mode=True,
            )
            record["artifact_root"] = f"formal/{record['artifact_root']}"
            records.append(record)
    return records


def test_matched_arm_metadata_mismatch_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["identity"]["model"] = "different"
    with pytest.raises(ValueError, match="relabelled|metadata mismatch|fixture-only"):
        validate_batch(records, tmp_path, formal=True)


def test_unbalanced_order_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["arm_order"] = records[-2]["arm_order"]
    with pytest.raises(
        ValueError, match="relabelled|unbalanced|Latin square|fixture-only"
    ):
        validate_batch(records, tmp_path, formal=True)


def test_missing_is_not_imputed_to_zero(tmp_path):
    result = aggregate(planned(), tmp_path, formal=True)
    assert result["metrics"] is None
    assert "no validator-approved" in result["reason"]


def test_oracle_rejects_sut_truth_fields():
    scenario = scenarios()[0]
    record = {
        "observations": [{"event": "claim", "false_effective": False}],
        "artifacts": {},
    }
    with pytest.raises(ValueError, match="oracle-owned"):
        oracle(scenario, record)


def test_path_escape_and_secret_redaction(tmp_path):
    with pytest.raises(ValueError, match="escapes"):
        safe_path(tmp_path, "../secret")
    manifest = sanitized_env({"PATH": "/bin", "API_TOKEN": "do-not-print"})
    assert manifest["PATH"] == "/bin"
    assert manifest["API_TOKEN"]["redacted"] is True
    assert "do-not-print" not in json.dumps(manifest)


@pytest.mark.parametrize(
    ("argv", "failed"),
    [
        ([sys.executable, "-c", "raise SystemExit(7)"], True),
        ([sys.executable, "-c", "import time; time.sleep(1)"], True),
    ],
)
def test_nonzero_and_timeout_preserve_raw_command_record(tmp_path, argv, failed):
    result = run_command(
        tmp_path / ("timeout" if "sleep" in argv[-1] else "nonzero"),
        argv,
        env=dict(os.environ),
        timeout_s=0.05,
    )
    assert result["timeout"] or result["exit_code"] == 7
    assert (Path(result["cwd"]) / result["stdout"]).is_file()
    assert (Path(result["cwd"]) / "command.json").is_file()
    assert failed


def test_digest_tamper_is_rejected(tmp_path):
    path = tmp_path / "raw"
    path.write_text("before")
    record = {
        "schema": "ecpa-false-effective-start/v1",
        "status": "failed",
        "evidence_class": "unit-selftest",
        "measurement_source": "test",
        "cell_id": "x",
        "scenario": "x",
        "arm": "ecpa",
        "start_id": "x",
        "repetition": 1,
        "arm_order": 1,
        "identity": {},
        "command": {},
        "artifacts": {"digests": {"raw": digest_file(path)}},
        "observations": [],
        "missing_reason": None,
    }
    path.write_text("after")
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_record(record, tmp_path)


def test_reproduce_checked_deterministic_outputs(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "false_effective_reproduce", ROOT / "reproduce.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "output"
    summary = module.generate(output)
    assert summary["starts"] == 45
    assert summary["formal_completed_cells"] == 0
    checked = ROOT / "artifacts"
    for name in (
        "formal-aggregate-summary.json",
        "paper-table.csv",
        "reference-summary.json",
    ):
        assert (output / name).read_bytes() == (checked / name).read_bytes()


def test_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError):
        canonical({"bad": float("nan")})


def test_conflict_arm_summary_counts_fp_and_fn():
    rows = [
        {"conflict_truth": "conflict", "conflict_decision": "reject"},
        {"conflict_truth": "conflict", "conflict_decision": "accept"},
        {"conflict_truth": "compatible", "conflict_decision": "reject"},
        {"conflict_truth": "conditional", "conflict_decision": "conditional"},
    ]
    result = conflict_metrics(rows)
    assert result["confusion"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
    assert result["precision"] is None
    assert result["recall"] is None


def test_raw_record_schema_accepts_planned_and_forbids_sut_truth():
    schema = json.loads((ROOT / "raw-record.schema.json").read_text())
    Draft7Validator(schema).validate(planned()[0])
    invalid = planned()[0]
    invalid["observations"] = [{"event": "bad", "truth": True}]
    assert list(Draft7Validator(schema).iter_errors(invalid))


def test_reference_record_relabelled_formal_is_rejected(tmp_path):
    record = run_reference_start(tmp_path, scenarios()[0], "ecpa", 1, 3)
    record["evidence_class"] = "formal-real"
    with pytest.raises(ValueError, match="relabelled"):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )


def test_missing_required_observation_is_incomplete_and_null():
    scenario = scenarios()[0]
    record = {"observations": [], "artifacts": {}, "command": {}}
    result = oracle(scenario, record)
    assert result["verdict"] == "INCOMPLETE"
    assert result["outcome"]["activation_event_coverage"] is None


def test_failed_safe_is_not_counted_as_rollback_success():
    scenario = next(row for row in scenarios() if row["id"] == "rollback-failure")
    record = {
        "observations": [
            {"event": name, "value": True} for name in scenario["expected_observable"]
        ]
        + [{"event": "rollback-class", "value": "FAILED_SAFE"}],
        "artifacts": {},
        "command": {},
    }
    assert oracle(scenario, record)["outcome"]["rollback_success"] is False


def test_planned_projection_validates_paper_schema():
    schema = json.loads(Path("paper/artifacts/results.schema.json").read_text())
    result = project_paper_result(planned()[0], schema)
    assert result["schema"] == "ecpa-result/v1"
    assert result["status"] == "planned"
    assert result["outcome"]["false_effective"] is None


@pytest.mark.parametrize("missing", ["effective-claim", "plugin-invoked"])
def test_core_claim_observations_are_mandatory(missing):
    scenario = scenarios()[0]
    events = [
        {"event": name, "value": True}
        for name in scenario["expected_observable"]
        + [
            "service-ready",
            "workload-complete",
            "fault-injected",
            "observer-captured",
            "effective-claim",
            "plugin-invoked",
            "service-shutdown",
        ]
        if name != missing
    ]
    result = oracle(scenario, {"observations": events, "artifacts": {}, "command": {}})
    assert result["verdict"] == "INCOMPLETE"
    assert any(missing in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "failed"),
        ("cell_id", "forged"),
    ],
)
def test_runner_receipt_rejects_core_relabel(tmp_path, field, value):
    record = run_reference_start(tmp_path, scenarios()[0], "ecpa", 1, 3)
    record[field] = value
    with pytest.raises(ValueError):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )


def test_disk_command_and_oracle_are_exactly_bound(tmp_path):
    record = run_reference_start(tmp_path, scenarios()[0], "ecpa", 1, 3)
    run_dir = tmp_path / record["artifact_root"]
    record["command"]["exit_code"] = 9
    with pytest.raises(ValueError, match="command|oracle|receipt"):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )
    assert (run_dir / "oracle.json").is_file()


def test_formal_sut_cannot_write_trusted_result(tmp_path):
    record = formal_complete_records(tmp_path)[0]
    run_dir = tmp_path / record["artifact_root"]
    sut_environment = json.loads((run_dir / "sut-environment.json").read_text())
    assert not any(name.startswith("ECPA_OBSERVER_") for name in sut_environment)
    assert not any(name.startswith("ECPA_RUNNER_") for name in sut_environment)
    assert (
        record["command"]["sut_process"]["pid"]
        != record["command"]["observer_process"]["pid"]
    )
    assert (
        record["observer_binding"]["pid"]
        == record["command"]["observer_process"]["pid"]
    )


def test_pid_reuse_identity_mutation_is_rejected(tmp_path):
    record = formal_complete_records(tmp_path)[0]
    record["command"]["observer_process"]["linux_identity"]["start_ticks"] += 1
    with pytest.raises(ValueError, match="identity"):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )


def test_frozen_registry_is_present_even_for_partial_input(tmp_path):
    result = aggregate(planned()[:1], tmp_path, formal=True)
    assert len(result["cells"]) == len(scenarios()) * 3


def test_interface_observer_ignores_plain_stdout_and_captures_lifecycle(tmp_path):
    records = formal_complete_records(tmp_path)
    record = records[0]
    assert record["status"] == "complete"
    assert record["evidence_class"] == "interface-fixture"
    assert record["measurement_source"] == "controlled-interface-observer"
    events = [item["event"] for item in record["observations"]]
    assert events.index("service-ready") < events.index("workload-complete")
    assert events.index("workload-complete") < events.index("fault-injected")
    assert events.index("fault-injected") < events.index("observer-captured")
    assert events.index("observer-captured") < events.index("service-shutdown")
    assert (
        record["command"]["sut_process"]["argv"]
        != record["command"]["observer_process"]["argv"]
    )


def test_arm_launch_contracts_are_distinct_and_auditable():
    adapters = [VanillaVLLMAdapter(), ManualIntegrationAdapter(), ECPAAdapter()]
    launches = [adapter.launch("service", [], {}) for adapter in adapters]
    assert len({env["ECPA_ACTIVATION_CONTRACT"] for _, env in launches}) == 3
    assert len({tuple(argv) for argv, _ in launches}) == 3
    assert any("--enable-ecpa-manager" in argv for argv, _ in launches)
    assert {env["ECPA_EVALUATION_ARM"] for _, env in launches} == {
        adapter.arm for adapter in adapters
    }


def _write_formal_execution_plan(tmp_path: Path) -> Path:
    plan = Plan(
        (PluginIdentity("org.vllm-hust", "formal", "0.1.0", "a" * 64),),
        HostCompatibility("vllm-hust", "0.11.0", "vllm", "1"),
        (),
        (EvidenceObligation("worker-load", "worker", "resolved", (0,)),),
        PredecessorSnapshot(0, None, {}),
        True,
    )
    path = (tmp_path / "plan.json").resolve()
    path.write_bytes(plan_artifact_bytes(plan))
    path.chmod(0o600)
    return path


def test_ecpa_managed_launch_uses_real_formal_run_and_manager_owned_identity(tmp_path):
    plan_path = _write_formal_execution_plan(tmp_path)
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    adapter = ECPAAdapter()
    manager = str(Path(sys.executable).with_name("vllm-hust-ext"))
    argv, env, binding = adapter.managed_launch(
        manager_executable=manager,
        plan_path=plan_path,
        launch_id="launch:test",
        controller_instance="controller:test",
        host_event_dir=event_dir,
        target_argv=[sys.executable, "-c", "raise SystemExit(99)"],
        env=dict(os.environ),
        dry_run=True,
    )

    assert "--enable-ecpa-manager" not in argv
    assert "--disable-entrypoints" not in argv
    assert argv[-3:] == [sys.executable, "-c", "raise SystemExit(99)"]
    assert not runner_module.CONTROLLED_ENVIRONMENT.intersection(env)
    completed = subprocess.run(argv, env=env, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["schema"] == "ecpa-managed-launch/v1"
    assert receipt["command"] == binding["target_argv"]
    assert receipt["plan_id"] == binding["plan_id"]
    assert receipt["controller_instance"] == "controller:test"


def test_ecpa_managed_launch_rejects_runner_owned_host_identity(tmp_path):
    plan_path = _write_formal_execution_plan(tmp_path)
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="manager-owned"):
        ECPAAdapter().managed_launch(
            manager_executable=str(Path(sys.executable).with_name("vllm-hust-ext")),
            plan_path=plan_path,
            launch_id="launch:test",
            controller_instance="controller:test",
            host_event_dir=event_dir,
            target_argv=[sys.executable, "-c", "pass"],
            env={"VLLM_ECPA_PLAN_ID": "forged"},
        )


def test_ecpa_managed_launch_propagates_host_owned_binding_to_target(tmp_path):
    plan_path = _write_formal_execution_plan(tmp_path)
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    target = (
        "import json,os; print(json.dumps({k:os.environ[k] for k in "
        "['VLLM_ECPA_PLAN_ID','VLLM_ECPA_LAUNCH_ID',"
        "'VLLM_ECPA_EVIDENCE_STRICT','ECPA_CONTROLLER_INSTANCE',"
        "'ECPA_ACTIVATION_CONTRACT']},sort_keys=True))"
    )
    argv, env, binding = ECPAAdapter().managed_launch(
        manager_executable=str(Path(sys.executable).with_name("vllm-hust-ext")),
        plan_path=plan_path,
        launch_id="launch:real-path-test",
        controller_instance="controller:real-path-test",
        host_event_dir=event_dir,
        target_argv=[sys.executable, "-c", target],
        env=dict(os.environ),
    )

    completed = subprocess.run(argv, env=env, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    received = json.loads(completed.stdout)
    assert received == {
        "ECPA_ACTIVATION_CONTRACT": "manager-controlled-activation",
        "ECPA_CONTROLLER_INSTANCE": "controller:real-path-test",
        "VLLM_ECPA_EVIDENCE_STRICT": "1",
        "VLLM_ECPA_LAUNCH_ID": "launch:real-path-test",
        "VLLM_ECPA_PLAN_ID": binding["plan_id"],
    }


def test_ecpa_managed_launch_snapshots_plan_before_original_is_replaced(tmp_path):
    original = _write_formal_execution_plan(tmp_path)
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    argv, env, binding = ECPAAdapter().managed_launch(
        manager_executable=str(Path(sys.executable).with_name("vllm-hust-ext")),
        plan_path=original,
        launch_id="launch:snapshot-test",
        controller_instance="controller:snapshot-test",
        host_event_dir=event_dir,
        target_argv=[sys.executable, "-c", "raise SystemExit(99)"],
        env=dict(os.environ),
        dry_run=True,
    )
    replacement = replace(
        Plan(
            (PluginIdentity("org.vllm-hust", "formal", "0.1.0", "a" * 64),),
            HostCompatibility("vllm-hust", "0.11.0", "vllm", "1"),
            (),
            (EvidenceObligation("worker-load", "worker", "resolved", (0,)),),
            PredecessorSnapshot(0, None, {}),
            True,
        ),
        plugins=(PluginIdentity("org.vllm-hust", "replacement", "0.1.0", "b" * 64),),
    )
    original.write_bytes(plan_artifact_bytes(replacement))
    original.chmod(0o600)

    snapshot = Path(binding["plan_path"])
    assert snapshot != original
    assert snapshot.read_bytes() != original.read_bytes()
    assert snapshot.stat().st_mode & 0o777 == 0o400
    assert snapshot.parent.stat().st_mode & 0o777 == 0o500
    completed = subprocess.run(argv, env=env, text=True, capture_output=True)
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["plan_id"] == binding["plan_id"]
    assert receipt["plan_id"] != replacement.plan_id


def test_ecpa_managed_launch_has_no_injectable_manager_argument_prefix():
    assert "manager_arguments" not in ECPAAdapter.managed_launch.__annotations__


def _minimal_formal_identity() -> dict:
    return {
        "model": "test",
        "dataset": "test",
        "workload": "test",
        "software": {"runtime": "test"},
        "observer": "host-event-stream/v1",
        "plugin_commits": [],
        "topology": "single",
        "fault_plan": "test",
        "fault": "test",
        "warm_state": "cold",
        "container_digest": "sha256:test",
        "gpu": "not-applicable",
        "npu": "not-applicable",
        "driver": "test",
        "required_processes": [
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 7,
            }
        ],
    }


def test_real_formal_rejects_caller_assertion_and_empty_registry(tmp_path):
    kwargs = {
        "root": tmp_path,
        "scenario": scenarios()[0],
        "protocol": json.loads((ROOT / "protocol.json").read_text()),
        "adapter": ECPAAdapter(),
        "repetition": 1,
        "arm_order": 3,
        "executable": sys.executable,
        "arguments": [str(Path("tests/fixtures/formal_sut_service.py").resolve())],
        "observer_executable": sys.executable,
        "observer_arguments": [
            str(Path("tests/fixtures/formal_observer_service.py").resolve())
        ],
        "timeout_s": 1,
    }
    with pytest.raises(ValueError, match="registry verification id"):
        run_formal_start(identity=_minimal_formal_identity(), **kwargs)
    asserted = _minimal_formal_identity() | {"adapter_contract_verified": True}
    with pytest.raises(ValueError, match="caller-declared"):
        run_formal_start(identity=asserted, **kwargs)


@pytest.mark.parametrize(
    "snapshot,error",
    [
        (None, "target process snapshot is missing"),
        ([], "target process snapshot is missing"),
        (
            [
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": False,
                    "process_epoch": 7,
                }
            ],
            "target process snapshot is malformed",
        ),
        (
            [
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                    "unexpected": True,
                }
            ],
            "target process snapshot is malformed",
        ),
        (
            [
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
            ],
            "target process snapshot contains duplicates",
        ),
        (
            [
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 8,
                },
            ],
            "target process snapshot contains duplicates",
        ),
        (
            [
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 1,
                    "process_epoch": 7,
                },
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
            ],
            "target process snapshot is not canonical",
        ),
    ],
)
def test_real_formal_rejects_invalid_target_snapshot_before_adapter_probe(
    tmp_path, monkeypatch, snapshot, error
):
    monkeypatch.setattr(
        runner_module,
        "verified_adapter_contract",
        lambda *args, **kwargs: pytest.fail(
            "adapter probe ran before target validation"
        ),
    )
    identity = _minimal_formal_identity()
    if snapshot is None:
        identity.pop("required_processes")
    else:
        identity["required_processes"] = snapshot
    with pytest.raises(ValueError, match=error):
        run_formal_start(
            tmp_path,
            scenarios()[0],
            json.loads((ROOT / "protocol.json").read_text()),
            ECPAAdapter(),
            1,
            3,
            executable=sys.executable,
            arguments=["unused"],
            observer_executable=sys.executable,
            observer_arguments=["unused-observer"],
            identity=identity,
            timeout_s=1,
            adapter_verification_id="reviewed",
        )


def test_adapter_probe_cannot_mutate_runner_owned_identity_or_plan(
    tmp_path, monkeypatch
):
    protocol = json.loads((ROOT / "protocol.json").read_text())
    scenario = scenarios()[0]
    adapter = ECPAAdapter()
    caller_identity = _minimal_formal_identity()
    declared_before_probe = copy.deepcopy(caller_identity)
    verification = {"verification_id": "reviewed"}

    def mutate_caller_during_probe(*args, **kwargs):
        caller_identity["required_processes"].append(
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 8,
            }
        )
        caller_identity["software"]["runtime"] = "mutated-during-probe"
        return verification

    monkeypatch.setattr(
        runner_module, "verified_adapter_contract", mutate_caller_during_probe
    )
    monkeypatch.setattr(runner_module, "_run_start", lambda *args, **kwargs: kwargs)
    captured = run_formal_start(
        tmp_path,
        scenario,
        protocol,
        adapter,
        1,
        3,
        executable=sys.executable,
        arguments=["unused"],
        observer_executable=sys.executable,
        observer_arguments=["unused-observer"],
        identity=caller_identity,
        timeout_s=1,
        adapter_verification_id="reviewed",
    )

    assert len(caller_identity["required_processes"]) == 2
    assert (
        captured["identity"]["required_processes"]
        == declared_before_probe["required_processes"]
    )
    assert captured["identity"]["software"] == declared_before_probe["software"]
    frozen_declared = declared_before_probe | {
        "fixture_only": False,
        "adapter_verification": verification,
    }
    expected_plan = {
        "protocol_digest": harness_module.digest_bytes(canonical(protocol)),
        "scenario_digest": harness_module.digest_bytes(canonical(scenario)),
        "arm": adapter.arm,
        "activation_contract": adapter.activation_contract,
        "declared_identity": frozen_declared,
    }
    assert captured["execution_identity"]["plan_id"] == harness_module.digest_bytes(
        canonical(expected_plan)
    )


def test_verified_adapter_registry_pins_commands_and_rejects_fixture_symlink(
    tmp_path, monkeypatch
):
    sut = tmp_path / "sut.py"
    observer = tmp_path / "observer.py"
    sut_source = """import argparse
import json
parser = argparse.ArgumentParser()
parser.add_argument('--enable-ecpa-manager', action='store_true')
parser.add_argument('--disable-entrypoints', action='store_true')
parser.add_argument('--ecpa-formal-activation-probe', action='store_true')
args = parser.parse_args()
if args.ecpa_formal_activation_probe:
    receipt = {
        'schema': 'ecpa-activation-probe/v1',
        'activation_contract': 'manager-controlled-activation',
        'accepted_options': ['--disable-entrypoints', '--enable-ecpa-manager'],
    }
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
"""
    sut.write_text(sut_source)
    observer.write_text("print('observer')\n")
    adapter = ECPAAdapter()
    sut_fingerprint = command_fingerprint(
        sys.executable, [str(sut), *adapter.activation_arguments]
    )
    observer_fingerprint = command_fingerprint(sys.executable, [str(observer)])
    registry = {
        "schema": "ecpa-formal-adapter-registry/v1",
        "adapters": [
            {
                "id": "test-host-v1",
                "arm": adapter.arm,
                "activation_contract": adapter.activation_contract,
                "evidence_owner": "vllm-hust-host",
                "evidence_channel": "host-owned-event-stream",
                "host_event_schema": "ecpa-host-runtime-evidence/v1",
                "required_observables": sorted(runner_module.FORMAL_HOST_OBSERVABLES),
                "sut_command_digest": sut_fingerprint["digest"],
                "observer_command_digest": observer_fingerprint["digest"],
                "activation_probe": activation_probe(adapter, [str(sut)]),
            }
        ],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(runner_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    verified = runner_module.verified_adapter_contract(
        "test-host-v1",
        adapter,
        sys.executable,
        [str(sut)],
        sys.executable,
        [str(observer)],
    )
    assert verified["sut_command"] == sut_fingerprint
    rejected_sources = [
        "print('--enable-ecpa-manager --disable-entrypoints')\n",
        """import argparse
import json
parser = argparse.ArgumentParser()
parser.add_argument('--enable-ecpa-manager', action='store_true')
parser.add_argument('--disable-entrypoints', action='store_true')
parser.add_argument('--ecpa-formal-activation-probe', action='store_true')
parser.parse_args()
receipt = {
    'schema': 'ecpa-activation-probe/v1',
    'activation_contract': 'manager-controlled-activation',
    'accepted_options': ['--disable-entrypoints', '--enable-ecpa-manager'],
}
print(json.dumps(receipt, indent=2))
""",
        """import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--enable-ecpa-manager-evil', action='store_true')
parser.add_argument('--disable-entrypoints-other', action='store_true')
parser.add_argument('--ecpa-formal-activation-probe', action='store_true')
parser.parse_args()
""",
        """import sys
sys.stdout.write('{\"accepted_options\":[\"--disable-entry')
sys.stderr.write('points\",\"--enable-ecpa-manager\"]}')
""",
        "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024 + 1))\n",
    ]
    for rejected_source in rejected_sources:
        sut.write_text(rejected_source)
        broken_probe = copy.deepcopy(registry)
        broken_sut = command_fingerprint(
            sys.executable, [str(sut), *adapter.activation_arguments]
        )
        broken_arguments = [
            str(sut),
            *adapter.activation_arguments,
            "--ecpa-formal-activation-probe",
        ]
        broken_probe["adapters"][0]["sut_command_digest"] = broken_sut["digest"]
        broken_probe["adapters"][0]["activation_probe"]["command_digest"] = (
            command_fingerprint(sys.executable, broken_arguments)["digest"]
        )
        registry_path.write_bytes(canonical(broken_probe) + b"\n")
        with pytest.raises(
            ValueError, match="JSON receipt|does not expose|output exceeds"
        ):
            runner_module.verified_adapter_contract(
                "test-host-v1",
                adapter,
                sys.executable,
                [str(sut)],
                sys.executable,
                [str(observer)],
            )
    descendant_pid_file = tmp_path / "probe-descendant.pid"
    sut.write_text(
        "import subprocess, sys\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(60)'])\n"
        f"Path({str(descendant_pid_file)!r}).write_text(str(child.pid))\n"
    )
    descendant_probe = copy.deepcopy(registry)
    descendant_sut = command_fingerprint(
        sys.executable, [str(sut), *adapter.activation_arguments]
    )
    descendant_arguments = [
        str(sut),
        *adapter.activation_arguments,
        "--ecpa-formal-activation-probe",
    ]
    descendant_probe["adapters"][0]["sut_command_digest"] = descendant_sut["digest"]
    descendant_probe["adapters"][0]["activation_probe"]["command_digest"] = (
        command_fingerprint(sys.executable, descendant_arguments)["digest"]
    )
    registry_path.write_bytes(canonical(descendant_probe) + b"\n")
    with pytest.raises(ValueError, match="did not complete"):
        runner_module.verified_adapter_contract(
            "test-host-v1",
            adapter,
            sys.executable,
            [str(sut)],
            sys.executable,
            [str(observer)],
        )
    descendant_pid = int(descendant_pid_file.read_text())
    descendant_stat = Path(f"/proc/{descendant_pid}/stat")
    for _ in range(200):
        try:
            stat_text = descendant_stat.read_text()
        except FileNotFoundError:
            break
        state = stat_text.rsplit(")", 1)[1].split()[0]
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail(f"activation probe descendant {descendant_pid} survived cleanup")
    sut.write_text(sut_source)
    registry_path.write_bytes(canonical(registry) + b"\n")
    observer.write_text("print('changed')\n")
    with pytest.raises(ValueError, match="observer command"):
        runner_module.verified_adapter_contract(
            "test-host-v1",
            adapter,
            sys.executable,
            [str(sut)],
            sys.executable,
            [str(observer)],
        )

    fixture_link = tmp_path / "renamed-sut.py"
    fixture_link.symlink_to(Path("tests/fixtures/formal_sut_service.py").resolve())
    with pytest.raises(ValueError, match="fixture-referencing"):
        runner_module.verified_adapter_contract(
            "test-host-v1",
            adapter,
            sys.executable,
            [str(fixture_link)],
            sys.executable,
            [str(observer)],
        )


def test_offline_validator_rechecks_registry_and_executed_commands(
    tmp_path, monkeypatch
):
    sut = tmp_path / "sut.py"
    observer = tmp_path / "observer.py"
    sut.write_text("""import argparse
import json
parser = argparse.ArgumentParser()
parser.add_argument('--enable-ecpa-manager', action='store_true')
parser.add_argument('--disable-entrypoints', action='store_true')
parser.add_argument('--ecpa-formal-activation-probe', action='store_true')
args = parser.parse_args()
if args.ecpa_formal_activation_probe:
    receipt = {
        'schema': 'ecpa-activation-probe/v1',
        'activation_contract': 'manager-controlled-activation',
        'accepted_options': ['--disable-entrypoints', '--enable-ecpa-manager'],
    }
    print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
""")
    observer.write_text("print('observer')\n")
    adapter = ECPAAdapter()
    sut_arguments = [str(sut), *adapter.activation_arguments]
    observer_arguments = [str(observer)]
    sut_fingerprint = command_fingerprint(sys.executable, sut_arguments)
    observer_fingerprint = command_fingerprint(sys.executable, observer_arguments)
    registry = {
        "schema": "ecpa-formal-adapter-registry/v1",
        "adapters": [
            {
                "id": "test-host-v1",
                "arm": adapter.arm,
                "activation_contract": adapter.activation_contract,
                "evidence_owner": "vllm-hust-host",
                "evidence_channel": "host-owned-event-stream",
                "host_event_schema": "ecpa-host-runtime-evidence/v1",
                "required_observables": sorted(runner_module.FORMAL_HOST_OBSERVABLES),
                "sut_command_digest": sut_fingerprint["digest"],
                "observer_command_digest": observer_fingerprint["digest"],
                "activation_probe": activation_probe(adapter, [str(sut)]),
            }
        ],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(runner_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    monkeypatch.setattr(harness_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    verification = runner_module.verified_adapter_contract(
        "test-host-v1",
        adapter,
        sys.executable,
        [str(sut)],
        sys.executable,
        observer_arguments,
    )
    record = {
        "arm": adapter.arm,
        "identity": {"adapter_verification": verification},
    }
    command = {
        "argv": [sys.executable, *sut_arguments],
        "sut_process": {"argv": [sys.executable, *sut_arguments]},
        "observer_process": {"argv": [sys.executable, *observer_arguments]},
    }
    harness_module.validate_formal_adapter_verification(record, command)

    tampered = copy.deepcopy(record)
    tampered["identity"]["adapter_verification"]["registry_digest"] = "sha256:fake"
    with pytest.raises(ValueError, match="metadata differs"):
        harness_module.validate_formal_adapter_verification(tampered, command)
    tampered = copy.deepcopy(record)
    tampered["identity"]["adapter_verification"]["activation_probe"][
        "stdout_base64"
    ] = "not-base64!"
    with pytest.raises(ValueError, match="probe bytes are invalid"):
        harness_module.validate_formal_adapter_verification(tampered, command)
    tampered = copy.deepcopy(record)
    tampered["identity"]["adapter_verification"]["activation_probe"][
        "stdout_base64"
    ] = base64.b64encode(b"forged --enable-ecpa-manager").decode()
    with pytest.raises(ValueError, match="metadata differs|does not satisfy"):
        harness_module.validate_formal_adapter_verification(tampered, command)
    changed_command = copy.deepcopy(command)
    changed_command["sut_process"]["argv"][-1] = "--different"
    with pytest.raises(ValueError, match="executed SUT argv"):
        harness_module.validate_formal_adapter_verification(record, changed_command)

    fixture_sut = Path("tests/fixtures/formal_sut_service.py").resolve()
    fixture_observer = Path("tests/fixtures/formal_observer_service.py").resolve()
    fixture_sut_arguments = [str(fixture_sut), *adapter.activation_arguments]
    fixture_observer_arguments = [str(fixture_observer)]
    fixture_sut_fingerprint = command_fingerprint(sys.executable, fixture_sut_arguments)
    fixture_observer_fingerprint = command_fingerprint(
        sys.executable, fixture_observer_arguments
    )
    fixture_registry = copy.deepcopy(registry)
    fixture_entry = fixture_registry["adapters"][0]
    fixture_entry["sut_command_digest"] = fixture_sut_fingerprint["digest"]
    fixture_entry["observer_command_digest"] = fixture_observer_fingerprint["digest"]
    registry_path.write_bytes(canonical(fixture_registry) + b"\n")
    fixture_verification = {
        **verification,
        "registry_digest": harness_module.digest_bytes(registry_path.read_bytes()),
        "sut_command": fixture_sut_fingerprint,
        "observer_command": fixture_observer_fingerprint,
    }
    fixture_record = {
        "arm": adapter.arm,
        "identity": {"adapter_verification": fixture_verification},
    }
    fixture_command = {
        "argv": [sys.executable, *fixture_sut_arguments],
        "sut_process": {"argv": [sys.executable, *fixture_sut_arguments]},
        "observer_process": {"argv": [sys.executable, *fixture_observer_arguments]},
    }
    with pytest.raises(ValueError, match="fixture-referencing"):
        harness_module.validate_formal_adapter_verification(
            fixture_record, fixture_command
        )


def test_interpreter_indirection_cannot_hide_fixture_commands(tmp_path, monkeypatch):
    adapter = ECPAAdapter()
    sut_fixture = Path("tests/fixtures/formal_sut_service.py").resolve()
    observer_fixture = Path("tests/fixtures/formal_observer_service.py").resolve()
    sut_source = (
        f"exec(compile(open({str(sut_fixture)!r},'rb').read(),"
        f"{str(sut_fixture)!r},'exec'))"
    )
    observer_source = (
        f"exec(compile(open({str(observer_fixture)!r},'rb').read(),"
        f"{str(observer_fixture)!r},'exec'))"
    )
    sut_arguments = ["-c", sut_source, *adapter.activation_arguments]
    observer_arguments = ["-c", observer_source]
    assert command_references_fixture(
        [sys.executable, *sut_arguments, sys.executable, *observer_arguments]
    )
    sut_fingerprint = command_fingerprint(sys.executable, sut_arguments)
    observer_fingerprint = command_fingerprint(sys.executable, observer_arguments)
    registry = {
        "schema": "ecpa-formal-adapter-registry/v1",
        "adapters": [
            {
                "id": "indirect-fixture",
                "arm": adapter.arm,
                "activation_contract": adapter.activation_contract,
                "evidence_owner": "vllm-hust-host",
                "evidence_channel": "host-owned-event-stream",
                "host_event_schema": "ecpa-host-runtime-evidence/v1",
                "required_observables": sorted(runner_module.FORMAL_HOST_OBSERVABLES),
                "sut_command_digest": sut_fingerprint["digest"],
                "observer_command_digest": observer_fingerprint["digest"],
                "activation_probe": activation_probe(adapter, ["-c", sut_source]),
            }
        ],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(runner_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    with pytest.raises(ValueError, match="fixture-referencing"):
        runner_module.verified_adapter_contract(
            "indirect-fixture",
            adapter,
            sys.executable,
            ["-c", sut_source],
            sys.executable,
            observer_arguments,
        )


def test_fixture_evidence_is_nonformal_and_execution_identity_is_bound(tmp_path):
    record = formal_complete_records(tmp_path)[0]
    run_dir = tmp_path / record["artifact_root"]
    assert record["evidence_class"] == "interface-fixture"
    assert record["identity"]["adapter_verification"] is None
    assert not (run_dir / "sut-telemetry.json").exists()
    assert not (tmp_path / "formal" / "formal-record-index.json").exists()
    execution = record["command"]["execution_identity"]
    assert set(execution) == {"plan_id", "launch_id", "controller_instance"}
    invocation_ids = {
        item["invocation_id"] for item in record["command"]["phase_invocations"]
    }
    assert len(invocation_ids) == 5
    assert all(
        event["launch_id"] == execution["launch_id"] for event in record["observations"]
    )
    assert all(
        event["sut_process_identity"]
        == record["command"]["sut_process"]["linux_identity"]
        for event in record["observations"]
    )
    counterexample = copy.deepcopy(record)
    counterexample["observations"][0]["launch_id"] = "launch:replayed"
    assert oracle(scenarios()[0], counterexample)["verdict"] == "INCOMPLETE"
    with pytest.raises(ValueError, match="fixture-only"):
        validate_batch([record], tmp_path, formal=True)


def test_runner_seals_inconsistent_observer_ack_as_failed(tmp_path):
    observer = tmp_path / "inconsistent_observer.py"
    observer.write_text(
        """import json, os, sys
from pathlib import Path
pid = int(os.environ['ECPA_SUT_PID'])
stat = Path(f'/proc/{pid}/stat').read_text()
close = stat.rfind(')')
ticks = int(stat[close + 2:].split()[19])
argv_bytes = Path(f'/proc/{pid}/cmdline').read_bytes()
argv = [
    part.decode(errors='surrogateescape')
    for part in argv_bytes.split(b'\\0')
    if part
]
identity = {'pid': pid, 'start_ticks': ticks, 'argv': argv}
events = []
for raw in sys.stdin:
    message = json.loads(raw)
    common = {
        'source_role': 'interface-observer', 'clock': 'monotonic',
        'monotonic_ns': message['monotonic_ns'],
        'plan_id': message['plan_id'], 'launch_id': message['launch_id'],
        'controller_instance': message['controller_instance'],
        'invocation_id': message['invocation_id'], 'sequence': 999,
        'challenge': 'wrong', 'causal_ack': False,
        'sut_process_identity': identity,
    }
    phase = message['phase']
    value = message['scenario'] if phase == 'fault-injected' else True
    events.append({'event': phase, 'value': value, **common})
    if phase == 'observer-captured':
        for name, value in (
            ('activation-path', os.environ['ECPA_EXPECTED_CONTRACT']),
            ('effective-claim', False), ('plugin-invoked', False),
            ('service_started', True), ('plugin_not_invoked', True),
        ):
            events.append({'event': name, 'value': value, **common})
os.write(int(os.environ['ECPA_OBSERVER_FD']), json.dumps({'events': events}).encode())
"""
    )
    record = run_formal_start(
        tmp_path / "formal",
        scenarios()[0],
        json.loads((ROOT / "protocol.json").read_text()),
        ECPAAdapter(),
        1,
        3,
        executable=sys.executable,
        arguments=[str(Path("tests/fixtures/formal_sut_service.py").resolve())],
        observer_executable=sys.executable,
        observer_arguments=[str(observer)],
        identity=_minimal_formal_identity(),
        timeout_s=2,
        fixture_mode=True,
    )
    assert record["status"] == "failed"
    assert record["oracle"]["verdict"] == "INCOMPLETE"
    assert any(
        "causal acknowledgement mismatch" in reason
        for reason in record["oracle"]["reasons"]
    )


def test_exact_observer_pipe_bytes_are_bound_independently(tmp_path):
    record = formal_complete_records(tmp_path)[0]
    run_dir = tmp_path / record["artifact_root"]
    pipe = run_dir / record["artifacts"]["observer_pipe"]
    pipe.write_bytes(pipe.read_bytes() + b" ")
    record["artifacts"]["digests"]["observer-pipe.bin"] = digest_file(pipe)
    with pytest.raises(ValueError, match="observer pipe bytes"):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )


def test_semantic_environment_is_runner_measured(tmp_path, monkeypatch):
    monkeypatch.setenv("VLLM_USE_V1", "1")
    record = run_reference_start(tmp_path, scenarios()[0], "ecpa", 1, 3)
    assert record["identity"]["semantic_environment"]["VLLM_USE_V1"] == "1"
    manifest = json.loads(
        (tmp_path / record["artifact_root"] / "environment.json").read_text()
    )
    assert manifest["VLLM_USE_V1"] == "1"


def test_oracle_mutation_is_rejected(tmp_path):
    record = run_reference_start(tmp_path, scenarios()[0], "ecpa", 1, 3)
    record["oracle"]["outcome"]["false_effective"] = True
    with pytest.raises(ValueError, match="oracle"):
        validate_record(
            record,
            tmp_path,
            scenario=scenarios()[0],
            protocol=json.loads((ROOT / "protocol.json").read_text()),
            schema=json.loads((ROOT / "raw-record.schema.json").read_text()),
        )


@pytest.mark.parametrize(
    "code",
    [
        "print('plain log')",
        "raise SystemExit(7)",
        "import time; time.sleep(10)",
        (
            "import json,time; phases=['service-ready','workload-complete',"
            "'fault-injected','observer-captured','service-shutdown'];"
            "[print(json.dumps({'ack':True,'phase':p,'sequence':i+1,"
            "'challenge':'guessed'}),flush=True) for i,p in enumerate(phases)];"
            "time.sleep(10)"
        ),
        """import json, sys
first = None
for raw in sys.stdin:
    request = json.loads(raw)
    first = first or request
    response = dict(request)
    response["ack"] = True
    if request["sequence"] > 1:
        response["challenge"] = first["challenge"]
    print(json.dumps(response), flush=True)
""",
        """import json, sys
for raw in sys.stdin:
    request = json.loads(raw)
    response = dict(request)
    response["ack"] = True
    if request["sequence"] == 2:
        response["phase"] = "fault-injected"
    print(json.dumps(response), flush=True)
""",
        """import json, sys
for raw in sys.stdin:
    request = json.loads(raw)
    if request["phase"] == "service-shutdown":
        break
    response = dict(request)
    response["ack"] = True
    print(json.dumps(response), flush=True)
""",
    ],
)
def test_formal_plain_or_nonzero_command_still_writes_failed_record(tmp_path, code):
    identity = {
        "model": "test",
        "dataset": "test",
        "workload": "test",
        "software": {"runtime": "test"},
        "observer": "result-file/v1",
        "plugin_commits": [],
        "topology": "single",
        "fault_plan": "test",
        "fault": "test",
        "warm_state": "cold",
        "container_digest": "test",
        "gpu": "not-applicable",
        "npu": "not-applicable",
        "driver": "test",
    }
    record = run_formal_start(
        tmp_path,
        scenarios()[0],
        json.loads((ROOT / "protocol.json").read_text()),
        ECPAAdapter(),
        1,
        3,
        executable=sys.executable,
        arguments=["-c", code],
        observer_executable=sys.executable,
        observer_arguments=[
            str(Path("tests/fixtures/formal_observer_service.py").resolve())
        ],
        identity=identity,
        timeout_s=1,
        fixture_mode=True,
    )
    assert record["status"] == "failed"
    assert record["oracle"]["verdict"] == "INCOMPLETE"
    assert (tmp_path / record["artifact_root"] / "record.json").is_file()


def test_proc_stat_parser_handles_parentheses_in_comm():
    tail = ["S"] + [str(value) for value in range(4, 23)]
    stat = "321 (worker (rank 0)) " + " ".join(tail)
    assert parse_proc_stat_start_ticks(stat) == 22


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "reverse",
        "false",
        "source",
        "fault",
        "activation",
        "causal-ack",
        "sequence",
        "challenge",
        "sut-identity",
    ],
)
def test_formal_oracle_rejects_lifecycle_counterexamples(tmp_path, mutation):
    record = copy.deepcopy(formal_complete_records(tmp_path)[0])
    events = record["observations"]
    if mutation == "duplicate":
        events.append(copy.deepcopy(events[0]))
    elif mutation == "reverse":
        ready = next(item for item in events if item["event"] == "service-ready")
        shutdown = next(item for item in events if item["event"] == "service-shutdown")
        ready["monotonic_ns"], shutdown["monotonic_ns"] = (
            shutdown["monotonic_ns"],
            ready["monotonic_ns"],
        )
    elif mutation == "false":
        next(item for item in events if item["event"] == "service-ready")["value"] = (
            False
        )
    elif mutation == "source":
        next(item for item in events if item["event"] == "plugin-invoked")[
            "source_role"
        ] = "sut"
    elif mutation == "fault":
        next(item for item in events if item["event"] == "fault-injected")["value"] = (
            "other"
        )
    elif mutation == "activation":
        next(item for item in events if item["event"] == "activation-path")["value"] = (
            "wrong-path"
        )
    elif mutation == "causal-ack":
        events[0]["causal_ack"] = False
    elif mutation == "sequence":
        events[0]["sequence"] = 999
    elif mutation == "challenge":
        events[0]["challenge"] = "replayed"
    else:
        events[0]["sut_process_identity"]["start_ticks"] += 1
    assert oracle(scenarios()[0], record)["verdict"] == "INCOMPLETE"


def _effect_identity(
    linux_identity,
    *,
    role: str,
    ordinal: int,
    epoch: int = 7,
    host: str = "host-a",
):
    return {
        "host": host,
        "role": role,
        "ordinal": ordinal,
        "process_epoch": epoch,
        "pid": linux_identity["pid"],
        "start_ticks": linux_identity["start_ticks"],
        "start_identity": (
            f"pid:{linux_identity['pid']}:start_ticks:{linux_identity['start_ticks']}"
        ),
        "argv": linux_identity["argv"],
        "assignment_source": "host",
    }


def _formal_process_record(tmp_path):
    record = copy.deepcopy(formal_complete_records(tmp_path)[0])
    record["evidence_class"] = "formal-real"
    record["identity"]["adapter_verification"] = {
        "evidence_owner": "vllm-hust-host",
        "evidence_channel": "host-owned-event-stream",
    }
    for event in record["observations"]:
        event["source_role"] = "host-observer"
    return record


def test_formal_oracle_rejects_controller_only_full_coverage_claim(tmp_path):
    record = _formal_process_record(tmp_path)
    controller = record["command"]["sut_process"]["linux_identity"]
    record["identity"]["required_processes"] = [
        {"host": "host-a", "role": "engine-core", "ordinal": 0, "process_epoch": 7},
        {"host": "host-a", "role": "worker", "ordinal": 0, "process_epoch": 7},
    ]
    invoked = next(
        item for item in record["observations"] if item["event"] == "plugin-invoked"
    )
    invoked["value"] = True
    invoked["effect_process_identities"] = [
        _effect_identity(controller, role="engine-core", ordinal=0)
    ]
    next(item for item in record["observations"] if item["event"] == "coverage")[
        "value"
    ] = 1.0
    next(item for item in record["observations"] if item["event"] == "effective-claim")[
        "value"
    ] = True

    result = oracle(scenarios()[0], record)
    assert result["verdict"] == "INCOMPLETE"
    assert result["outcome"]["activation_event_coverage"] == 0.5
    assert result["outcome"]["false_effective"] is True
    assert "reported coverage disagrees with process evidence" in result["reasons"]


def test_formal_oracle_rejects_one_linux_identity_covering_two_roles(tmp_path):
    record = _formal_process_record(tmp_path)
    controller = record["command"]["sut_process"]["linux_identity"]
    record["identity"]["required_processes"] = [
        {"host": "host-a", "role": "engine-core", "ordinal": 0, "process_epoch": 7},
        {"host": "host-a", "role": "worker", "ordinal": 0, "process_epoch": 7},
    ]
    invoked = next(
        item for item in record["observations"] if item["event"] == "plugin-invoked"
    )
    invoked["value"] = True
    invoked["effect_process_identities"] = [
        _effect_identity(controller, role="engine-core", ordinal=0),
        _effect_identity(controller, role="worker", ordinal=0),
    ]
    next(item for item in record["observations"] if item["event"] == "coverage")[
        "value"
    ] = 1.0

    result = oracle(scenarios()[0], record)
    assert result["verdict"] == "INCOMPLETE"
    assert "formal effect process identities contain duplicates" in result["reasons"]


def test_formal_oracle_rejects_stale_process_epoch(tmp_path):
    record = _formal_process_record(tmp_path)
    controller = record["command"]["sut_process"]["linux_identity"]
    record["identity"]["required_processes"] = [
        {"host": "host-a", "role": "worker", "ordinal": 0, "process_epoch": 8}
    ]
    invoked = next(
        item for item in record["observations"] if item["event"] == "plugin-invoked"
    )
    invoked["value"] = True
    invoked["effect_process_identities"] = [
        _effect_identity(controller, role="worker", ordinal=0, epoch=7)
    ]
    next(item for item in record["observations"] if item["event"] == "coverage")[
        "value"
    ] = 1.0

    result = oracle(scenarios()[0], record)
    assert result["verdict"] == "INCOMPLETE"
    assert "formal effect process is outside the target snapshot" in result["reasons"]


def test_formal_oracle_accepts_distinct_complete_effect_processes(tmp_path):
    record = _formal_process_record(tmp_path)
    controller = record["command"]["sut_process"]["linux_identity"]
    worker = {"pid": controller["pid"] + 1000, "start_ticks": 12345, "argv": ["worker"]}
    record["identity"]["required_processes"] = [
        {"host": "host-a", "role": "engine-core", "ordinal": 0, "process_epoch": 7},
        {"host": "host-a", "role": "worker", "ordinal": 0, "process_epoch": 7},
    ]
    invoked = next(
        item for item in record["observations"] if item["event"] == "plugin-invoked"
    )
    invoked["value"] = True
    invoked["effect_process_identities"] = [
        _effect_identity(controller, role="engine-core", ordinal=0),
        _effect_identity(worker, role="worker", ordinal=0),
    ]
    next(item for item in record["observations"] if item["event"] == "coverage")[
        "value"
    ] = 1.0

    result = oracle(scenarios()[0], record)
    assert result["verdict"] == "PASS"
    assert result["outcome"]["activation_event_coverage"] == 1.0


def test_formal_oracle_accepts_same_numeric_identity_on_distinct_hosts(tmp_path):
    record = _formal_process_record(tmp_path)
    controller = record["command"]["sut_process"]["linux_identity"]
    record["identity"]["required_processes"] = [
        {"host": "host-a", "role": "engine-core", "ordinal": 0, "process_epoch": 7},
        {"host": "host-b", "role": "worker", "ordinal": 0, "process_epoch": 7},
    ]
    invoked = next(
        item for item in record["observations"] if item["event"] == "plugin-invoked"
    )
    invoked["value"] = True
    invoked["effect_process_identities"] = [
        _effect_identity(controller, role="engine-core", ordinal=0, host="host-a"),
        _effect_identity(controller, role="worker", ordinal=0, host="host-b"),
    ]
    next(item for item in record["observations"] if item["event"] == "coverage")[
        "value"
    ] = 1.0

    result = oracle(scenarios()[0], record)
    assert result["verdict"] == "PASS"
    assert result["outcome"]["activation_event_coverage"] == 1.0


def test_oracle_rejects_duplicate_or_reordered_phase_invocations(tmp_path):
    record = copy.deepcopy(formal_complete_records(tmp_path)[0])
    duplicate = copy.deepcopy(record["command"]["phase_invocations"][0])
    duplicate["challenge"] = "different"
    duplicate["invocation_id"] = "different"
    record["command"]["phase_invocations"].append(duplicate)
    assert oracle(scenarios()[0], record)["verdict"] == "INCOMPLETE"

    record = copy.deepcopy(formal_complete_records(tmp_path / "reordered")[0])
    record["command"]["phase_invocations"].reverse()
    assert oracle(scenarios()[0], record)["verdict"] == "INCOMPLETE"


def test_runner_manifest_rejects_tampered_record_and_manual_jsonl(tmp_path):
    formal_complete_records(tmp_path)
    root = tmp_path / "formal"
    records = [
        json.loads(path.read_text())
        for path in sorted(root.glob("starts/*/record.json"))
    ]
    manifest = write_formal_manifest(root, records)
    target = root / records[0]["artifact_root"] / "record.json"
    target.write_text(
        target.read_text().replace('"status":"complete"', '"status":"failed"')
    )
    module = _reproduce_module()
    with pytest.raises(ValueError, match="digest"):
        module.generate(tmp_path / "published", manifest)
    assert not (tmp_path / "published").exists()
    manual = tmp_path / "manual.jsonl"
    manual.write_text("{}\n")
    with pytest.raises(ValueError, match="manifest|schema|current pointer"):
        module.generate(tmp_path / "manual-output", manual)
    assert not (tmp_path / "manual-output").exists()


def test_manifest_rejects_noncanonical_jsonl_and_wrong_start_binding(tmp_path):
    formal_complete_records(tmp_path)
    root = tmp_path / "formal"
    records = [
        json.loads(path.read_text())
        for path in sorted(root.glob("starts/*/record.json"))
    ]
    write_formal_manifest(root, records)
    current_path = root / "formal-record-index.json"
    current = json.loads(current_path.read_text())
    manifest_path = root / current["generation_index"]
    manifest = json.loads(manifest_path.read_text())
    manifest["records"][0]["start_id"] = "forged"
    manifest_path.write_bytes(canonical(manifest) + b"\n")
    current["generation_index_digest"] = digest_file(manifest_path)
    current_path.write_bytes(canonical(current) + b"\n")
    with pytest.raises(ValueError, match="start_id"):
        _reproduce_module().generate(tmp_path / "bad-index", current_path)

    current_path = write_formal_manifest(root, records)
    current = json.loads(current_path.read_text())
    manifest_path = root / current["generation_index"]
    manifest = json.loads(manifest_path.read_text())
    jsonl = root / manifest["records_jsonl"]
    jsonl.write_text("\n".join(json.dumps(row) for row in records) + "\n")
    manifest["records_jsonl_digest"] = digest_file(jsonl)
    manifest_path.write_bytes(canonical(manifest) + b"\n")
    current["generation_index_digest"] = digest_file(manifest_path)
    current_path.write_bytes(canonical(current) + b"\n")
    with pytest.raises(ValueError, match="canonical"):
        _reproduce_module().generate(tmp_path / "noncanonical", current_path)


def test_manifest_requires_runner_owned_pointer_and_generation_layout(tmp_path):
    formal_complete_records(tmp_path)
    root = tmp_path / "formal"
    records = [
        json.loads(path.read_text())
        for path in sorted(root.glob("starts/*/record.json"))
    ]
    current_path = write_formal_manifest(root, records)
    renamed = root / "caller-chosen.json"
    renamed.write_bytes(current_path.read_bytes())
    with pytest.raises(ValueError, match="runner-owned current pointer"):
        _reproduce_module().generate(tmp_path / "renamed-output", renamed)

    current = json.loads(current_path.read_text())
    index_path = root / current["generation_index"]
    outside = root / "not-a-generation" / "index.json"
    outside.parent.mkdir()
    outside.write_bytes(index_path.read_bytes())
    current["generation_index"] = "not-a-generation/index.json"
    current["generation_index_digest"] = digest_file(outside)
    current_path.write_bytes(canonical(current) + b"\n")
    with pytest.raises(ValueError, match="generation index path"):
        _reproduce_module().generate(tmp_path / "layout-output", current_path)


def test_manifest_rejects_generation_symlinks(tmp_path):
    formal_complete_records(tmp_path)
    root = tmp_path / "formal"
    records = [
        json.loads(path.read_text())
        for path in sorted(root.glob("starts/*/record.json"))
    ]
    current_path = write_formal_manifest(root, records)
    current = json.loads(current_path.read_text())
    index_path = root / current["generation_index"]
    index_bytes = index_path.read_bytes()
    outside = root / "outside"
    outside.mkdir()
    outside_index = outside / "index.json"
    outside_index.write_bytes(index_bytes)
    index_path.unlink()
    index_path.symlink_to(outside_index)
    with pytest.raises(ValueError, match="symlink|invalid component"):
        _reproduce_module().generate(tmp_path / "index-symlink", current_path)

    index_path.unlink()
    index_path.write_bytes(index_bytes)
    manifest = json.loads(index_bytes)
    jsonl_path = root / manifest["records_jsonl"]
    outside_jsonl = outside / "records.jsonl"
    outside_jsonl.write_bytes(jsonl_path.read_bytes())
    jsonl_path.unlink()
    jsonl_path.symlink_to(outside_jsonl)
    with pytest.raises(ValueError, match="symlink|invalid component"):
        _reproduce_module().generate(tmp_path / "jsonl-symlink", current_path)


def test_reproduce_default_output_uses_nonexistent_child():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "reproduce.py")],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["starts"] == 45
    assert result["formal_completed_cells"] == 0


def test_cli_rejects_fixture_completed_and_failed_manifest_without_partial_output(
    tmp_path,
):
    formal_complete_records(tmp_path)
    root = tmp_path / "formal"
    first = json.loads(next(root.glob("starts/*/record.json")).read_text())
    failed = run_formal_start(
        root,
        scenarios()[1],
        json.loads((ROOT / "protocol.json").read_text()),
        ECPAAdapter(),
        4,
        3,
        executable=sys.executable,
        arguments=["-c", "raise SystemExit(7)"],
        observer_executable=sys.executable,
        observer_arguments=[
            str(Path("tests/fixtures/formal_observer_service.py").resolve())
        ],
        identity=first["identity"],
        timeout_s=1,
        fixture_mode=True,
    )
    assert failed["status"] == "failed"
    records = [
        json.loads(path.read_text())
        for path in sorted(root.glob("starts/*/record.json"))
    ]
    manifest = write_formal_manifest(root, records)
    output = tmp_path / "published"
    with pytest.raises(ValueError, match="fixture-only"):
        _reproduce_module().generate(output, manifest)
    assert not output.exists()


def _reproduce_module():
    spec = importlib.util.spec_from_file_location(
        "false_effective_reproduce_extra", ROOT / "reproduce.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
