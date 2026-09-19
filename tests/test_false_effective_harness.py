import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

ROOT = Path("experiments/false_effective").resolve()
sys.path.insert(0, str(ROOT))

from harness import (  # noqa: E402
    aggregate,
    canonical,
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
    planned_records,
    run_formal_start,
    run_reference_start,
)


def scenarios():
    return json.loads((ROOT / "scenarios.json").read_text())["scenarios"]


def planned():
    return planned_records(scenarios())


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
    helper = str(Path("tests/fixtures/formal_lifecycle_service.py").resolve())
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
                arguments=[helper, scenario["id"]],
                identity=identity,
                timeout_s=5,
            )
            record["artifact_root"] = f"formal/{record['artifact_root']}"
            records.append(record)
    return records


def test_matched_arm_metadata_mismatch_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["identity"]["model"] = "different"
    with pytest.raises(ValueError, match="relabelled|metadata mismatch"):
        validate_batch(records, tmp_path, formal=True)


def test_unbalanced_order_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["arm_order"] = records[-2]["arm_order"]
    with pytest.raises(ValueError, match="relabelled|unbalanced|Latin square"):
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


def test_formal_runner_forbids_reference_helper(tmp_path):
    protocol = json.loads((ROOT / "protocol.json").read_text())
    with pytest.raises(ValueError, match="reference helper"):
        run_formal_start(
            tmp_path,
            scenarios()[0],
            protocol,
            ECPAAdapter(),
            1,
            3,
            executable=sys.executable,
            arguments=[str((ROOT / "helper_service.py").resolve())],
            identity={},
            timeout_s=1,
        )


def test_frozen_registry_is_present_even_for_partial_input(tmp_path):
    result = aggregate(planned()[:1], tmp_path, formal=True)
    assert len(result["cells"]) == len(scenarios()) * 3


def test_formal_observer_ignores_plain_stdout_and_captures_lifecycle(tmp_path):
    records = formal_complete_records(tmp_path)
    record = records[0]
    assert record["status"] == "complete"
    assert record["measurement_source"] == "independent-result-file-observer"
    events = [item["event"] for item in record["observations"]]
    assert events.index("service-ready") < events.index("workload-complete")
    assert events.index("workload-complete") < events.index("fault-injected")
    assert events.index("fault-injected") < events.index("observer-captured")
    assert events.index("observer-captured") < events.index("service-shutdown")
    run_dir = tmp_path / record["artifact_root"]
    assert (run_dir / "stdout.bin").read_text().startswith("ordinary service log")


def test_arm_launch_contracts_are_distinct_and_auditable():
    adapters = [VanillaVLLMAdapter(), ManualIntegrationAdapter(), ECPAAdapter()]
    launches = [adapter.launch("service", [], {}) for adapter in adapters]
    assert len({env["ECPA_ACTIVATION_CONTRACT"] for _, env in launches}) == 3
    assert {env["ECPA_EVALUATION_ARM"] for _, env in launches} == {
        adapter.arm for adapter in adapters
    }


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


@pytest.mark.parametrize("code", ["print('plain log')", "raise SystemExit(7)"])
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
        identity=identity,
        timeout_s=1,
    )
    assert record["status"] == "failed"
    assert record["oracle"]["verdict"] == "INCOMPLETE"
    assert (tmp_path / record["artifact_root"] / "record.json").is_file()
