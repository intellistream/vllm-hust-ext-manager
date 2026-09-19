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
    run_command,
    safe_path,
    sanitized_env,
    validate_batch,
    validate_record,
)
from runner import planned_records  # noqa: E402


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
    for name in ("raw", "environment", "command", "oracle"):
        (tmp_path / name).write_text(name)
    records = []
    schedule = (
        ("vanilla-vllm-entry-points", "manual-integration", "ecpa"),
        ("manual-integration", "ecpa", "vanilla-vllm-entry-points"),
        ("ecpa", "vanilla-vllm-entry-points", "manual-integration"),
    )
    for repetition, order in enumerate(schedule, 1):
        for arm_order, arm in enumerate(order, 1):
            record = planned()[0]
            record.update(
                status="complete",
                arm=arm,
                start_id=f"r{repetition}-{arm}",
                repetition=repetition,
                arm_order=arm_order,
                identity={
                    "arm": arm,
                    "model": "same",
                    "workload": "same",
                    "hardware": "same",
                    "runtime_commit": "same",
                    "plugin_commits": [],
                    "topology": "same",
                    "fault": "same",
                    "warm_state": "cold",
                    "git_dirty": False,
                    "container_digest": None,
                    "cpu": None,
                    "gpu": None,
                    "npu": None,
                    "driver": None,
                    "runtime": "same",
                },
                command={},
                missing_reason=None,
            )
            record["artifacts"] = {
                "raw_log": "raw",
                "environment": "environment",
                "command": "command",
                "oracle": "oracle",
                "digests": {
                    name: digest_file(tmp_path / name)
                    for name in ("raw", "environment", "command", "oracle")
                },
            }
            records.append(record)
    return records


def test_matched_arm_metadata_mismatch_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["identity"]["model"] = "different"
    with pytest.raises(ValueError, match="metadata mismatch"):
        validate_batch(records, tmp_path, formal=True)


def test_unbalanced_order_is_rejected(tmp_path):
    records = formal_complete_records(tmp_path)
    records[-1]["arm_order"] = records[-2]["arm_order"]
    with pytest.raises(ValueError, match="unbalanced"):
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
    assert summary["starts"] == 27
    assert summary["formal_completed_cells"] == 0
    checked = ROOT / "artifacts"
    for name in (
        "formal-aggregate.json",
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
