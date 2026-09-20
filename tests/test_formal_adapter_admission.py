from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import jsonschema
import pytest

from vllm_hust_ext.formal_adapter_admission import (
    validate_formal_adapter_admission,
)

ROOT = Path("experiments/false_effective").resolve()
sys.path.insert(0, str(ROOT))

import harness as harness_module  # noqa: E402
import runner as runner_module  # noqa: E402
from runner import ECPAAdapter, VanillaVLLMAdapter, canonical  # noqa: E402


def admission() -> dict[str, object]:
    return {
        "schema": "ecpa-formal-adapter-admission/v1",
        "repository": "vLLM-HUST/vllm-hust",
        "repository_id": 1360701120,
        "node_id": "R_kgDOURE3QwA",
        "default_branch": "main",
        "pull_request": 27,
        "reviewed_head": "1" * 40,
        "reviewed_tree": "2" * 40,
        "base": "3" * 40,
        "state": "merged",
        "merge_commit": "4" * 40,
        "human_line_review": True,
        "commands_reviewed": True,
        "activation_path_reviewed": True,
        "observer_independence_reviewed": True,
        "observed_at": "2026-09-21T07:00:00+08:00",
    }


def test_adapter_admission_requires_exact_merged_reviewed_producer() -> None:
    receipt = admission()
    schema = json.loads(
        Path(
            "experiments/false_effective/formal-adapter-admission.schema.json"
        ).read_text()
    )
    jsonschema.Draft7Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(receipt)
    assert validate_formal_adapter_admission(receipt) == receipt

    for field, value in (
        ("state", "open"),
        ("human_line_review", False),
        ("commands_reviewed", False),
        ("activation_path_reviewed", False),
        ("observer_independence_reviewed", False),
    ):
        rejected = copy.deepcopy(receipt)
        rejected[field] = value
        with pytest.raises(ValueError, match="not merge-admissible"):
            validate_formal_adapter_admission(rejected)


def test_adapter_admission_rejects_schema_or_field_set_changes() -> None:
    wrong_schema = admission()
    wrong_schema["schema"] = "ecpa-formal-adapter-admission/v0"
    with pytest.raises(ValueError, match="schema is unsupported"):
        validate_formal_adapter_admission(wrong_schema)

    missing = admission()
    del missing["merge_commit"]
    with pytest.raises(ValueError, match="fields are incomplete"):
        validate_formal_adapter_admission(missing)

    extra = admission()
    extra["unreviewed_override"] = True
    with pytest.raises(ValueError, match="fields are incomplete"):
        validate_formal_adapter_admission(extra)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "vllm-hust", "identity"),
        ("repository_id", True, "identity"),
        ("reviewed_head", "1" * 39, "Git identity"),
        ("reviewed_tree", "g" * 40, "Git identity"),
        ("observed_at", "2026-09-21T07:00:00", "canonical"),
        ("observed_at", "2026-09-21T07:00:00+0800", "canonical"),
    ],
)
def test_adapter_admission_rejects_malformed_authority_fields(
    field: str, value: object, message: str
) -> None:
    rejected = admission()
    rejected[field] = value
    with pytest.raises(ValueError, match=message):
        validate_formal_adapter_admission(rejected)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-21T07:00:00+0800",
        "2026-09-21 07:00:00+08:00",
        "2026-09-21t07:00:00+08:00",
        "2026-09-21T07:00:00z",
        "2026-09-21T07:00:00.1+08:00",
    ],
)
def test_schema_and_runtime_reject_noncanonical_observation_time(
    timestamp: str,
) -> None:
    receipt = admission()
    receipt["observed_at"] = timestamp
    schema = json.loads(
        Path(
            "experiments/false_effective/formal-adapter-admission.schema.json"
        ).read_text()
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(receipt)
    with pytest.raises(ValueError, match="not canonical"):
        validate_formal_adapter_admission(receipt)


def test_unmerged_producer_fails_before_ecpa_probe_or_target_launch(
    tmp_path, monkeypatch
) -> None:
    blocked = admission()
    blocked["state"] = "open"
    registry = {
        "schema": "ecpa-formal-adapter-registry/v2",
        "adapters": [{"id": "blocked", "admission": blocked}],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(runner_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    probe_called = False

    def probe(*_args, **_kwargs):
        nonlocal probe_called
        probe_called = True
        raise AssertionError("activation probe must not run")

    monkeypatch.setattr(runner_module, "run_ecpa_activation_probe", probe)
    with pytest.raises(ValueError, match="not merge-admissible"):
        runner_module.verified_ecpa_adapter_contract(
            "blocked",
            ECPAAdapter(),
            "/missing/manager",
            "/missing/target",
            [],
            "/missing/observer",
            [],
        )
    assert not probe_called


def test_unreviewed_producer_fails_before_vanilla_probe_or_sut_launch(
    tmp_path, monkeypatch
) -> None:
    blocked = admission()
    blocked["human_line_review"] = False
    registry = {
        "schema": "ecpa-formal-adapter-registry/v2",
        "adapters": [{"id": "blocked", "admission": blocked}],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(runner_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)
    probe_called = False

    def probe(*_args, **_kwargs):
        nonlocal probe_called
        probe_called = True
        raise AssertionError("activation probe must not run")

    monkeypatch.setattr(runner_module, "run_activation_probe", probe)
    with pytest.raises(ValueError, match="not merge-admissible"):
        runner_module.verified_adapter_contract(
            "blocked",
            VanillaVLLMAdapter(),
            "/missing/sut",
            [],
            "/missing/observer",
            [],
        )
    assert not probe_called


def test_offline_validation_rejects_registry_downgrade_to_open_producer(
    tmp_path, monkeypatch
) -> None:
    blocked = admission()
    blocked["state"] = "open"
    registry = {
        "schema": "ecpa-formal-adapter-registry/v2",
        "adapters": [{"id": "blocked", "admission": blocked}],
    }
    registry_path = tmp_path / "verified-adapters.json"
    registry_path.write_bytes(canonical(registry) + b"\n")
    monkeypatch.setattr(harness_module, "VERIFIED_ADAPTER_REGISTRY", registry_path)

    record = {
        "arm": "ecpa",
        "identity": {"adapter_verification": {"verification_id": "blocked"}},
    }
    with pytest.raises(ValueError, match="not merge-admissible"):
        harness_module.validate_formal_adapter_verification(record, {})
