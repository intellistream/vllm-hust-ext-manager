from __future__ import annotations

import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/false_effective/deployment_stack_preflight.py"
CANDIDATES = ROOT / "experiments/false_effective/deployment-candidates"


def load_preflight():
    spec = importlib.util.spec_from_file_location("deployment_stack_preflight", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def inputs() -> tuple[dict, dict]:
    requirements = json.loads(
        (CANDIDATES / "ascend-910b2-112.requirements.json").read_text()
    )
    observation = json.loads(
        (CANDIDATES / "ascend-910b2-112.observation.json").read_text()
    )
    return requirements, observation


def test_checked_candidate_is_recomputed_and_schema_valid() -> None:
    preflight = load_preflight()
    requirements, observation = inputs()
    result = preflight.audit_stack(requirements, observation)
    checked = json.loads((CANDIDATES / "ascend-910b2-112.preflight.json").read_text())
    assert result == checked
    schema = json.loads(
        (
            ROOT / "experiments/false_effective/formal-real-stack-preflight.schema.json"
        ).read_text()
    )
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(result)
    assert result["formal_real_result"] is False
    assert result["registration_authority"] is False

    for field in ("formal_real_result", "registration_authority"):
        promoted = deepcopy(result)
        promoted[field] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft7Validator(schema).validate(promoted)

    contradictory = deepcopy(result)
    contradictory["status"] = "ready-for-registration-review"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft7Validator(schema).validate(contradictory)


def test_fully_matching_stack_is_only_ready_for_registration_review() -> None:
    preflight = load_preflight()
    requirements, observation = inputs()
    observation["runtime"] = {
        "commit": requirements["runtime"]["commit"],
        "tree": requirements["runtime"]["tree"],
    }
    observation["accelerator_plugin"]["commit"] = requirements["accelerator_plugin"][
        "commit"
    ]
    observation["accelerator_plugin"]["tree"] = requirements["accelerator_plugin"][
        "tree"
    ]
    requirements["accelerator_plugin"]["verified_runtime_commit"] = requirements[
        "runtime"
    ]["upstream_commit"]
    observation["cann_version"] = requirements["accelerator_plugin"][
        "required_cann_version"
    ]
    requirements["execution"]["image_digest"] = "sha256:" + "1" * 64
    observation["execution"]["container_server_accessible"] = True
    observation["execution"]["image_digest"] = requirements["execution"]["image_digest"]
    observation["execution"]["image_source_commits"] = requirements["execution"][
        "image_source_commits"
    ]
    observation["execution"]["runtime_mode"] = requirements["execution"]["runtime_mode"]
    observation["model"]["files"] = list(requirements["model"]["required_files"])
    observation["model"]["file_sha256"] = dict(requirements["model"]["file_sha256"])

    result = preflight.audit_stack(requirements, observation)

    assert result["status"] == "ready-for-registration-review"
    assert result["blockers"] == []
    assert result["formal_real_result"] is False
    assert result["registration_authority"] is False


def test_identity_and_topology_drift_fail_closed() -> None:
    preflight = load_preflight()
    requirements, observation = inputs()
    changed = deepcopy(observation)
    changed["runtime"] = {"commit": "0" * 40, "tree": "1" * 40}
    changed["accelerator_plugin"] = {"commit": "2" * 40}
    changed["hardware"]["device_count"] = 1
    changed["model"]["revision"] = "different"

    blockers = preflight.audit_stack(requirements, changed)["blockers"]

    assert "runtime-identity-mismatch" in blockers
    assert "accelerator-plugin-identity-mismatch" in blockers
    assert "hardware-topology-mismatch" in blockers
    assert "model-identity-mismatch" in blockers


def test_source_binary_mode_and_model_content_drift_fail_closed() -> None:
    preflight = load_preflight()
    requirements, observation = inputs()

    blockers = preflight.audit_stack(requirements, observation)["blockers"]

    assert "accelerator-plugin-runtime-unverified" in blockers
    assert "container-source-binary-mismatch" in blockers
    assert "runtime-mode-mismatch" in blockers
    assert "model-content-mismatch" not in blockers

    observation["model"]["file_sha256"]["config.json"] = "0" * 64
    blockers = preflight.audit_stack(requirements, observation)["blockers"]
    assert "model-content-mismatch" in blockers
