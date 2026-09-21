from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (
    ROOT
    / "experiments/false_effective/deployment-candidates/ascend-910b2-112.smoke.json"
)
SCHEMA = ROOT / "experiments/false_effective/pre-admission-real-smoke.schema.json"


def test_checked_real_smoke_is_valid_but_non_formal() -> None:
    record = json.loads(SMOKE.read_text())
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft7Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )

    jsonschema.Draft7Validator.check_schema(schema)
    validator.validate(record)
    assert record["execution"]["status"] == "succeeded"
    assert record["formal_real_result"] is False
    assert record["registration_authority"] is False

    for field in ("formal_real_result", "registration_authority"):
        promoted = deepcopy(record)
        promoted[field] = True
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(promoted)


def test_smoke_cannot_hide_non_production_execution_mode() -> None:
    record = json.loads(SMOKE.read_text())
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft7Validator(schema)

    for field, value in (
        ("source_overrides", False),
        ("batch_invariant", False),
        ("custom_ops", True),
    ):
        relabeled = deepcopy(record)
        relabeled["execution"][field] = value
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(relabeled)
