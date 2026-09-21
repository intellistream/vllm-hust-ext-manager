import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "docs" / "corpus"


def _load(name: str) -> dict:
    return json.loads((CORPUS / name).read_text(encoding="utf-8"))


def test_plugin_validation_matrix_is_schema_valid_and_corpus_complete() -> None:
    matrix = _load("validation-matrix-2026-09-21.json")
    jsonschema.Draft202012Validator(
        _load("validation-matrix.schema.json"),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    ).validate(matrix)

    corpus = _load("plugins.json")
    corpus_repositories = {
        record["repository"]
        for record in (*corpus["plugins"], *corpus["candidates"])
    }
    observed = {
        record["repository"]
        for record in matrix["repositories"]
    }
    assert observed == corpus_repositories
    assert len(observed) == len(matrix["repositories"])


def test_plugin_validation_matrix_does_not_overclaim_runtime_effectiveness() -> None:
    matrix = _load("validation-matrix-2026-09-21.json")
    assert "do not establish accelerator execution" in matrix["claim_boundary"]
    assert "formal-real" in matrix["claim_boundary"]
    assert all(record["limitations"] for record in matrix["repositories"])
    assert all(record["limitations"] for record in matrix["package_validations"])


def test_failed_source_observations_are_bound_to_a_passing_remediation() -> None:
    matrix = _load("validation-matrix-2026-09-21.json")
    remediated = [
        record
        for record in matrix["repositories"]
        if record["status"] == "failed-remediated"
    ]
    assert len(remediated) == 1
    assert remediated[0]["counts"]["failed"] > 0
    assert remediated[0]["remediation"]["counts"]["failed"] == 0
