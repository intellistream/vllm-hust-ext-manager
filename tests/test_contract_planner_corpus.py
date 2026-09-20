from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments" / "contract_planner"
SPEC = ROOT / "spec" / "0.1"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_frozen_contract_planner_artifacts_validate() -> None:
    pairs = (
        (SPEC / "contract-taxonomy.schema.json", SPEC / "contract-taxonomy.json"),
        (EXPERIMENT / "cases.schema.json", EXPERIMENT / "cases.json"),
        (EXPERIMENT / "oracle.schema.json", EXPERIMENT / "oracle.json"),
    )
    for schema_path, artifact_path in pairs:
        schema = _load(schema_path)
        jsonschema.Draft7Validator.check_schema(schema)
        jsonschema.Draft7Validator(schema).validate(_load(artifact_path))


def test_taxonomy_names_and_aliases_are_globally_unique() -> None:
    taxonomy = _load(SPEC / "contract-taxonomy.json")
    capability_names = [item["name"] for item in taxonomy["capabilities"]]
    resource_names = [
        name
        for resource in taxonomy["resources"]
        for name in [resource["canonical"], *resource["aliases"]]
    ]
    assert len(capability_names) == len(set(capability_names))
    assert len(resource_names) == len(set(resource_names))
    assert taxonomy["decision_precedence"] == [
        "unknown-resource",
        "invalid-mode",
        "capability-cardinality",
        "resource-mode",
        "mediator-consistency",
        "mediator-presence",
    ]


def test_evidence_backed_contracts_cover_registered_corpus_only() -> None:
    corpus = _load(ROOT / "docs" / "corpus" / "plugins.json")
    cases = _load(EXPERIMENT / "cases.json")
    modeled = {
        contract["source_plugin"]
        for contract in cases["contracts"]
        if contract["model_kind"] == "evidence-backed-abstraction"
    }
    assert modeled == {plugin["id"] for plugin in corpus["plugins"]}
    assert None not in modeled

    excluded = set(cases["excluded_candidates"])
    assert excluded == {candidate["repository"] for candidate in corpus["candidates"]}


def test_contracts_use_only_frozen_taxonomy() -> None:
    taxonomy = _load(SPEC / "contract-taxonomy.json")
    cases = _load(EXPERIMENT / "cases.json")
    capabilities = {item["name"] for item in taxonomy["capabilities"]}
    resources = {}
    for item in taxonomy["resources"]:
        for name in [item["canonical"], *item["aliases"]]:
            resources[name] = set(item["allowed_modes"])
    for contract in cases["contracts"]:
        for capability in [*contract["provides"], *contract["requires"]]:
            assert capability["name"] in capabilities
        for resource in contract["resources"]:
            if contract["id"] != "control.unknown-resource-owner":
                assert resource["name"] in resources
                assert resource["mode"] in resources[resource["name"]]


def test_cases_and_candidate_oracle_are_complete_and_bound() -> None:
    cases_path = EXPERIMENT / "cases.json"
    cases = _load(cases_path)
    oracle = _load(EXPERIMENT / "oracle.json")
    contract_ids = [contract["id"] for contract in cases["contracts"]]
    contracts = set(contract_ids)
    case_ids = {case["id"] for case in cases["cases"]}
    label_ids = [label["case_id"] for label in oracle["labels"]]
    labels = {label["case_id"]: label for label in oracle["labels"]}

    assert len(contract_ids) == len(contracts)
    assert len(case_ids) == len(cases["cases"])
    assert len(label_ids) == len(set(label_ids))
    assert case_ids == set(labels)
    assert oracle["status"] == "candidate-awaiting-independent-review"
    assert oracle["cases_sha256"] == hashlib.sha256(cases_path.read_bytes()).hexdigest()
    assert (
        oracle["taxonomy_sha256"]
        == hashlib.sha256((SPEC / "contract-taxonomy.json").read_bytes()).hexdigest()
    )
    assert (
        oracle["source_corpus_sha256"]
        == hashlib.sha256(
            (ROOT / "docs" / "corpus" / "plugins.json").read_bytes()
        ).hexdigest()
    )
    assert oracle["counts"] == {
        "admit": sum(label["decision"] == "admit" for label in labels.values()),
        "reject": sum(label["decision"] == "reject" for label in labels.values()),
    }
    assert oracle["counts"]["admit"] > oracle["counts"]["reject"]

    shape_sizes = {"single": 1, "pair": 2, "triple": 3}
    for case in cases["cases"]:
        assert len(case["members"]) == shape_sizes[case["shape"]]
        assert set(case["members"]) <= contracts


def test_required_l2_boundary_cells_are_present() -> None:
    cases = _load(EXPERIMENT / "cases.json")
    oracle = _load(EXPERIMENT / "oracle.json")
    labels = {label["case_id"]: label for label in oracle["labels"]}
    by_dimension: dict[str, set[str]] = {}
    for case in cases["cases"]:
        by_dimension.setdefault(case["dimension"], set()).add(
            labels[case["id"]]["decision"]
        )

    assert len([case for case in cases["cases"] if case["shape"] == "single"]) >= 11
    assert {case["shape"] for case in cases["cases"]} == {"single", "pair", "triple"}
    assert by_dimension["alias-conflict"] == {"reject"}
    assert by_dimension["shared-read"] == {"admit"}
    assert by_dimension["mediation"] == {"admit", "reject"}
    assert by_dimension["shared-provider"] == {"admit"}
    assert by_dimension["provider-ambiguity"] == {"reject"}
    assert by_dimension["unknown-resource"] == {"reject"}
