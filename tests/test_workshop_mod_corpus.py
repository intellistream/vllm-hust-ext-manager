from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "docs/corpus/workshop-mods.json"
SCHEMA_PATH = ROOT / "docs/corpus/workshop-mods.schema.json"

EXPECTED_MOD_IDS = (
    "bidkv",
    "diffspec",
    "vspec",
    "latchmoe",
    "ascend-adaptive-quantized-kv",
    "ascend-quant-runtime-descriptor",
    "kvcompress-ascend",
    "kv-tiering-migration",
    "knorm-migration",
    "pyramidkv-ascend-migration",
    "quantized-kv-cache-migration",
    "simllm-migration",
    "unified-communication-migration",
    "split-batch-full-graph-migration",
    "kv-transfer-observability-migration",
    "layered-prefill-migration",
    "activation-sparsity-migration",
    "pipeline-microbatch-migration",
    "qos-scheduler-migration",
    "betterscale",
    "request-lifecycle-profiler",
    "kv-materialization-arrival-control",
    "dla",
    "traceloom",
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_workshop_mod_corpus_is_schema_valid_and_exactly_page_scoped() -> None:
    corpus = _load(CORPUS_PATH)
    schema = _load(SCHEMA_PATH)
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(corpus)

    rows = corpus["mods"]
    assert tuple(row["id"] for row in rows) == EXPECTED_MOD_IDS
    assert len({row["id"] for row in rows}) == 24
    assert len({row["repository_id"] for row in rows}) == 24
    assert all(row["repository"].startswith("vLLM-HUST/") for row in rows)
    assert not any(
        row["repository"].startswith(("intellistream/", "Qixin-Gaoke/")) for row in rows
    )

    population = corpus["population"]
    snapshot = ROOT / population["metadata_snapshot_path"]
    metadata = _load(snapshot)
    assert (
        hashlib.sha256(snapshot.read_bytes()).hexdigest()
        == population["metadata_sha256"]
    )
    assert list(metadata["plugins"]) == list(EXPECTED_MOD_IDS)
    assert {
        mod_id: item["repository"] for mod_id, item in metadata["plugins"].items()
    } == {row["id"]: row["repository"] for row in rows}


def test_workshop_counts_are_derived_from_rows() -> None:
    corpus = _load(CORPUS_PATH)
    rows = corpus["mods"]
    integration = Counter(row["integration_class"] for row in rows)
    tests = Counter(row["local_test"] for row in rows)
    builds = Counter(row["package_build"] for row in rows)
    counts = corpus["counts"]

    assert counts["mods"] == len(rows) == corpus["population"]["mod_count"]
    for name in (
        "ecpa_bundle_namespace",
        "namespace_mismatch",
        "general_plugin_only",
        "direct_or_non_entry_integration",
        "source_only",
    ):
        assert counts[name] == integration[name]
    assert counts["local_tests_pass"] == tests["pass"]
    assert counts["environment_blocked"] == tests["environment_blocked"]
    assert counts["no_automated_tests"] == tests["no_automated_tests"]
    assert counts["local_package_build_pass"] == builds["pass"]
    assert counts["package_projects"] == (
        builds["pass"] + builds["qualified_staging_required"]
    )


def test_discovery_gap_is_explicit_instead_of_silently_excluded() -> None:
    corpus = _load(CORPUS_PATH)
    rows = {row["id"]: row for row in corpus["mods"]}

    assert rows["dla"]["bundle_id"] == "org.vllm-hust.dla"
    assert rows["dla"]["integration_class"] == "namespace_mismatch"
    assert rows["request-lifecycle-profiler"]["integration_class"] == (
        "general_plugin_only"
    )
    assert rows["traceloom"]["integration_class"] == ("direct_or_non_entry_integration")
    assert rows["kv-tiering-migration"]["integration_class"] == "source_only"


def test_cpu_and_package_results_are_not_formal_real_claims() -> None:
    corpus = _load(CORPUS_PATH)
    assert {row["evidence_class"] for row in corpus["mods"]} == {
        "source-package-cpu-only"
    }
    assert all(
        "formal-real" in limit
        or "do not establish" in limit
        or "not code failures" in limit
        for limit in corpus["evidence_limits"]
    )
