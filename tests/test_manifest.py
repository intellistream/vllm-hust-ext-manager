import json
from pathlib import Path

import pytest

from vllm_hust_ext.discovery import _flatten_entry_points
from vllm_hust_ext.manifest import ManifestError, activation_blocker, parse_manifest


def valid_manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "bundle_id": "org.vllm-hust.example",
        "bundle_version": "1.2.3",
        "host_api_range": ">=1,<2",
        "components": [
            {
                "component_id": "scheduler",
                "contracts": ["vllm.scheduler.policy.v1"],
                "execution_planes": ["scheduler"],
                "isolation": "trusted_in_process",
                "implementation_ref": "example.plugin:Scheduler",
                "permissions": [],
            }
        ],
    }


def test_manifest_accepts_bidkv_shape() -> None:
    manifest = parse_manifest(valid_manifest())
    assert manifest.bundle_id == "org.vllm-hust.example"
    assert manifest.components[0].component_id == "scheduler"


def test_manifest_rejects_unknown_field() -> None:
    payload = valid_manifest()
    payload["surprise"] = True
    with pytest.raises(ManifestError, match="unknown fields"):
        parse_manifest(payload)


def test_manifest_rejects_incompatible_host_api() -> None:
    payload = valid_manifest()
    payload["host_api_range"] = ">=2"
    with pytest.raises(ManifestError, match="host provides"):
        parse_manifest(payload)


def test_experimental_manifest_requires_explicit_host_runtime_and_owner() -> None:
    path = Path(__file__).parent / "fixtures" / "mooncake-v0.2.json"
    manifest = parse_manifest(json.loads(path.read_text(encoding="utf-8")))

    assert manifest.schema_version == "0.2-experimental"
    assert manifest.kind == "kv_service_adapter"
    assert manifest.host.provider == "mooncake"
    assert manifest.host.version_range == ">=0.3.11.post1,<0.4"
    assert manifest.host.api_range is None
    assert manifest.runtime.type == "composite"
    assert manifest.lifecycle_owner == "external_operator"
    assert all(protocol.version_range is None for protocol in manifest.protocols)
    assert manifest.requires_services[0].service_id == "mooncake-store"
    assert manifest.requires_services[0].version_range is None
    carrier = dict(manifest.implementation[0].attributes)
    assert carrier["source_repository"] == (
        "https://github.com/vLLM-HUST/mooncake-hust"
    )
    assert carrier["upstream_repository"] == "https://github.com/kvcache-ai/Mooncake"


def test_control_plane_carrier_records_hust_fork_and_upstream() -> None:
    path = Path(__file__).parent / "fixtures" / "production-stack-v0.2.json"
    manifest = parse_manifest(json.loads(path.read_text(encoding="utf-8")))
    carrier = dict(manifest.implementation[-1].attributes)

    assert carrier["source_repository"] == (
        "https://github.com/vLLM-HUST/production-stack-hust"
    )
    assert carrier["upstream_repository"] == (
        "https://github.com/vllm-project/production-stack"
    )
    assert carrier["validated_platform"] == "linux/arm64"


def test_python_310_grouped_entry_points_are_flattened() -> None:
    first = object()
    second = object()

    assert _flatten_entry_points({"one": (first,), "two": (second,)}) == (
        first,
        second,
    )


def test_python_module_carrier_requires_explicit_registration_status() -> None:
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "bidkv-v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    del payload["implementation"][0]["status"]

    with pytest.raises(ManifestError, match="module, object, and status"):
        parse_manifest(payload)


def test_import_only_manifest_is_discoverable_but_not_activatable() -> None:
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "bidkv-v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    payload["implementation"][0]["status"] = "import_only"

    blocker = activation_blocker(parse_manifest(payload))

    assert blocker is not None
    assert "descriptor-only" in blocker


@pytest.mark.parametrize("status", ["import_only", "legacy_unregistered"])
def test_inactive_entry_point_is_not_activatable(status: str) -> None:
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "bidkv-v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    payload["implementation"] = [
        {
            "type": "python_entry_point",
            "group": "vllm.legacy_plugin",
            "name": "example",
            "status": status,
        }
    ]

    blocker = activation_blocker(parse_manifest(payload))

    assert blocker is not None
    assert status in blocker


def test_unqualified_registered_entry_point_remains_activatable() -> None:
    payload = json.loads(
        (Path(__file__).parent / "fixtures" / "bidkv-v0.2.json").read_text(
            encoding="utf-8"
        )
    )
    payload["implementation"] = [
        {
            "type": "python_entry_point",
            "group": "vllm.general_plugins",
            "name": "example",
        }
    ]

    assert activation_blocker(parse_manifest(payload)) is None
