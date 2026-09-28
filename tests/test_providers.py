from __future__ import annotations

import json
from dataclasses import replace
from importlib.metadata import PackageNotFoundError
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import (
    LifecycleState,
    plan_for,
    reject_conflicting_plans,
    status_for,
)
from vllm_hust_ext.manifest import ActivationEntryPoint, BundleManifest, parse_manifest
from vllm_hust_ext.providers import vllm as vllm_provider
from vllm_hust_ext.providers.base import ProviderPlan
from vllm_hust_ext.providers.mooncake import MooncakeProvider
from vllm_hust_ext.providers.production_stack import ProductionStackProvider
from vllm_hust_ext.providers.vllm import VllmProvider

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parents[1] / "examples"


def manifest(name: str) -> BundleManifest:
    return parse_manifest(json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def bundle(value: BundleManifest) -> SimpleNamespace:
    return SimpleNamespace(bundle_id=value.bundle_id, manifest=value)


class _HTTPResponse(BytesIO):
    status = 200


def test_bidkv_is_a_vllm_owned_scheduler_policy() -> None:
    value = manifest("bidkv-v0.2.json")
    plan = VllmProvider().plan(value, {}, enabled=True)

    assert value.kind == "scheduler_policy"
    assert value.lifecycle_owner == "vllm"
    assert all(not action.mutating for action in plan.actions)
    assert plan.generated_config["additional_config"] == {}
    assert plan.generated_config["vllm_options"] == {
        "--preemption-policy": (
            "bidkv.adapters.vllm_hust.selector.BidkvPreemptionPolicy"
        )
    }
    assert "run refuses unverified policies" in plan.warnings[0]
    assert value.activation.entry_points == ()
    carrier = value.implementation[0]
    assert carrier.type == "python_module"
    assert dict(carrier.attributes)["status"] == "active"
    assert plan.generated_config["native_extension_manifest"] == {
        "schema_version": "1.0",
        "bundle_id": "org.vllm-hust.bidkv",
        "bundle_version": "0.2.0",
        "host_api_range": ">=1,<2",
        "components": [
            {
                "component_id": "victim-selector",
                "contracts": ["vllm.preemption-policy.v1"],
                "execution_planes": ["scheduler"],
                "isolation": "trusted_in_process",
                "implementation_ref": (
                    "bidkv.adapters.vllm_hust.selector:BidkvPreemptionPolicy"
                ),
                "permissions": [],
            }
        ],
    }


def test_pipeline_microbatch_uses_batch_admission_policy_contract() -> None:
    value = manifest("pipeline-microbatch-v0.2.json")
    plan = VllmProvider().plan(
        value,
        {
            "launch_options": {
                "batch_admission_policy_config": {
                    "mode": "balanced",
                    "microbatch_count": 2,
                }
            }
        },
        enabled=True,
    )

    assert plan.generated_config["vllm_options"] == {
        "--batch-admission-policy": (
            "vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy"
        )
    }
    assert plan.generated_config["vllm_json_options"] == {
        "--batch-admission-policy-config": {
            "mode": "balanced",
            "microbatch_count": 2,
        }
    }


def test_vllm_detects_scheduler_policy_only_from_host_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = SimpleNamespace(value="vllm.scheduler.policy.v1")
    module = SimpleNamespace(
        DomainContract=SimpleNamespace(SCHEDULER_POLICY_V1=contract)
    )
    monkeypatch.setattr(vllm_provider, "import_module", lambda _name: module)

    assert vllm_provider._detect_protocol_versions() == {"vllm.scheduler.policy": "1.0"}


def test_vllm_detects_preemption_policy_from_versioned_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def imported(name: str) -> SimpleNamespace:
        if name == "vllm.v1.core.sched.preemption":
            return SimpleNamespace(PREEMPTION_POLICY_API_VERSION="1.0")
        raise ImportError(name)

    monkeypatch.setattr(vllm_provider, "import_module", imported)

    assert vllm_provider._detect_protocol_versions() == {
        "vllm.preemption-policy": "1.0"
    }


def test_vllm_detects_batch_admission_policy_from_versioned_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def imported(name: str) -> SimpleNamespace:
        if name == "vllm.v1.core.sched.batch_admission":
            return SimpleNamespace(BATCH_ADMISSION_POLICY_API_VERSION="1.1")
        raise ImportError(name)

    monkeypatch.setattr(vllm_provider, "import_module", imported)

    assert vllm_provider._detect_protocol_versions() == {
        "vllm.batch-admission-policy": "1.1"
    }


def test_vllm_detects_request_and_kv_materialization_contracts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def imported(name: str) -> SimpleNamespace:
        if name == "vllm.plugins.request_processing":
            return SimpleNamespace(REQUEST_PROCESSING_HOOK_API_VERSION="1.0")
        if name == "vllm.v1.core.kv_materialization":
            return SimpleNamespace(KV_MATERIALIZATION_RUNTIME_CONTROL_API_VERSION="1.0")
        raise ImportError(name)

    monkeypatch.setattr(vllm_provider, "import_module", imported)

    assert vllm_provider._detect_protocol_versions() == {
        "vllm.request-processing-hook": "1.0",
        "vllm.kv-materialization-runtime-control": "1.0",
    }


def test_vllm_plan_projects_general_and_platform_plugin_names() -> None:
    value = manifest("bidkv-v0.2.json")
    value = replace(
        value,
        activation=replace(
            value.activation,
            entry_points=(
                ActivationEntryPoint("vllm.general_plugins", "arrival_control"),
                ActivationEntryPoint("vllm.platform_plugins", "custom_platform"),
            ),
        ),
    )

    plan = VllmProvider().plan(value, {}, enabled=True)

    assert plan.generated_config["vllm_plugins"] == [
        "arrival_control",
        "custom_platform",
    ]


@pytest.mark.parametrize("unsupported", ["2.0", "not-a-version", object()])
def test_vllm_does_not_report_unknown_plugin_api_versions(
    monkeypatch: pytest.MonkeyPatch, unsupported: object
) -> None:
    def imported(name: str) -> SimpleNamespace:
        if name == "vllm.plugins.request_processing":
            return SimpleNamespace(REQUEST_PROCESSING_HOOK_API_VERSION=unsupported)
        if name == "vllm.v1.core.kv_materialization":
            return SimpleNamespace(
                KV_MATERIALIZATION_RUNTIME_CONTROL_API_VERSION=unsupported
            )
        raise ImportError(name)

    monkeypatch.setattr(vllm_provider, "import_module", imported)

    assert vllm_provider._detect_protocol_versions() == {}


def test_vllm_provider_uses_manifest_host_distribution_for_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("bidkv-v0.2.json")
    value = replace(
        value,
        host=type(value.host)(
            provider="vllm",
            name="vllm-ascend",
            version_range=">=0.23,<0.24",
            api_range=None,
        ),
    )
    requested: list[str] = []

    def installed_version(distribution: str) -> str:
        requested.append(distribution)
        return "0.23.0"

    monkeypatch.setattr(vllm_provider, "version", installed_version)

    check = VllmProvider().check(value, {})

    assert requested == ["vllm-ascend"]
    assert check.compatible is None
    assert any("host version 0.23.0 satisfies" in item for item in check.evidence)


def test_vllm_provider_renders_configured_speculative_config() -> None:
    value = manifest("bidkv-v0.2.json")
    value = replace(value, host=replace(value.host, api_range=None))

    plan = VllmProvider().plan(
        value,
        {
            "launch_options": {
                "speculative_config": {
                    "method": "eagle3",
                    "draft_context_policy": "diffspec",
                }
            }
        },
        enabled=True,
    )

    assert plan.generated_config["vllm_json_options"] == {
        "--speculative-config": {
            "method": "eagle3",
            "draft_context_policy": "diffspec",
        }
    }
    assert "native_extension_manifest" not in plan.generated_config


def test_vllm_provider_allows_only_declared_environment_overrides() -> None:
    value = manifest("bidkv-v0.2.json")

    plan = VllmProvider().plan(
        value,
        {"environment": {"BIDKV_UTILITY_STRATEGY": "lru"}},
        enabled=True,
    )

    assert plan.generated_config["environment"] == {
        "BIDKV_UTILITY_ENABLE": "1",
        "BIDKV_UTILITY_STRATEGY": "lru",
    }
    with pytest.raises(ValueError, match="must be declared"):
        VllmProvider().plan(
            value,
            {"environment": {"UNDECLARED_SECRET": "value"}},
            enabled=True,
        )


def test_vllm_provider_keeps_import_only_descriptor_inert() -> None:
    value = manifest("bidkv-v0.2.json")
    carrier = value.implementation[0]
    value = replace(
        value,
        implementation=(
            replace(
                carrier,
                attributes=tuple(
                    (key, "import_only" if key == "status" else item)
                    for key, item in carrier.attributes
                ),
            ),
        ),
    )

    plan = VllmProvider().plan(value, {}, enabled=True)
    check = VllmProvider().check(value, {"host_version": "0.10.2"})

    assert [action.operation for action in plan.actions] == ["inspect_only"]
    assert plan.generated_config == {}
    assert check.configured is False
    assert check.degraded is True
    assert "descriptor-only" in check.evidence[-1]


def test_mooncake_plan_reuses_official_connector_without_owning_service() -> None:
    value = manifest("mooncake-v0.2.json")
    plan = MooncakeProvider().plan(
        value,
        {"connector": "MooncakeStoreConnector", "kv_role": "kv_both"},
        enabled=True,
    )

    assert value.kind == "kv_service_adapter"
    assert value.lifecycle_owner == "external_operator"
    assert plan.generated_config["kv_transfer_config"]["kv_connector"] == (
        "MooncakeStoreConnector"
    )
    assert {action.operation for action in plan.actions} == {
        "render_connector_config",
        "check_service",
    }
    assert all(not action.mutating for action in plan.actions)


def test_ascend_store_plan_preserves_connector_options() -> None:
    configuration = {
        "connector": "AscendStoreConnector",
        "kv_load_failure_policy": "fail",
        "device_backend": "ascend",
        "transport_protocol": "ascend",
        "kv_connector_extra_config": {"backend": "mooncake", "use_layerwise": False},
    }
    plan = MooncakeProvider().plan(
        manifest("mooncake-v0.2.json"), configuration, enabled=True
    )
    assert plan.generated_config == {
        "kv_transfer_config": {
            "kv_connector": "AscendStoreConnector",
            "kv_role": "kv_both",
            "kv_load_failure_policy": "fail",
            "kv_connector_extra_config": configuration["kv_connector_extra_config"],
        }
    }
    assert all(not action.mutating for action in plan.actions)
    for field in ("device_backend", "transport_protocol", "kv_connector_extra_config"):
        invalid = dict(configuration)
        invalid.pop(field)
        with pytest.raises(ValueError, match="AscendStoreConnector requires"):
            MooncakeProvider().plan(
                manifest("mooncake-v0.2.json"), invalid, enabled=True
            )

    for policy in ("fail", "recompute"):
        configured = dict(configuration, kv_load_failure_policy=policy)
        result = MooncakeProvider().plan(
            manifest("mooncake-v0.2.json"), configured, enabled=True
        )
        assert (
            result.generated_config["kv_transfer_config"]["kv_load_failure_policy"]
            == policy
        )
    with pytest.raises(ValueError, match="unsupported KV load failure policy"):
        MooncakeProvider().plan(
            manifest("mooncake-v0.2.json"),
            dict(configuration, kv_load_failure_policy="ignore"),
            enabled=True,
        )


def test_ascend_store_requires_host_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = {
        "connector": "AscendStoreConnector",
        "device_backend": "ascend",
        "transport_protocol": "ascend",
        "kv_connector_extra_config": {"backend": "mooncake"},
    }

    def missing(distribution: str) -> str:
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.version", missing)
    compatible, configured, evidence = (
        MooncakeProvider()._validate_runtime_configuration(
            configuration, "mooncake-transfer-engine-npu"
        )
    )
    assert not compatible and not configured
    assert evidence == ("AscendStoreConnector requires vllm-ascend",)
    monkeypatch.setattr(
        "vllm_hust_ext.providers.mooncake.version", lambda _: "0.25.1rc1"
    )
    compatible, configured, evidence = (
        MooncakeProvider()._validate_runtime_configuration(
            configuration, "mooncake-transfer-engine-npu"
        )
    )
    assert compatible and configured
    assert "detected vllm-ascend 0.25.1rc1" in evidence


def test_mooncake_unreachable_is_degraded_not_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def unreachable(*args: object, **kwargs: object) -> None:
        raise URLError("connection refused")

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.urlopen", unreachable)
    status = status_for(
        bundle(value),
        ExtensionConfig(True, {"health_url": "http://127.0.0.1:1/health"}),
        include_external_providers=False,
    )

    assert LifecycleState.ENABLED in status.states
    assert LifecycleState.DEGRADED in status.states
    assert LifecycleState.REACHABLE not in status.states


def test_mooncake_unversioned_surfaces_do_not_invent_protocol_semver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def installed_version(distribution: str) -> str:
        if distribution == "mooncake-transfer-engine-non-cuda":
            return "0.3.12.post1"
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.version", installed_version)
    check = MooncakeProvider().check(value, {})

    assert check.compatible is True
    assert any("not independently versioned" in item for item in check.evidence)
    assert not any(
        "protocol mooncake-store-rest 1.0" in item for item in check.evidence
    )


def test_mooncake_detects_official_npu_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def installed_version(distribution: str) -> str:
        if distribution == "mooncake-transfer-engine-npu":
            return "0.3.13.post1"
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.version", installed_version)
    check = MooncakeProvider().check(
        value,
        {"device_backend": "ascend", "transport_protocol": "ascend"},
    )

    assert check.compatible is True
    assert any("mooncake-transfer-engine-npu" in item for item in check.evidence)


def test_mooncake_rejects_multiple_runtime_variants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def installed_version(distribution: str) -> str:
        if distribution in {
            "mooncake-transfer-engine",
            "mooncake-transfer-engine-npu",
        }:
            return "0.3.13.post1"
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.version", installed_version)
    check = MooncakeProvider().check(value, {})

    assert check.compatible is False
    assert check.degraded is True
    assert any("multiple mutually exclusive" in item for item in check.evidence)


def test_mooncake_npu_requires_ascend_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def installed_version(distribution: str) -> str:
        if distribution == "mooncake-transfer-engine-npu":
            return "0.3.11.post1"
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.version", installed_version)
    check = MooncakeProvider().check(
        value,
        {
            "connector": "MooncakeStoreConnector",
            "transport_protocol": "tcp",
            "health_url": "http://127.0.0.1:50055/health",
        },
    )

    assert check.compatible is False
    assert check.configured is False
    assert check.degraded is True
    assert any("cannot dereference NPU" in item for item in check.evidence)


def test_mooncake_store_rejects_sync_load_on_validated_vllm_path() -> None:
    value = manifest("mooncake-v0.2.json")
    check = MooncakeProvider().check(
        value,
        {
            "connector": "MooncakeStoreConnector",
            "kv_connector_extra_config": {"load_async": False},
            "health_url": "http://127.0.0.1:50055/health",
        },
    )

    assert check.configured is False
    assert check.degraded is True
    assert any("requires load_async=true" in item for item in check.evidence)


def test_mooncake_operation_failures_degrade_an_otherwise_healthy_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def respond(*args: object, **kwargs: object) -> _HTTPResponse:
        return _HTTPResponse(b"ok")

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.urlopen", respond)
    check = MooncakeProvider().check(
        value,
        {
            "health_url": "http://127.0.0.1:50055/health",
            "connector_operation_evidence": {
                "lookup_exists_ok": 22,
                "save_put_ok": 9,
                "load_get_ok": 9,
                "failed_keys": 4,
            },
        },
    )

    assert check.reachable is True
    assert check.healthy is False
    assert check.degraded is True
    assert any("failed_keys=4" in item for item in check.evidence)


def test_production_stack_renders_but_never_applies() -> None:
    value = manifest("production-stack-v0.2.json")
    provider = ProductionStackProvider()
    plan = provider.plan(
        value,
        {"values": {"routerSpec": {"enableRouter": True}}},
        enabled=True,
    )
    artifacts = provider.render(plan)

    assert value.kind == "control_plane_extension"
    crd_carrier = next(item for item in value.implementation if item.type == "crd")
    assert dict(crd_carrier.attributes)["kinds"] == ["LoraAdapter"]
    assert all(not action.mutating for action in plan.actions)
    assert all("apply" not in action.operation for action in plan.actions)
    operator_plan = json.loads(artifacts[1].content)
    assert operator_plan["apply"] is None
    assert set(operator_plan["operator_owned_mutations"]) == {
        "install",
        "upgrade",
        "rollback",
        "uninstall",
    }
    assert all(
        value is None for value in operator_plan["operator_owned_mutations"].values()
    )
    assert operator_plan["render"]["mutating"] is False
    assert operator_plan["validate"]["mutating"] is False
    assert "check_ownership_conflicts" in {action.operation for action in plan.actions}
    assert operator_plan["verification"]["required_component_evidence"] == [
        "controller_reconciliation",
        "router_traffic",
        "autoscaler_decision",
    ]
    assert operator_plan["verification"]["required_router_data_plane_evidence"] == [
        "backend_kind",
        "model",
        "failure_http_status",
        "recovered_http_status",
        "response_marker",
        "router_version",
        "architecture",
        "release_image_supported",
    ]

    check = provider.check(value, {"values": {}})
    assert check.compatible is None
    assert check.degraded is True


def test_production_stack_refuses_unsubstantiated_healthy_state() -> None:
    value = manifest("production-stack-v0.2.json")
    provider = ProductionStackProvider()

    missing_cluster_evidence = provider.check(
        value,
        {
            "values": {},
            "cluster_reachable": True,
            "rollout_healthy": True,
        },
    )
    contradictory = provider.check(
        value,
        {
            "values": {},
            "cluster_reachable": False,
            "rollout_healthy": True,
            "rollout_evidence": "deployment available",
        },
    )

    assert missing_cluster_evidence.configured is False
    assert missing_cluster_evidence.degraded is True
    assert any("cluster_evidence" in item for item in missing_cluster_evidence.evidence)
    assert contradictory.configured is False
    assert any("cluster_reachable=true" in item for item in contradictory.evidence)

    missing_component_evidence = provider.check(
        value,
        {
            "values": {},
            "kube_context": "isolated-kind",
            "router_backend_endpoint": "http://model.default.svc:8000",
            "cluster_reachable": True,
            "cluster_evidence": "isolated Kubernetes API responded",
            "rollout_healthy": True,
            "rollout_evidence": "deployment available",
        },
    )
    assert missing_component_evidence.configured is False
    assert any(
        "controller_reconciliation" in item
        for item in missing_component_evidence.evidence
    )

    missing_service_configuration = provider.check(
        value,
        {
            "values": {},
            "cluster_reachable": True,
            "cluster_evidence": "isolated Kubernetes API responded",
            "rollout_healthy": True,
            "rollout_evidence": "deployment available",
            "component_evidence": {
                "controller_reconciliation": "owned resources reconciled",
                "router_traffic": "real model returned output",
                "autoscaler_decision": "HPA changed desired replicas",
            },
        },
    )
    assert missing_service_configuration.configured is False
    assert any(
        "kube_context" in item and "router_backend_endpoint" in item
        for item in missing_service_configuration.evidence
    )


def test_production_stack_projects_healthy_only_with_evidence() -> None:
    value = manifest("production-stack-v0.2.json")
    check = ProductionStackProvider().check(
        value,
        {
            "values": {},
            "kube_context": "isolated-kind",
            "router_backend_endpoint": "http://model.default.svc:8000",
            "host_version": "0.1.12",
            "host_api_version": "1.0",
            "protocol_versions": {
                "helm-values": "4.2.4",
                "kubernetes-api": "1.34.11",
            },
            "cluster_reachable": True,
            "cluster_evidence": "Kubernetes server v1.34.11 responded",
            "rollout_healthy": True,
            "rollout_evidence": "deployment available 1/1",
            "component_evidence": {
                "controller_reconciliation": "VLLMRouter owned Deployment and Service",
                "router_traffic": "POST /v1/chat/completions returned model output",
                "autoscaler_decision": "Metrics API drove replicas 1 to 3",
            },
            "router_data_plane_evidence": {
                "backend_kind": "real_model",
                "model": "test/model",
                "failure_http_status": 503,
                "recovered_http_status": 200,
                "response_marker": "ROUTER_OK",
                "router_version": "0.1.12",
                "architecture": "amd64",
                "release_image_supported": True,
            },
        },
    )

    assert check.compatible is True
    assert check.configured is True
    assert check.reachable is True
    assert check.healthy is True
    assert check.degraded is False
    assert any("deployment available 1/1" in item for item in check.evidence)


def test_production_stack_rejects_mock_router_as_healthy_evidence() -> None:
    value = manifest("production-stack-v0.2.json")
    check = ProductionStackProvider().check(
        value,
        {
            "values": {},
            "kube_context": "isolated-kind",
            "router_backend_endpoint": "http://model.default.svc:8000",
            "cluster_reachable": True,
            "cluster_evidence": "isolated Kubernetes API responded",
            "rollout_healthy": True,
            "rollout_evidence": "deployment available",
            "component_evidence": {
                "controller_reconciliation": "owned resources reconciled",
                "router_traffic": "mock backend returned a marker",
                "autoscaler_decision": "HPA changed desired replicas",
            },
            "router_data_plane_evidence": {
                "backend_kind": "mock",
                "model": "mock",
                "failure_http_status": 500,
                "recovered_http_status": 200,
                "response_marker": "MOCK_OK",
                "router_version": "0.1.12",
                "architecture": "amd64",
                "release_image_supported": True,
            },
        },
    )

    assert check.configured is False
    assert check.degraded is True
    assert any(
        "mock backends are smoke evidence only" in item for item in check.evidence
    )


def test_production_stack_projects_release_image_gap_as_degraded() -> None:
    value = manifest("production-stack-v0.2.json")
    check = ProductionStackProvider().check(
        value,
        {
            "values": {},
            "kube_context": "isolated-kind",
            "router_backend_endpoint": "http://127.0.0.1:8001",
            "host_version": "0.1.12",
            "host_api_version": "1.0",
            "protocol_versions": {
                "helm-values": "4.2.4",
                "kubernetes-api": "1.34.11",
            },
            "cluster_reachable": True,
            "cluster_evidence": "isolated Kubernetes API responded",
            "rollout_healthy": True,
            "rollout_evidence": "deployment available",
            "component_evidence": {
                "controller_reconciliation": "owned resources reconciled",
                "router_traffic": "real model returned ROUTER_OK",
                "autoscaler_decision": "HPA changed desired replicas",
            },
            "router_data_plane_evidence": {
                "backend_kind": "real_model",
                "model": "zai-org/GLM-4-32B-0414",
                "failure_http_status": 500,
                "recovered_http_status": 200,
                "response_marker": "ROUTER_OK",
                "router_version": "0.1.dev1+g1b87c11a2",
                "architecture": "arm64",
                "release_image_supported": False,
            },
        },
    )

    assert check.compatible is True
    assert check.healthy is True
    assert check.degraded is True
    assert any("source-built Router artifact" in item for item in check.evidence)


def test_production_stack_rejects_replica_ownership_conflict() -> None:
    value = manifest("production-stack-v0.2.json")
    check = ProductionStackProvider().check(
        value,
        {
            "values": {},
            "cluster_reachable": True,
            "cluster_evidence": "isolated Kubernetes API responded",
            "ownership_conflicts": [
                "VLLMRouter controller and HPA both write Deployment.spec.replicas"
            ],
        },
    )

    assert check.compatible is False
    assert check.configured is False
    assert check.healthy is False
    assert check.degraded is True
    assert any("ownership conflict" in item for item in check.evidence)


def test_core_rejects_provider_generated_mutation() -> None:
    value = manifest("bidkv-v0.2.json")
    plan = plan_for(
        bundle(value),
        ExtensionConfig(True, {}),
        include_external_providers=False,
    )
    assert all(not action.mutating for action in plan.actions)


def test_known_host_version_projects_compatible_or_incompatible() -> None:
    value = manifest("bidkv-v0.2.json")

    compatible = status_for(
        bundle(value),
        ExtensionConfig(
            True,
            {
                "host_version": "0.28.1rc1.dev319",
                "protocol_versions": {"vllm.preemption-policy": "1.0"},
                "runtime_qualification": {
                    "status": "passed",
                    "accelerator": "ascend",
                    "execution_mode": "graph",
                    "model": "Qwen3.8-27B",
                    "tensor_parallel_size": 4,
                },
            },
        ),
        include_external_providers=False,
    )
    incompatible = status_for(
        bundle(value),
        ExtensionConfig(True, {"host_version": "0.29.0"}),
        include_external_providers=False,
    )

    assert LifecycleState.COMPATIBLE in compatible.states
    assert LifecycleState.RUNTIME_EFFECTIVE not in compatible.states
    assert LifecycleState.INCOMPATIBLE in incompatible.states


def test_bidkv_source_contract_does_not_claim_runtime_compatibility() -> None:
    value = manifest("bidkv-v0.2.json")

    status = status_for(
        bundle(value),
        ExtensionConfig(
            True,
            {
                "host_version": "0.28.1rc1.dev319",
                "protocol_versions": {"vllm.preemption-policy": "1.0"},
            },
        ),
        include_external_providers=False,
    )

    assert LifecycleState.COMPATIBLE not in status.states
    assert LifecycleState.ENABLED in status.states
    assert LifecycleState.RUNTIME_EFFECTIVE not in status.states
    assert LifecycleState.DEGRADED in status.states
    assert any("qualification is unavailable" in item for item in status.evidence)


def test_vllm_does_not_assume_a_fork_only_protocol_exists() -> None:
    value = manifest("bidkv-v0.2.json")

    unverified = status_for(
        bundle(value),
        ExtensionConfig(True, {"host_version": "0.28.1rc1.dev319"}),
        include_external_providers=False,
    )

    assert LifecycleState.COMPATIBLE not in unverified.states
    assert LifecycleState.DEGRADED in unverified.states
    assert any(
        "protocol vllm.preemption-policy" in item for item in unverified.evidence
    )


def test_conflicting_provider_plans_are_rejected() -> None:
    plans = (
        ProviderPlan("one", "vllm", (), {"additional_config": {"policy": "a"}}),
        ProviderPlan("two", "vllm", (), {"additional_config": {"policy": "b"}}),
    )

    with pytest.raises(ValueError, match="conflict"):
        reject_conflicting_plans(plans)


@pytest.mark.parametrize(
    ("directory", "provider"),
    [
        ("mooncake-provider", "mooncake"),
        ("production-stack-provider", "production-stack"),
    ],
)
def test_installable_provider_profiles_use_project_owned_namespace(
    directory: str, provider: str
) -> None:
    root = EXAMPLES / directory
    manifest_path = next(root.glob("src/*/manifests/vllm-hust-extension-v0.2.json"))
    value = parse_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert value.host.provider == provider
    assert '[project.entry-points."vllm_hust.extension_bundles"]' in pyproject
    assert "vllm.extension_bundles" not in pyproject
    assert 'dependencies = ["vllm-hust-ext==0.2.0.dev0"]' in pyproject
