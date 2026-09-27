import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import vllm_hust_ext.cli as cli
from vllm_hust_ext.cli import (
    _activation_environment,
    _bundle_dict,
    _merge_command_config,
    _merge_provider_plan,
)
from vllm_hust_ext.config import ExtensionConfig, UserConfig
from vllm_hust_ext.core import LifecycleState
from vllm_hust_ext.manifest import (
    BundleActivation,
    HostSpec,
    ImplementationCarrier,
    RequiredService,
    RuntimeSpec,
)
from vllm_hust_ext.providers.base import PlanAction, ProviderPlan


def test_activation_does_not_replace_vllm_plugin_allowlist() -> None:
    bundle = SimpleNamespace(
        bundle_id="org.vllm-hust.bidkv",
        manifest=SimpleNamespace(
            activation=BundleActivation(environment=(("BIDKV_UTILITY_ENABLE", "1"),))
        ),
    )

    environment = _activation_environment((bundle,))

    assert environment == {
        "BIDKV_UTILITY_ENABLE": "1",
        "VLLMHUST_EXT_ENABLED_BUNDLES": "org.vllm-hust.bidkv",
    }
    assert "VLLM_PLUGINS" not in environment


def test_inspection_exposes_import_only_activation_blocker() -> None:
    carrier = ImplementationCarrier(
        "python_module",
        (
            ("module", "example"),
            ("object", "Descriptor"),
            ("status", "import_only"),
        ),
    )
    bundle = SimpleNamespace(
        bundle_id="org.vllm-hust.descriptor",
        bundle_version="0.1.0",
        distribution_name="descriptor",
        distribution_version="0.1.0",
        manifest_path=Path("descriptor.json"),
        manifest=SimpleNamespace(
            bundle_version="0.1.0",
            kind="in_process_plugin",
            host=HostSpec("vllm", "vllm", ">=0"),
            runtime=RuntimeSpec("python", "vllm-worker", "trusted_in_process"),
            lifecycle_owner="vllm",
            protocols=(),
            implementation=(carrier,),
            requires_services=(),
            experimental=True,
            components=(),
            activation=BundleActivation(),
        ),
    )

    value = _bundle_dict(bundle, set())

    assert value["activation_ready"] is False
    assert "descriptor-only" in str(value["activation_blocker"])
    assert value["implementation"][0]["status"] == "import_only"


def test_run_merges_existing_additional_config() -> None:
    command = ["vllm", "serve", "model", "--additional-config", '{"user":1}']

    merged = _merge_command_config(command, {"victim_selector_plugin": "bidkv"})

    assert merged[-1] == '{"user":1,"victim_selector_plugin":"bidkv"}'


def test_run_rejects_activation_conflict() -> None:
    command = [
        "vllm",
        "serve",
        "model",
        "--additional-config",
        '{"victim_selector_plugin":"other"}',
    ]

    with pytest.raises(ValueError, match="conflicts"):
        _merge_command_config(command, {"victim_selector_plugin": "bidkv"})


def connector_plan(provider: str, connector: str) -> ProviderPlan:
    return ProviderPlan(
        f"org.vllm-hust.{provider}-provider",
        provider,
        (
            PlanAction(
                "render_connector_config",
                "vllm",
                "vllm",
                mutating=False,
            ),
        ),
        {
            "kv_transfer_config": {
                "kv_connector": connector,
                "kv_role": "kv_both",
            }
        },
    )


@pytest.mark.parametrize(
    ("provider", "connector"),
    [
        ("mooncake", "MooncakeStoreConnector"),
    ],
)
def test_run_merges_any_declared_vllm_connector_capability(
    provider: str, connector: str
) -> None:
    command = _merge_provider_plan(
        ["vllm", "serve", "model"], connector_plan(provider, connector)
    )

    assert command[-2] == "--kv-transfer-config"
    assert json.loads(command[-1])["kv_connector"] == connector


def test_run_rejects_two_connectors_claiming_vllm_transfer_config() -> None:
    command = _merge_provider_plan(
        ["vllm", "serve", "model"],
        connector_plan("mooncake", "MooncakeStoreConnector"),
    )

    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(
            command,
            connector_plan("other", "OtherConnector"),
        )


def test_run_rejects_connector_config_without_declared_vllm_action() -> None:
    plan = ProviderPlan(
        "org.example.invalid",
        "invalid",
        (),
        {"kv_transfer_config": {"kv_connector": "Invalid"}},
    )

    with pytest.raises(ValueError, match="render_connector_config"):
        _merge_provider_plan(["vllm", "serve", "model"], plan)


def test_vllm_provider_merges_declared_speculative_config() -> None:
    plan = ProviderPlan(
        "org.vllm-hust.diffspec",
        "vllm",
        (),
        {
            "vllm_json_options": {
                "--speculative-config": {
                    "method": "eagle3",
                    "draft_context_policy": "diffspec",
                }
            }
        },
    )

    command = _merge_provider_plan(["vllm", "serve", "model"], plan)

    assert command[-2] == "--speculative-config"
    assert json.loads(command[-1]) == {
        "method": "eagle3",
        "draft_context_policy": "diffspec",
    }


def test_vllm_provider_rejects_conflicting_speculative_config() -> None:
    plan = ProviderPlan(
        "org.vllm-hust.diffspec",
        "vllm",
        (),
        {"vllm_json_options": {"--speculative-config": {"method": "eagle3"}}},
    )

    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(
            ["vllm", "serve", "model", "--speculative-config", '{"method":"ngram"}'],
            plan,
        )


def test_vllm_provider_merges_batch_admission_policy_config() -> None:
    config = {"mode": "balanced", "microbatch_count": 2}
    plan = ProviderPlan(
        "org.vllm-hust.pipeline-microbatch",
        "vllm",
        (),
        {"vllm_json_options": {"--batch-admission-policy-config": config}},
    )

    command = _merge_provider_plan(["vllm", "serve", "model"], plan)

    assert command[-2] == "--batch-admission-policy-config"
    assert json.loads(command[-1]) == config


def test_vllm_provider_merges_declared_preemption_policy() -> None:
    implementation = "bidkv.adapters.vllm_hust.selector:BidkvPreemptionPolicy"
    plan = ProviderPlan(
        "org.vllm-hust.bidkv",
        "vllm",
        (),
        {"vllm_options": {"--preemption-policy": implementation}},
    )

    command = _merge_provider_plan(["vllm", "serve", "model"], plan)

    assert command[-2:] == ["--preemption-policy", implementation]


def test_vllm_provider_rejects_conflicting_preemption_policy() -> None:
    plan = ProviderPlan(
        "org.vllm-hust.bidkv",
        "vllm",
        (),
        {"vllm_options": {"--preemption-policy": "example:Bidkv"}},
    )

    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(
            ["vllm", "serve", "model", "--preemption-policy=example:Other"],
            plan,
        )


def test_forget_refuses_enabled_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    extension_id = "org.vllm-hust.bidkv"
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )

    with pytest.raises(ValueError, match="disable"):
        cli._extension_command(SimpleNamespace(action="forget", bundle_id=extension_id))


def test_enable_refuses_import_only_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.descriptor"
    manifest = SimpleNamespace(
        implementation=(
            ImplementationCarrier(
                "python_module",
                (
                    ("module", "example"),
                    ("object", "Descriptor"),
                    ("status", "import_only"),
                ),
            ),
        )
    )
    monkeypatch.setattr(cli, "load_config", UserConfig)
    monkeypatch.setattr(
        cli,
        "discover_bundles",
        lambda *_args: (SimpleNamespace(manifest=manifest),),
    )

    with pytest.raises(ValueError, match="descriptor-only"):
        cli._extension_command(SimpleNamespace(action="enable", bundle_id=extension_id))


def test_forget_removes_disabled_stored_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.bidkv"
    saved: list[UserConfig] = []
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=False)}),
    )
    monkeypatch.setattr(cli, "save_config", saved.append)

    result = cli._extension_command(
        SimpleNamespace(action="forget", bundle_id=extension_id)
    )

    assert result == 0
    assert saved == [UserConfig()]


def test_run_refuses_unverified_in_process_scheduler_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.bidkv"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="vllm"),
        kind="scheduler_policy",
        runtime=SimpleNamespace(isolation="trusted_in_process"),
        activation=BundleActivation(),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: (bundle,))
    monkeypatch.setattr(
        cli,
        "status_for",
        lambda *_args: SimpleNamespace(
            states=(), evidence=("protocol version is unavailable",)
        ),
    )

    with pytest.raises(ValueError, match="unverified trusted in-process extension"):
        cli._run_command(SimpleNamespace(command=["vllm"], dry_run=True))


def test_run_accepts_scheduler_policy_only_after_compatibility_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.bidkv"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="vllm"),
        kind="scheduler_policy",
        runtime=SimpleNamespace(isolation="trusted_in_process"),
        activation=BundleActivation(),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: (bundle,))
    monkeypatch.setattr(
        cli,
        "status_for",
        lambda *_args: SimpleNamespace(
            states=(LifecycleState.COMPATIBLE,), evidence=("verified",)
        ),
    )
    monkeypatch.setattr(
        cli, "plan_for", lambda *_args: ProviderPlan(extension_id, "vllm", ())
    )

    assert cli._run_command(SimpleNamespace(command=["true"], dry_run=True)) == 0


def test_run_materializes_native_manifest_for_vllm_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.bidkv"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="vllm"),
        kind="scheduler_policy",
        runtime=SimpleNamespace(isolation="trusted_in_process"),
        activation=BundleActivation(),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    native_manifest = {
        "schema_version": "1.0",
        "bundle_id": extension_id,
        "bundle_version": "0.1.1",
        "host_api_range": ">=1,<2",
        "components": [],
    }
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: (bundle,))
    monkeypatch.setattr(
        cli,
        "status_for",
        lambda *_args: SimpleNamespace(
            states=(LifecycleState.COMPATIBLE,), evidence=("verified",)
        ),
    )
    monkeypatch.setattr(
        cli,
        "plan_for",
        lambda *_args: ProviderPlan(
            extension_id,
            "vllm",
            (),
            {"native_extension_manifest": native_manifest},
        ),
    )
    monkeypatch.delenv("VLLM_EXTENSION_MANIFESTS", raising=False)
    monkeypatch.delenv("VLLM_EXTENSION_BUNDLES", raising=False)

    def supervise(
        command: list[str],
        *,
        env: dict[str, str],
        shutdown_grace_seconds: float,
    ) -> int:
        paths = env["VLLM_EXTENSION_MANIFESTS"].split(os.pathsep)
        assert len(paths) == 1
        assert json.loads(Path(paths[0]).read_text(encoding="utf-8")) == native_manifest
        assert env["VLLM_EXTENSION_BUNDLES"] == extension_id
        assert shutdown_grace_seconds == 10
        return 17

    monkeypatch.setattr(cli, "supervise", supervise)

    assert cli._run_command(SimpleNamespace(command=["true"], dry_run=False)) == 17


def test_run_refuses_any_enabled_incompatible_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.example"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="mooncake"),
        kind="kv_service_adapter",
        activation=BundleActivation(),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: (bundle,))
    monkeypatch.setattr(
        cli,
        "status_for",
        lambda *_args: SimpleNamespace(
            states=(LifecycleState.INCOMPATIBLE,),
            evidence=("host version is outside the declared range",),
        ),
    )

    with pytest.raises(ValueError, match="refusing to launch incompatible extension"):
        cli._run_command(SimpleNamespace(command=["vllm"], dry_run=True))


def test_run_refuses_unhealthy_required_external_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_id = "org.vllm-hust.pegaflow"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="pegaflow"),
        kind="kv_service_adapter",
        activation=BundleActivation(),
        implementation=(),
        requires_services=(
            RequiredService(
                "pegaflow-server",
                "http-health",
                None,
                "health_url",
            ),
        ),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({extension_id: ExtensionConfig(enabled=True)}),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: (bundle,))
    monkeypatch.setattr(
        cli,
        "status_for",
        lambda *_args: SimpleNamespace(
            states=(LifecycleState.CONFIGURED, LifecycleState.DEGRADED),
            evidence=("PegaFlow service is unreachable",),
        ),
    )

    with pytest.raises(ValueError, match="required service health is not verified"):
        cli._run_command(SimpleNamespace(command=["vllm"], dry_run=True))
