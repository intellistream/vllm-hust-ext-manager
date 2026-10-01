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
    _validate_dependency_removal,
    _validate_extension_dependencies,
)
from vllm_hust_ext.config import ExtensionConfig, UserConfig
from vllm_hust_ext.core import LifecycleState
from vllm_hust_ext.discovery import DiscoveryDiagnostic
from vllm_hust_ext.manifest import (
    ActivationEntryPoint,
    BundleActivation,
    HostSpec,
    ImplementationCarrier,
    RequiredExtension,
    RequiredService,
    ResourceClaim,
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


def test_list_reports_invalid_bundle_without_hiding_valid_bundle(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    valid = SimpleNamespace(
        bundle_id="org.vllm-hust.valid",
        manifest=SimpleNamespace(bundle_version="1.0"),
    )
    monkeypatch.setattr(cli, "load_config", UserConfig)
    monkeypatch.setattr(
        cli,
        "discover_bundle_inventory",
        lambda: (
            (valid,),
            (DiscoveryDiagnostic("org.vllm-hust.invalid", "manifest is invalid"),),
        ),
    )
    monkeypatch.setattr(
        cli,
        "_bundle_dict",
        lambda _bundle, _enabled, _versions: {
            "bundle_id": "org.vllm-hust.valid",
            "bundle_version": "1.0",
            "enabled": False,
        },
    )

    result = cli._extension_command(SimpleNamespace(action="list", json=False))

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == "org.vllm-hust.valid 1.0 disabled\n"
    assert captured.err == ("org.vllm-hust.invalid invalid manifest is invalid\n")


def test_json_list_includes_structured_invalid_bundle_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_config", UserConfig)
    monkeypatch.setattr(
        cli,
        "discover_bundle_inventory",
        lambda: (
            (),
            (DiscoveryDiagnostic("org.vllm-hust.invalid", "broken descriptor"),),
        ),
    )

    result = cli._extension_command(SimpleNamespace(action="list", json=True))

    assert result == 0
    assert json.loads(capsys.readouterr().out) == [
        {
            "bundle_id": "org.vllm-hust.invalid",
            "discovery_error": "broken descriptor",
            "valid": False,
        }
    ]


def test_activation_merges_vllm_plugin_entry_points_with_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VLLM_PLUGINS", "ascend,existing")
    bundle = SimpleNamespace(
        bundle_id="org.vllm-hust.kv-materialization-arrival-control",
        manifest=SimpleNamespace(
            activation=BundleActivation(
                entry_points=(
                    ActivationEntryPoint("vllm.general_plugins", "kv_materialization"),
                    ActivationEntryPoint("unrelated.group", "ignored"),
                )
            )
        ),
    )

    environment = _activation_environment((bundle,))

    assert environment["VLLM_PLUGINS"] == "ascend,existing,kv_materialization"


def test_activation_keeps_ascend_and_orders_bundles_deterministically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VLLM_PLUGINS", raising=False)

    def bundle(bundle_id: str, group: str, name: str) -> SimpleNamespace:
        return SimpleNamespace(
            bundle_id=bundle_id,
            manifest=SimpleNamespace(
                activation=BundleActivation(
                    entry_points=(ActivationEntryPoint(group, name),)
                )
            ),
        )

    general = bundle("org.example.z-general", "vllm.general_plugins", "general")
    platform = bundle("org.example.a-platform", "vllm.platform_plugins", "platform")

    first = _activation_environment((general, platform))
    second = _activation_environment((platform, general))

    assert first["VLLM_PLUGINS"] == "ascend,platform,general"
    assert second["VLLM_PLUGINS"] == first["VLLM_PLUGINS"]


def test_activation_rejects_plugin_name_owned_by_two_extensions() -> None:
    def bundle(bundle_id: str, group: str) -> SimpleNamespace:
        return SimpleNamespace(
            bundle_id=bundle_id,
            manifest=SimpleNamespace(
                activation=BundleActivation(
                    entry_points=(ActivationEntryPoint(group, "shared"),)
                )
            ),
        )

    with pytest.raises(ValueError, match="both declare.*shared"):
        _activation_environment(
            (
                bundle("org.example.general", "vllm.general_plugins"),
                bundle("org.example.platform", "vllm.platform_plugins"),
            )
        )


def test_disabled_extension_does_not_project_vllm_plugin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VLLM_PLUGINS", "user-selection")

    environment = _activation_environment(())

    assert "VLLM_PLUGINS" not in environment


def test_activation_deduplicates_explicit_plugin_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VLLM_PLUGINS", "ascend,kv_materialization")
    bundle = SimpleNamespace(
        bundle_id="org.vllm-hust.kv-materialization-arrival-control",
        manifest=SimpleNamespace(
            activation=BundleActivation(
                entry_points=(
                    ActivationEntryPoint("vllm.general_plugins", "kv_materialization"),
                )
            )
        ),
    )

    environment = _activation_environment((bundle,))

    assert environment["VLLM_PLUGINS"] == "ascend,kv_materialization"


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


def test_inspection_fails_activation_ready_when_dependency_is_disabled() -> None:
    bundle = SimpleNamespace(
        bundle_id="org.example.consumer",
        distribution_name="consumer",
        distribution_version="1.0.0",
        manifest_path=Path("consumer.json"),
        manifest=SimpleNamespace(
            bundle_version="1.0.0",
            kind="in_process_plugin",
            host=HostSpec("vllm", "vllm", ">=0"),
            runtime=RuntimeSpec("python", "vllm-worker", "trusted_in_process"),
            lifecycle_owner="vllm",
            protocols=(),
            implementation=(ImplementationCarrier("host_builtin", (("name", "x"),)),),
            requires_services=(),
            requires_extensions=(RequiredExtension("org.example.provider", ">=1,<2"),),
            resource_claims=(),
            experimental=True,
            components=(),
            activation=BundleActivation(),
        ),
    )

    value = _bundle_dict(
        bundle,
        set(),
        {"org.example.consumer": "1.0.0", "org.example.provider": "1.2.0"},
    )

    assert value["activation_ready"] is False
    assert value["activation_blocker"] == (
        "required extension 'org.example.provider' is not enabled"
    )
    assert value["requires_extensions"][0]["installed"] is True


def _dependency_bundle(
    bundle_id: str,
    version: str = "1.0.0",
    dependencies: tuple[RequiredExtension, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        bundle_id=bundle_id,
        manifest=SimpleNamespace(
            bundle_version=version,
            requires_extensions=dependencies,
        ),
    )


def test_extension_dependencies_require_enabled_compatible_bundle() -> None:
    consumer = _dependency_bundle(
        "org.example.consumer",
        dependencies=(RequiredExtension("org.example.provider", ">=1,<2"),),
    )

    with pytest.raises(ValueError, match="requires enabled extension"):
        _validate_extension_dependencies((consumer,))

    with pytest.raises(ValueError, match="found 2.0.0"):
        _validate_extension_dependencies(
            (consumer, _dependency_bundle("org.example.provider", "2.0.0"))
        )

    _validate_extension_dependencies(
        (consumer, _dependency_bundle("org.example.provider", "1.4.0"))
    )


def test_extension_dependencies_reject_cycles() -> None:
    first = _dependency_bundle(
        "org.example.first",
        dependencies=(RequiredExtension("org.example.second", ">=1"),),
    )
    second = _dependency_bundle(
        "org.example.second",
        dependencies=(RequiredExtension("org.example.first", ">=1"),),
    )

    with pytest.raises(ValueError, match="dependency cycle"):
        _validate_extension_dependencies((first, second))


def test_enabled_dependent_blocks_dependency_removal() -> None:
    provider = _dependency_bundle("org.example.provider")
    consumer = _dependency_bundle(
        "org.example.consumer",
        dependencies=(RequiredExtension("org.example.provider", ">=1"),),
    )

    with pytest.raises(ValueError, match="org.example.consumer"):
        _validate_dependency_removal("org.example.provider", (provider, consumer))


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


def test_vllm_provider_merges_declared_boolean_flag() -> None:
    plan = ProviderPlan(
        "org.vllm-hust.dla",
        "vllm",
        (),
        {"vllm_flags": ["--scheduler-reserve-output-budget"]},
    )

    command = _merge_provider_plan(["vllm", "serve", "model"], plan)

    assert command[-1] == "--scheduler-reserve-output-budget"


def test_vllm_provider_rejects_unknown_boolean_flag() -> None:
    plan = ProviderPlan(
        "org.vllm-hust.example",
        "vllm",
        (),
        {"vllm_flags": ["--enforce-eager"]},
    )

    with pytest.raises(ValueError, match="unsupported provider flag"):
        _merge_provider_plan(["vllm", "serve", "model"], plan)


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


def test_run_refuses_multiple_stateaxis_process_owners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extension_ids = (
        "org.stateaxis.hybrid-branch-coherence",
        "org.stateaxis.no-harm-preparation",
    )
    bundles = tuple(
        SimpleNamespace(
            bundle_id=extension_id,
            manifest=SimpleNamespace(
                host=SimpleNamespace(provider="stateaxis"),
                runtime=SimpleNamespace(
                    process_scope="stateaxis_processes",
                    isolation="trusted_in_process",
                ),
            ),
        )
        for extension_id in extension_ids
    )
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig(
            {
                extension_id: ExtensionConfig(enabled=True)
                for extension_id in extension_ids
            }
        ),
    )
    monkeypatch.setattr(cli, "discover_bundles", lambda *_args: bundles)

    with pytest.raises(ValueError, match="only one StateAxis ECPA carrier"):
        cli._run_command(SimpleNamespace(command=["stateaxis"], dry_run=True))


def test_enable_refuses_second_stateaxis_process_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = "org.stateaxis.hybrid-branch-coherence"
    second = "org.stateaxis.no-harm-preparation"
    bundles = tuple(
        SimpleNamespace(
            bundle_id=extension_id,
            manifest=SimpleNamespace(
                host=SimpleNamespace(provider="stateaxis"),
                runtime=SimpleNamespace(
                    process_scope="stateaxis_processes",
                    isolation="trusted_in_process",
                ),
                implementation=(),
            ),
        )
        for extension_id in (first, second)
    )
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({first: ExtensionConfig(enabled=True)}),
    )

    def discover(selected):
        return tuple(bundle for bundle in bundles if bundle.bundle_id in selected)

    monkeypatch.setattr(cli, "discover_bundles", discover)
    monkeypatch.setattr(cli, "save_config", lambda *_args: pytest.fail("must not save"))

    with pytest.raises(ValueError, match="only one StateAxis ECPA carrier"):
        cli._extension_command(SimpleNamespace(action="enable", bundle_id=second))


def test_enable_refuses_conflicting_manifest_resource_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = "org.example.first-scheduler"
    second = "org.example.second-scheduler"
    claim = ResourceClaim("vllm.scheduler.policy", "vllm-process", "exclusive")
    bundles = tuple(
        SimpleNamespace(
            bundle_id=extension_id,
            manifest=SimpleNamespace(
                host=SimpleNamespace(provider="vllm"),
                runtime=SimpleNamespace(
                    process_scope="scheduler",
                    isolation="trusted_in_process",
                ),
                implementation=(),
                resource_claims=(claim,),
            ),
        )
        for extension_id in (first, second)
    )
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda: UserConfig({first: ExtensionConfig(enabled=True)}),
    )

    def discover(selected):
        return tuple(bundle for bundle in bundles if bundle.bundle_id in selected)

    monkeypatch.setattr(cli, "discover_bundles", discover)
    monkeypatch.setattr(cli, "save_config", lambda *_args: pytest.fail("must not save"))

    with pytest.raises(ValueError, match="vllm-process:vllm.scheduler.policy"):
        cli._extension_command(SimpleNamespace(action="enable", bundle_id=second))


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


def test_run_dry_run_projects_declared_plugin_activation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    extension_id = "org.vllm-hust.arrival-control"
    manifest = SimpleNamespace(
        host=SimpleNamespace(provider="vllm"),
        kind="in_process_plugin",
        runtime=SimpleNamespace(isolation="trusted_in_process"),
        activation=BundleActivation(
            entry_points=(
                ActivationEntryPoint("vllm.general_plugins", "arrival_control"),
            )
        ),
    )
    bundle = SimpleNamespace(bundle_id=extension_id, manifest=manifest)
    monkeypatch.delenv("VLLM_PLUGINS", raising=False)
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

    payload = json.loads(capsys.readouterr().out)
    assert payload["environment"]["VLLM_PLUGINS"] == "ascend,arrival_control"


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
