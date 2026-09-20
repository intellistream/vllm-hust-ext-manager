"""Command-line lifecycle manager."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from vllm_hust_ext.catalog import load_catalog
from vllm_hust_ext.config import ExtensionConfig, load_config, save_config
from vllm_hust_ext.core import (
    LifecycleState,
    plan_dict,
    plan_for,
    render_plan,
    status_for,
)
from vllm_hust_ext.discovery import InstalledBundle, discover_bundles
from vllm_hust_ext.manager_controller import (
    activation_probe_receipt,
    launch_managed,
)
from vllm_hust_ext.manifest import activation_blocker
from vllm_hust_ext.providers.base import ProviderPlan


def _bundle_dict(bundle: InstalledBundle, enabled: set[str]) -> dict[str, object]:
    blocker = activation_blocker(bundle.manifest)
    return {
        "bundle_id": bundle.bundle_id,
        "bundle_version": bundle.manifest.bundle_version,
        "distribution": bundle.distribution_name,
        "distribution_version": bundle.distribution_version,
        "enabled": bundle.bundle_id in enabled,
        "kind": bundle.manifest.kind,
        "host": asdict(bundle.manifest.host),
        "runtime": asdict(bundle.manifest.runtime),
        "lifecycle_owner": bundle.manifest.lifecycle_owner,
        "protocols": [asdict(protocol) for protocol in bundle.manifest.protocols],
        "implementation": [
            {"type": carrier.type, **dict(carrier.attributes)}
            for carrier in bundle.manifest.implementation
        ],
        "requires_services": [
            asdict(service) for service in bundle.manifest.requires_services
        ],
        "activation_ready": blocker is None,
        "activation_blocker": blocker,
        "experimental": bundle.manifest.experimental,
        "components": [asdict(component) for component in bundle.manifest.components],
        "activation": asdict(bundle.manifest.activation),
        "manifest_path": str(bundle.manifest_path),
    }


def _activation_environment(bundles: Sequence[InstalledBundle]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for bundle in bundles:
        for key, value in bundle.manifest.activation.environment:
            if key in environment and environment[key] != value:
                raise ValueError(
                    f"enabled Bundles disagree on environment variable {key}"
                )
            environment[key] = value
    environment["VLLMHUST_EXT_ENABLED_BUNDLES"] = ",".join(
        bundle.bundle_id for bundle in bundles
    )
    return environment


def _activation_config(bundles: Sequence[InstalledBundle]) -> dict[str, object]:
    merged: dict[str, object] = {}
    for bundle in bundles:
        for key, value in bundle.manifest.activation.additional_config:
            if key in merged and merged[key] != value:
                raise ValueError(
                    f"enabled Bundles disagree on additional_config key {key}"
                )
            merged[key] = value
    return merged


def _merge_command_config(
    command: list[str], activation: dict[str, object]
) -> list[str]:
    if not activation:
        return command
    result = list(command)
    existing: dict[str, object] = {}
    option_index: int | None = None
    for index, argument in enumerate(result):
        if argument == "--additional-config":
            if index + 1 >= len(result):
                raise ValueError("--additional-config requires a JSON object")
            option_index = index
            raw = result[index + 1]
            break
        if argument.startswith("--additional-config="):
            option_index = index
            raw = argument.partition("=")[2]
            break
    else:
        raw = None
    if raw is not None:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("--additional-config must contain a JSON object")
        existing = parsed
    conflicts = {
        key
        for key, value in activation.items()
        if key in existing and existing[key] != value
    }
    if conflicts:
        raise ValueError(
            "plugin activation conflicts with additional_config keys: "
            f"{sorted(conflicts)}"
        )
    existing.update(activation)
    encoded = json.dumps(existing, separators=(",", ":"), sort_keys=True)
    if option_index is None:
        result.extend(("--additional-config", encoded))
    elif result[option_index] == "--additional-config":
        result[option_index + 1] = encoded
    else:
        result[option_index] = f"--additional-config={encoded}"
    return result


def _extension_command(args: argparse.Namespace) -> int:
    config = load_config()
    enabled = set(config.enabled)
    if args.action == "list":
        bundles = discover_bundles()
        payload = [_bundle_dict(bundle, enabled) for bundle in bundles]
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for item in payload:
                state = "enabled" if item["enabled"] else "disabled"
                print(f"{item['bundle_id']} {item['bundle_version']} {state}")
        return 0
    if args.action in {"inspect", "validate"}:
        bundle = discover_bundles((args.bundle_id,))[0]
        print(json.dumps(_bundle_dict(bundle, enabled), indent=2, sort_keys=True))
        return 0
    if args.action == "enable":
        bundle = discover_bundles((args.bundle_id,))[0]
        blocker = activation_blocker(bundle.manifest)
        if blocker is not None:
            raise ValueError(f"cannot enable {args.bundle_id!r}: {blocker}")
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(True, current.configuration),
            )
        )
        print(f"enabled {args.bundle_id}")
        return 0
    if args.action == "disable":
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(False, current.configuration),
            )
        )
        print(f"disabled {args.bundle_id}")
        return 0
    if args.action == "forget":
        current = config.extensions.get(args.bundle_id)
        if current is None:
            raise ValueError(f"extension {args.bundle_id!r} has no stored state")
        if current.enabled:
            raise ValueError(
                f"disable {args.bundle_id!r} before forgetting its stored state"
            )
        save_config(config.without_extension(args.bundle_id))
        print(f"forgot {args.bundle_id}")
        return 0
    if args.action == "configure":
        discover_bundles((args.bundle_id,))
        configuration = json.loads(Path(args.file).read_text(encoding="utf-8"))
        if not isinstance(configuration, dict):
            raise ValueError("extension configuration file must contain an object")
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(current.enabled, configuration),
            )
        )
        print(f"configured {args.bundle_id}")
        return 0
    if args.action in {"status", "check", "plan", "render"}:
        bundle = discover_bundles((args.bundle_id,))[0]
        extension = config.extension(args.bundle_id)
        if args.action in {"status", "check"}:
            print(json.dumps(status_for(bundle, extension).as_dict(), indent=2))
            return 0
        plan = plan_for(bundle, extension)
        if args.action == "plan":
            print(json.dumps(plan_dict(plan), indent=2, sort_keys=True))
            return 0
        artifacts = [asdict(artifact) for artifact in render_plan(plan)]
        print(json.dumps(artifacts, indent=2, sort_keys=True))
        return 0
    if args.action == "env":
        bundles = discover_bundles(config.enabled) if config.enabled else ()
        print(json.dumps(_activation_environment(bundles), indent=2, sort_keys=True))
        return 0
    raise AssertionError(args.action)


def _catalog_command(args: argparse.Namespace) -> int:
    catalog = load_catalog(Path(args.file))
    if args.action == "validate":
        print(
            json.dumps(
                {
                    "schema": catalog["schema"],
                    "extensions": len(catalog["extensions"]),
                    "valid": True,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.action == "list":
        entries = [
            entry
            for entry in catalog["extensions"]
            if args.include_preview or entry["availability"] != "preview"
        ]
        if args.json:
            print(json.dumps(entries, indent=2, sort_keys=True))
        else:
            for entry in entries:
                print(
                    f"{entry['id']} {entry['maturity']} "
                    f"{entry['availability']} {entry['recommendation']['level']}"
                )
        return 0
    if args.action == "inspect":
        for entry in catalog["extensions"]:
            if entry["id"] == args.extension_id:
                print(json.dumps(entry, indent=2, sort_keys=True))
                return 0
        raise ValueError(f"catalog extension {args.extension_id!r} was not found")
    raise AssertionError(args.action)


def _run_command(args: argparse.Namespace) -> int:
    config = load_config()
    bundles = discover_bundles(config.enabled) if config.enabled else ()
    for bundle in bundles:
        blocker = activation_blocker(bundle.manifest)
        if blocker is not None:
            raise ValueError(f"refusing to launch {bundle.bundle_id!r}: {blocker}")
        extension = config.extension(bundle.bundle_id)
        status = status_for(bundle, extension)
        if LifecycleState.INCOMPATIBLE in status.states:
            raise ValueError(
                f"refusing to launch incompatible extension {bundle.bundle_id!r}: "
                + "; ".join(status.evidence)
            )
        required_services = tuple(
            service
            for service in getattr(bundle.manifest, "requires_services", ())
            if not service.optional
        )
        if required_services and LifecycleState.HEALTHY not in status.states:
            service_ids = ", ".join(service.service_id for service in required_services)
            raise ValueError(
                f"refusing to launch {bundle.bundle_id!r}: required service "
                f"health is not verified ({service_ids}); " + "; ".join(status.evidence)
            )
        if (
            bundle.manifest.host.provider == "vllm"
            and bundle.manifest.runtime.isolation == "trusted_in_process"
            and LifecycleState.COMPATIBLE not in status.states
        ):
            raise ValueError(
                f"refusing to launch unverified trusted in-process extension "
                f"{bundle.bundle_id!r}: " + "; ".join(status.evidence)
            )
    activation = _activation_environment(bundles)
    command = list(args.command or ["vllm"])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("run requires a command after --")
    command = _merge_command_config(command, _activation_config(bundles))
    plans = []
    for bundle in bundles:
        extension = config.extension(bundle.bundle_id)
        plan = plan_for(bundle, extension)
        plans.append(plan)
        command = _merge_provider_plan(command, plan)
    native_manifests = [
        (plan.extension_id, plan.generated_config["native_extension_manifest"])
        for plan in plans
        if "native_extension_manifest" in plan.generated_config
    ]
    if args.dry_run:
        print(
            json.dumps(
                {
                    "command": command,
                    "environment": activation,
                    "native_extension_manifests": dict(native_manifests),
                },
                indent=2,
            )
        )
        return 0
    if native_manifests and (
        "VLLM_EXTENSION_MANIFESTS" in os.environ
        or "VLLM_EXTENSION_BUNDLES" in os.environ
    ):
        raise ValueError(
            "vllm-hust-ext owns VLLM_EXTENSION_MANIFESTS and "
            "VLLM_EXTENSION_BUNDLES while launching enabled vLLM extensions"
        )
    environment = os.environ.copy()
    environment.update(activation)
    if not native_manifests:
        return subprocess.call(command, env=environment)
    with tempfile.TemporaryDirectory(prefix="vllm-hust-ext-") as directory:
        manifest_paths = []
        for index, (_bundle_id, native_manifest) in enumerate(native_manifests):
            manifest_path = Path(directory) / f"{index}-manifest.json"
            manifest_path.write_text(
                json.dumps(native_manifest, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            manifest_paths.append(str(manifest_path))
        environment["VLLM_EXTENSION_MANIFESTS"] = os.pathsep.join(manifest_paths)
        environment["VLLM_EXTENSION_BUNDLES"] = ",".join(
            bundle_id for bundle_id, _ in native_manifests
        )
        return subprocess.call(command, env=environment)


def _formal_run_command(args: argparse.Namespace) -> int:
    if args.ecpa_formal_activation_probe:
        print(activation_probe_receipt().decode(), end="")
        return 0
    missing = [
        option
        for option, value in (
            ("--plan", args.plan),
            ("--launch-id", args.launch_id),
            ("--controller-instance", args.controller_instance),
            ("--host-event-dir", args.host_event_dir),
        )
        if value is None
    ]
    if missing:
        raise ValueError("formal-run requires " + ", ".join(missing))
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    return launch_managed(
        plan_path=args.plan,
        launch_id=args.launch_id,
        controller_instance=args.controller_instance,
        host_event_dir=args.host_event_dir,
        command=command,
        dry_run=args.dry_run,
    )


def _merge_provider_plan(command: list[str], plan: ProviderPlan) -> list[str]:
    """Merge a Provider's declared vLLM launch capability without name checks."""

    kv_transfer_config = plan.generated_config.get("kv_transfer_config")
    if kv_transfer_config is not None:
        if not isinstance(kv_transfer_config, dict):
            raise ValueError("provider kv_transfer_config must be a JSON object")
        connector_actions = [
            action
            for action in plan.actions
            if action.operation == "render_connector_config"
            and action.target == "vllm"
            and not action.mutating
        ]
        if len(connector_actions) != 1:
            raise ValueError(
                "provider kv_transfer_config requires one non-mutating "
                "render_connector_config action targeting vllm"
            )
        return _merge_json_option(
            command,
            "--kv-transfer-config",
            kv_transfer_config,
        )
    if plan.provider != "vllm":
        raise ValueError(f"{plan.provider} extensions use plan/render/check, not run")
    json_options = plan.generated_config.get("vllm_json_options", {})
    if not isinstance(json_options, dict):
        raise ValueError("provider vllm_json_options must be an object")
    result = command
    for option, value in json_options.items():
        if option not in {
            "--batch-admission-policy-config",
            "--speculative-config",
        } or not isinstance(value, dict):
            raise ValueError(f"unsupported provider JSON option {option!r}")
        result = _merge_json_option(result, option, value)
    scalar_options = plan.generated_config.get("vllm_options", {})
    if not isinstance(scalar_options, dict):
        raise ValueError("provider vllm_options must be an object")
    for option, value in scalar_options.items():
        if option not in {
            "--batch-admission-policy",
            "--preemption-policy",
        } or not isinstance(value, str):
            raise ValueError(f"unsupported provider option {option!r}")
        result = _merge_scalar_option(result, option, value)
    return result


def _merge_scalar_option(command: list[str], option: str, generated: str) -> list[str]:
    result = list(command)
    for index, argument in enumerate(result):
        if argument == option:
            if index + 1 >= len(result):
                raise ValueError(f"{option} requires a value")
            if result[index + 1] != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
        if argument.startswith(f"{option}="):
            if argument.partition("=")[2] != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
    result.extend((option, generated))
    return result


def _merge_json_option(
    command: list[str], option: str, generated: dict[str, object]
) -> list[str]:
    result = list(command)
    encoded = json.dumps(generated, separators=(",", ":"), sort_keys=True)
    for index, argument in enumerate(result):
        if argument == option:
            if index + 1 >= len(result):
                raise ValueError(f"{option} requires a JSON object")
            existing = json.loads(result[index + 1])
            if existing != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
        if argument.startswith(f"{option}="):
            existing = json.loads(argument.partition("=")[2])
            if existing != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
    result.extend((option, encoded))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vllm-hust-ext")
    subcommands = parser.add_subparsers(dest="command_name", required=True)
    extension = subcommands.add_parser("extension")
    extension_subcommands = extension.add_subparsers(dest="action", required=True)
    list_parser = extension_subcommands.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    for action in (
        "inspect",
        "validate",
        "enable",
        "disable",
        "forget",
        "status",
        "check",
        "plan",
        "render",
    ):
        action_parser = extension_subcommands.add_parser(action)
        action_parser.add_argument("bundle_id")
    configure_parser = extension_subcommands.add_parser("configure")
    configure_parser.add_argument("bundle_id")
    configure_parser.add_argument("--file", required=True)
    extension_subcommands.add_parser("env")
    catalog = subcommands.add_parser("catalog")
    catalog_subcommands = catalog.add_subparsers(dest="action", required=True)
    catalog_validate = catalog_subcommands.add_parser("validate")
    catalog_validate.add_argument("file")
    catalog_list = catalog_subcommands.add_parser("list")
    catalog_list.add_argument("file")
    catalog_list.add_argument("--json", action="store_true")
    catalog_list.add_argument("--include-preview", action="store_true")
    catalog_inspect = catalog_subcommands.add_parser("inspect")
    catalog_inspect.add_argument("file")
    catalog_inspect.add_argument("extension_id")
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    formal_run = subcommands.add_parser("formal-run")
    formal_run.add_argument("--plan")
    formal_run.add_argument("--launch-id")
    formal_run.add_argument("--controller-instance")
    formal_run.add_argument("--host-event-dir")
    formal_run.add_argument("--dry-run", action="store_true")
    formal_run.add_argument("--ecpa-formal-activation-probe", action="store_true")
    formal_run.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command_name == "extension":
            return _extension_command(args)
        if args.command_name == "catalog":
            return _catalog_command(args)
        if args.command_name == "formal-run":
            return _formal_run_command(args)
        return _run_command(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2
