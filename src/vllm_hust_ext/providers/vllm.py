"""Provider for vLLM-owned in-process extension points."""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import asdict
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from packaging.version import InvalidVersion, Version

from vllm_hust_ext.manifest import BundleManifest, activation_blocker
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)

_JSON_LAUNCH_OPTIONS = {
    "batch_admission_policy_config": "--batch-admission-policy-config",
    "speculative_config": "--speculative-config",
}
_BOOLEAN_LAUNCH_OPTIONS = {
    "scheduler_reserve_output_budget": "--scheduler-reserve-output-budget",
}
_RUNTIME_QUALIFICATION_KEY = "_manager_runtime_qualification"
VLLM_PLUGIN_ENTRY_POINT_GROUPS = frozenset(
    {"vllm.general_plugins", "vllm.platform_plugins"}
)


def _v1_api_version(value: object) -> str | None:
    """Accept only well-formed v1 host contracts; all other values fail closed."""

    if not isinstance(value, str):
        return None
    try:
        parsed = Version(value)
    except InvalidVersion:
        return None
    return value if parsed.major == 1 else None


def declared_vllm_plugin_names(manifest: BundleManifest) -> tuple[str, ...]:
    """Project only official vLLM activation groups in declaration order."""

    return tuple(
        dict.fromkeys(
            entry_point.name
            for entry_point in manifest.activation.entry_points
            if entry_point.group in VLLM_PLUGIN_ENTRY_POINT_GROUPS
        )
    )


def _qualname_from_implementation_ref(implementation_ref: str) -> str:
    """Convert manifest ``module:object`` syntax to vLLM's Python qualname."""
    module, separator, object_name = implementation_ref.partition(":")
    if not separator or not module or not object_name:
        raise ValueError("policy implementation_ref must use module:object syntax")
    return f"{module}.{object_name}"


def _detect_protocol_versions() -> dict[str, str]:
    """Report only contracts exported by the installed vLLM host."""
    detected: dict[str, str] = {}
    try:
        contracts = import_module("vllm.plugins.contracts")
        scheduler_policy = contracts.DomainContract.SCHEDULER_POLICY_V1
    except (AttributeError, ImportError):
        pass
    else:
        if scheduler_policy.value == "vllm.scheduler.policy.v1":
            detected["vllm.scheduler.policy"] = "1.0"
    try:
        preemption = import_module("vllm.v1.core.sched.preemption")
        preemption_version = preemption.PREEMPTION_POLICY_API_VERSION
    except (AttributeError, ImportError):
        pass
    else:
        if preemption_version == "1.0":
            detected["vllm.preemption-policy"] = preemption_version
    try:
        admission = import_module("vllm.v1.core.sched.batch_admission")
        admission_version = admission.BATCH_ADMISSION_POLICY_API_VERSION
    except (AttributeError, ImportError):
        pass
    else:
        if supported := _v1_api_version(admission_version):
            detected["vllm.batch-admission-policy"] = supported
    try:
        request_processing = import_module("vllm.plugins.request_processing")
        request_processing_version = (
            request_processing.REQUEST_PROCESSING_HOOK_API_VERSION
        )
    except (AttributeError, ImportError):
        pass
    else:
        if supported := _v1_api_version(request_processing_version):
            detected["vllm.request-processing-hook"] = supported
    try:
        kv_materialization = import_module("vllm.v1.core.kv_materialization")
        kv_materialization_version = (
            kv_materialization.KV_MATERIALIZATION_RUNTIME_CONTROL_API_VERSION
        )
    except (AttributeError, ImportError):
        pass
    else:
        if supported := _v1_api_version(kv_materialization_version):
            detected["vllm.kv-materialization-runtime-control"] = supported
    return detected


class VllmProvider:
    name = "vllm"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        blocker = activation_blocker(manifest)
        if blocker is not None:
            return ProviderPlan(
                manifest.bundle_id,
                self.name,
                (
                    PlanAction(
                        "inspect_only",
                        manifest.bundle_id,
                        manifest.lifecycle_owner,
                        details={"enabled": False},
                    ),
                ),
                warnings=(blocker,),
            )
        native_manifest = None
        if manifest.host.api_range is not None:
            native_manifest = {
                "schema_version": "1.0",
                "bundle_id": manifest.bundle_id,
                "bundle_version": manifest.bundle_version,
                "host_api_range": manifest.host.api_range,
                "components": [
                    {
                        "component_id": component.component_id,
                        "contracts": list(component.contracts),
                        "execution_planes": list(component.execution_planes),
                        "isolation": component.isolation,
                        "implementation_ref": component.implementation_ref,
                        "permissions": list(component.permissions),
                    }
                    for component in manifest.components
                ],
            }
        launch_options = configuration.get("launch_options", {})
        if not isinstance(launch_options, dict):
            raise ValueError("launch_options must be an object")
        unknown_options = launch_options.keys() - (
            _JSON_LAUNCH_OPTIONS.keys() | _BOOLEAN_LAUNCH_OPTIONS.keys()
        )
        if unknown_options:
            raise ValueError(
                f"unsupported vLLM launch_options: {sorted(unknown_options)}"
            )
        json_options: dict[str, dict[str, Any]] = {}
        vllm_flags: list[str] = []
        for name, value in launch_options.items():
            if name in _BOOLEAN_LAUNCH_OPTIONS:
                if not isinstance(value, bool):
                    raise ValueError(f"launch_options.{name} must be a boolean")
                if value:
                    vllm_flags.append(_BOOLEAN_LAUNCH_OPTIONS[name])
                continue
            if not isinstance(value, dict):
                raise ValueError(f"launch_options.{name} must be an object")
            json_options[_JSON_LAUNCH_OPTIONS[name]] = value

        declared_environment = dict(manifest.activation.environment)
        environment_overrides = configuration.get("environment", {})
        if not isinstance(environment_overrides, dict):
            raise ValueError("environment must be an object")
        unknown_environment = environment_overrides.keys() - declared_environment.keys()
        if unknown_environment:
            raise ValueError(
                "environment overrides must be declared by the manifest: "
                f"{sorted(unknown_environment)}"
            )
        if not all(isinstance(value, str) for value in environment_overrides.values()):
            raise ValueError("environment override values must be strings")
        declared_environment.update(environment_overrides)

        additional_config = dict(manifest.activation.additional_config)
        additional_config.pop(_RUNTIME_QUALIFICATION_KEY, None)
        generated: dict[str, Any] = {
            "environment": declared_environment,
            "additional_config": additional_config,
            "user_config": configuration,
            "vllm_json_options": json_options,
        }
        plugin_names = declared_vllm_plugin_names(manifest)
        if plugin_names:
            generated["vllm_plugins"] = list(plugin_names)
        if vllm_flags:
            generated["vllm_flags"] = vllm_flags
        preemption_components = [
            component
            for component in manifest.components
            if "vllm.preemption-policy.v1" in component.contracts
        ]
        if preemption_components:
            if len(preemption_components) != 1:
                raise ValueError(
                    "exactly one vllm.preemption-policy.v1 component is required"
                )
            generated.setdefault("vllm_options", {})["--preemption-policy"] = (
                _qualname_from_implementation_ref(
                    preemption_components[0].implementation_ref
                )
            )
        admission_components = [
            component
            for component in manifest.components
            if "vllm.batch-admission-policy.v1" in component.contracts
        ]
        if admission_components:
            if len(admission_components) != 1:
                raise ValueError(
                    "exactly one vllm.batch-admission-policy.v1 component is required"
                )
            generated.setdefault("vllm_options", {})["--batch-admission-policy"] = (
                _qualname_from_implementation_ref(
                    admission_components[0].implementation_ref
                )
            )
        if native_manifest is not None:
            generated["native_extension_manifest"] = native_manifest
        warnings: tuple[str, ...] = ()
        if manifest.kind == "scheduler_policy" and manifest.protocols:
            warnings = (
                "in-process scheduler activation requires explicit host and "
                "protocol compatibility evidence; run refuses unverified policies",
            )
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            (
                PlanAction(
                    "configure_launch",
                    "vllm",
                    manifest.lifecycle_owner,
                    details={"enabled": enabled},
                ),
            ),
            generated,
            warnings,
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        native_manifest = plan.generated_config.get("native_extension_manifest")
        artifacts = []
        if native_manifest is not None:
            artifacts.append(
                RenderArtifact(
                    "vllm-extension-manifest.json",
                    "application/json",
                    json.dumps(native_manifest, indent=2, sort_keys=True),
                )
            )
        artifacts.append(
            RenderArtifact(
                "vllm-launch.json",
                "application/json",
                json.dumps(asdict(plan), indent=2, sort_keys=True),
            )
        )
        return tuple(artifacts)

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        detected_version = None
        with suppress(PackageNotFoundError):
            detected_version = version(manifest.host.name)
        compatible, evidence = assess_compatibility(
            manifest,
            configuration,
            detected_host_version=detected_version,
            default_api_version="1.0",
            # A matching vLLM distribution version does not prove that a
            # fork-only or draft extension protocol is actually present.
            default_protocol_versions=_detect_protocol_versions(),
        )
        required_profile = dict(manifest.activation.additional_config).get(
            _RUNTIME_QUALIFICATION_KEY
        )
        if compatible is True and required_profile is not None:
            qualification = configuration.get("runtime_qualification")
            if not isinstance(required_profile, dict):
                return ProviderCheck(
                    compatible=False,
                    configured=False,
                    degraded=True,
                    evidence=evidence
                    + ("manifest runtime qualification profile is invalid",),
                )
            if (
                not isinstance(qualification, dict)
                or qualification.get("status") != "passed"
            ):
                compatible = None
                evidence += (
                    "matching source contracts are insufficient; required runtime "
                    "qualification is unavailable",
                )
            else:
                mismatches = {
                    key: (expected, qualification.get(key))
                    for key, expected in required_profile.items()
                    if qualification.get(key) != expected
                }
                if mismatches:
                    compatible = False
                    evidence += (
                        f"runtime qualification profile mismatch: {mismatches}",
                    )
                else:
                    evidence += ("required runtime qualification profile passed",)
        blocker = activation_blocker(manifest)
        if blocker is not None:
            return ProviderCheck(
                compatible=compatible,
                configured=False,
                degraded=True,
                evidence=evidence + (blocker,),
            )
        return ProviderCheck(
            compatible=compatible,
            configured=compatible is not False,
            degraded=compatible is None,
            evidence=evidence + ("vLLM launch configuration can be rendered",),
        )
