"""Non-invasive provider for Mooncake services and vLLM/Ascend connectors."""

from __future__ import annotations

import json
from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)

_CONNECTORS = {"MooncakeConnector", "MooncakeStoreConnector", "AscendStoreConnector"}
_DISTRIBUTIONS = (
    "mooncake-transfer-engine",
    "mooncake-transfer-engine-cuda13",
    "mooncake-transfer-engine-non-cuda",
    "mooncake-transfer-engine-npu",
    "mooncake-transfer-engine-musa",
    "mooncake-transfer-engine-efa",
    "mooncake-transfer-engine-efa-non-cuda",
)
_REQUIRED_OPERATION_EVIDENCE = (
    "lookup_exists_ok",
    "save_put_ok",
    "load_get_ok",
    "failed_keys",
)


def _installed_distributions() -> tuple[tuple[str, str], ...]:
    installed: list[tuple[str, str]] = []
    for distribution in _DISTRIBUTIONS:
        with suppress(PackageNotFoundError):
            installed.append((distribution, version(distribution)))
    return tuple(installed)


class MooncakeProvider:
    name = "mooncake"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def _connector_config(self, configuration: dict[str, Any]) -> dict[str, Any]:
        connector = configuration.get("connector", "MooncakeConnector")
        if connector not in _CONNECTORS:
            raise ValueError(f"unsupported Mooncake connector: {connector}")
        role = configuration.get("kv_role", "kv_both")
        if role not in {"kv_producer", "kv_consumer", "kv_both"}:
            raise ValueError(f"unsupported Mooncake KV role: {role}")
        result: dict[str, Any] = {"kv_connector": connector, "kv_role": role}
        if "kv_load_failure_policy" in configuration:
            failure_policy = configuration["kv_load_failure_policy"]
            if failure_policy not in {"fail", "recompute"}:
                raise ValueError(
                    f"unsupported KV load failure policy: {failure_policy}"
                )
            result["kv_load_failure_policy"] = failure_policy
        extra = configuration.get("kv_connector_extra_config", {})
        if not isinstance(extra, dict):
            raise ValueError("kv_connector_extra_config must be an object")
        if connector == "AscendStoreConnector" and (
            configuration.get("device_backend") != "ascend"
            or configuration.get("transport_protocol") != "ascend"
            or extra.get("backend") != "mooncake"
        ):
            raise ValueError(
                "AscendStoreConnector requires device_backend=ascend, "
                "transport_protocol=ascend and backend=mooncake"
            )
        if extra:
            result["kv_connector_extra_config"] = extra
        return result

    def _validate_runtime_configuration(
        self,
        configuration: dict[str, Any],
        installed_distribution: str | None,
    ) -> tuple[bool, bool, tuple[str, ...]]:
        evidence: list[str] = []
        connector = configuration.get("connector", "MooncakeConnector")
        extra = configuration.get("kv_connector_extra_config", {})
        if connector == "AscendStoreConnector":
            try:
                ascend_version = version("vllm-ascend")
            except PackageNotFoundError:
                return False, False, ("AscendStoreConnector requires vllm-ascend",)
            evidence.append(f"detected vllm-ascend {ascend_version}")
        if connector == "MooncakeStoreConnector" and extra.get("load_async") is False:
            evidence.append(
                "MooncakeStoreConnector requires load_async=true on the validated "
                "vLLM 0.23 execution path"
            )
            return True, False, tuple(evidence)

        device_backend = configuration.get("device_backend")
        transport = configuration.get("transport_protocol")
        npu_runtime = installed_distribution == "mooncake-transfer-engine-npu"
        if device_backend == "ascend" or npu_runtime:
            if transport != "ascend":
                evidence.append(
                    "Ascend NPU KV cache requires Mooncake transport_protocol=ascend; "
                    "generic tcp transport cannot dereference NPU virtual addresses"
                )
                return False, False, tuple(evidence)
            evidence.append("Ascend NPU runtime uses Mooncake ascend transport")
        return True, True, tuple(evidence)

    def _operation_evidence(
        self, configuration: dict[str, Any]
    ) -> tuple[bool | None, bool, tuple[str, ...]]:
        raw = configuration.get("connector_operation_evidence")
        if raw is None:
            return None, True, ()
        if not isinstance(raw, dict):
            return False, False, ("connector_operation_evidence must be an object",)
        missing = [name for name in _REQUIRED_OPERATION_EVIDENCE if name not in raw]
        if missing:
            return (
                False,
                False,
                ("connector_operation_evidence is missing: " + ", ".join(missing),),
            )
        values: dict[str, float] = {}
        for name in _REQUIRED_OPERATION_EVIDENCE:
            value = raw[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or value < 0
            ):
                return (
                    False,
                    False,
                    (f"connector_operation_evidence.{name} must be non-negative",),
                )
            values[name] = float(value)
        healthy = (
            values["lookup_exists_ok"] > 0
            and values["save_put_ok"] > 0
            and values["load_get_ok"] > 0
            and values["failed_keys"] == 0
        )
        return (
            healthy,
            True,
            (
                "Mooncake connector operations: "
                f"lookup={values['lookup_exists_ok']:g}, "
                f"save={values['save_put_ok']:g}, "
                f"load={values['load_get_ok']:g}, "
                f"failed_keys={values['failed_keys']:g}",
            ),
        )

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        connector = self._connector_config(configuration)
        actions = [
            PlanAction(
                "render_connector_config",
                "vllm",
                "vllm",
                details={"enabled": enabled},
            )
        ]
        for service in manifest.requires_services:
            actions.append(
                PlanAction(
                    "check_service",
                    service.service_id,
                    manifest.lifecycle_owner,
                    details={"protocol": service.protocol},
                )
            )
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            tuple(actions),
            {"kv_transfer_config": connector},
            (
                "Mooncake service lifecycle remains owned by its external operator; "
                "the manager will not start, stop, upgrade, or delete it.",
                "For Ascend NPU caches, render the external Mooncake configuration "
                "with transport_protocol=ascend. MooncakeStoreConnector requires "
                "load_async enabled on the validated execution path.",
            ),
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        return (
            RenderArtifact(
                "mooncake-vllm-connector.json",
                "application/json",
                json.dumps(plan.generated_config, indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        installed = _installed_distributions()
        if len(installed) > 1:
            names = ", ".join(name for name, _ in installed)
            return ProviderCheck(
                False,
                False,
                degraded=True,
                evidence=(
                    "multiple mutually exclusive Mooncake runtime variants are "
                    f"installed: {names}",
                ),
            )
        installed_name = installed[0][0] if installed else None
        detected_version = installed[0][1] if installed else None
        distribution_evidence = (
            (f"detected {installed[0][0]} {installed[0][1]}",) if installed else ()
        )
        compatible, compatibility_evidence = assess_compatibility(
            manifest,
            configuration,
            detected_host_version=detected_version,
        )
        compatibility_evidence = distribution_evidence + compatibility_evidence
        if compatible is False:
            return ProviderCheck(False, False, evidence=compatibility_evidence)
        try:
            self._connector_config(configuration)
        except ValueError as error:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence + (str(error),),
            )
        runtime_compatible, runtime_configured, runtime_evidence = (
            self._validate_runtime_configuration(configuration, installed_name)
        )
        compatibility_evidence += runtime_evidence
        if not runtime_compatible or not runtime_configured:
            return ProviderCheck(
                False if not runtime_compatible else compatible,
                runtime_configured,
                degraded=True,
                evidence=compatibility_evidence,
            )
        operations_healthy, operations_configured, operations_evidence = (
            self._operation_evidence(configuration)
        )
        compatibility_evidence += operations_evidence
        if not operations_configured:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence,
            )
        health_url = configuration.get("health_url")
        if not health_url:
            required = bool(manifest.requires_services)
            return ProviderCheck(
                compatible,
                not required,
                degraded=required,
                evidence=compatibility_evidence
                + ("health_url is required to verify the external service",),
            )
        try:
            request = Request(str(health_url), method="GET")
            with urlopen(request, timeout=2) as response:  # noqa: S310
                healthy = 200 <= response.status < 300
                return ProviderCheck(
                    compatible,
                    True,
                    reachable=True,
                    healthy=healthy and operations_healthy is not False,
                    degraded=not healthy or operations_healthy is False,
                    evidence=compatibility_evidence
                    + (f"Mooncake health endpoint returned {response.status}",),
                )
        except HTTPError as error:
            return ProviderCheck(
                compatible,
                True,
                reachable=True,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + (f"Mooncake health endpoint returned {error.code}",),
            )
        except (OSError, URLError) as error:
            return ProviderCheck(
                compatible,
                True,
                reachable=False,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + (f"Mooncake service is unreachable: {error}",),
            )
