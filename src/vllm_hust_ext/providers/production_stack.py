"""Render-only provider for vLLM Production Stack and Kubernetes resources."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)


class ProductionStackProvider:
    name = "production-stack"
    required_component_evidence = (
        "controller_reconciliation",
        "router_traffic",
        "autoscaler_decision",
    )
    required_router_data_plane_evidence = (
        "backend_kind",
        "model",
        "failure_http_status",
        "recovered_http_status",
        "response_marker",
        "router_version",
        "architecture",
        "release_image_supported",
    )

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        values = configuration.get("values", {})
        if not isinstance(values, dict):
            raise ValueError("Production Stack values must be an object")
        chart = str(configuration.get("chart", "vllm/vllm-stack"))
        release = str(configuration.get("release", "vllm"))
        namespace = str(configuration.get("namespace", "default"))
        generated = {
            "chart": chart,
            "release": release,
            "namespace": namespace,
            "values": values,
            "enabled": enabled,
            "replica_ownership": "single-writer-required",
        }
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            (
                PlanAction("helm_template", chart, "kubernetes"),
                PlanAction("server_dry_run", namespace, "kubernetes"),
                PlanAction("check_rollout", release, "kubernetes"),
                PlanAction("check_ownership_conflicts", release, "kubernetes"),
            ),
            generated,
            (
                "Rendering is non-mutating. Applying Helm releases, CRDs, "
                "controllers, routers, autoscalers, or OCI images remains an "
                "explicit Kubernetes operator action.",
            ),
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        values = plan.generated_config["values"]
        release = plan.generated_config["release"]
        chart = plan.generated_config["chart"]
        namespace = plan.generated_config["namespace"]
        commands = {
            "render": {
                "argv": [
                    "helm",
                    "template",
                    release,
                    chart,
                    "--namespace",
                    namespace,
                    "-f",
                    "values.json",
                ],
                "mutating": False,
            },
            "validate": {
                "argv": [
                    "kubectl",
                    "--namespace",
                    namespace,
                    "apply",
                    "--dry-run=server",
                    "-f",
                    "rendered.yaml",
                ],
                "mutating": False,
            },
            "apply": None,
            "operator_owned_mutations": {
                "install": None,
                "upgrade": None,
                "rollback": None,
                "uninstall": None,
            },
            "verification": {
                "helm_history_argv": [
                    "helm",
                    "history",
                    release,
                    "--namespace",
                    namespace,
                ],
                "rollout_status_argv": [
                    "kubectl",
                    "--namespace",
                    namespace,
                    "rollout",
                    "status",
                    "<operator-selected-workload>",
                ],
                "required_component_evidence": list(self.required_component_evidence),
                "required_router_data_plane_evidence": list(
                    self.required_router_data_plane_evidence
                ),
                "replica_ownership_rule": (
                    "A VLLMRouter-owned Deployment and an HPA must not both "
                    "write spec.replicas unless the operator explicitly "
                    "delegates replica ownership."
                ),
            },
        }
        return (
            RenderArtifact(
                "values.json",
                "application/json",
                json.dumps(values, indent=2, sort_keys=True),
            ),
            RenderArtifact(
                "operator-plan.json",
                "application/json",
                json.dumps(commands, indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        compatible, compatibility_evidence = assess_compatibility(
            manifest, configuration
        )
        values = configuration.get("values")
        required_service_keys = tuple(
            service.endpoint_config
            for service in manifest.requires_services
            if not service.optional
        )
        missing_service_configuration = tuple(
            key
            for key in required_service_keys
            if not isinstance(configuration.get(key), str)
            or not str(configuration[key]).strip()
        )
        configured = (
            isinstance(values, dict)
            and compatible is not False
            and not missing_service_configuration
        )
        reachable = configuration.get("cluster_reachable")
        healthy = configuration.get("rollout_healthy")
        cluster_evidence = configuration.get("cluster_evidence")
        rollout_evidence = configuration.get("rollout_evidence")
        component_evidence = configuration.get("component_evidence")
        router_data_plane_evidence = configuration.get("router_data_plane_evidence")
        ownership_conflicts = configuration.get("ownership_conflicts", [])
        backend_endpoint = configuration.get("router_backend_endpoint")
        if backend_endpoint is not None:
            parsed_backend_endpoint = urlparse(str(backend_endpoint))
            if (
                not isinstance(backend_endpoint, str)
                or parsed_backend_endpoint.scheme not in {"http", "https"}
                or not parsed_backend_endpoint.netloc
            ):
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + ("router_backend_endpoint must be an absolute http(s) URL",),
                )
        if reachable is not None and not isinstance(reachable, bool):
            return ProviderCheck(
                compatible,
                False,
                evidence=compatibility_evidence
                + ("cluster_reachable must be boolean",),
            )
        if healthy is not None and not isinstance(healthy, bool):
            return ProviderCheck(
                compatible,
                False,
                evidence=compatibility_evidence + ("rollout_healthy must be boolean",),
            )
        if cluster_evidence is not None and (
            not isinstance(cluster_evidence, str) or not cluster_evidence.strip()
        ):
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("cluster_evidence must be a non-empty string",),
            )
        if rollout_evidence is not None and (
            not isinstance(rollout_evidence, str) or not rollout_evidence.strip()
        ):
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("rollout_evidence must be a non-empty string",),
            )
        if component_evidence is not None and not isinstance(component_evidence, dict):
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("component_evidence must be an object",),
            )
        if isinstance(component_evidence, dict):
            invalid_components = tuple(
                name
                for name, value in component_evidence.items()
                if not isinstance(name, str)
                or not isinstance(value, str)
                or not value.strip()
            )
            if invalid_components:
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "component_evidence values must be non-empty strings: "
                        + ", ".join(map(str, invalid_components)),
                    ),
                )
        if router_data_plane_evidence is not None and not isinstance(
            router_data_plane_evidence, dict
        ):
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("router_data_plane_evidence must be an object",),
            )
        if isinstance(router_data_plane_evidence, dict):
            missing_data_plane_evidence = tuple(
                name
                for name in self.required_router_data_plane_evidence
                if name not in router_data_plane_evidence
            )
            if missing_data_plane_evidence:
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "router_data_plane_evidence is missing: "
                        + ", ".join(missing_data_plane_evidence),
                    ),
                )
            backend_kind = router_data_plane_evidence["backend_kind"]
            if backend_kind != "real_model":
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "router_data_plane_evidence.backend_kind must be "
                        "real_model; mock backends are smoke evidence only",
                    ),
                )
            for name in (
                "model",
                "response_marker",
                "router_version",
                "architecture",
            ):
                value = router_data_plane_evidence[name]
                if not isinstance(value, str) or not value.strip():
                    return ProviderCheck(
                        compatible,
                        False,
                        degraded=True,
                        evidence=compatibility_evidence
                        + (
                            f"router_data_plane_evidence.{name} must be a "
                            "non-empty string",
                        ),
                    )
            failure_status = router_data_plane_evidence["failure_http_status"]
            if (
                isinstance(failure_status, bool)
                or not isinstance(failure_status, int)
                or not 500 <= failure_status < 600
            ):
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "router_data_plane_evidence.failure_http_status must "
                        "be a 5xx integer",
                    ),
                )
            recovered_status = router_data_plane_evidence["recovered_http_status"]
            if (
                isinstance(recovered_status, bool)
                or not isinstance(recovered_status, int)
                or not 200 <= recovered_status < 300
            ):
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "router_data_plane_evidence.recovered_http_status "
                        "must be a 2xx integer",
                    ),
                )
            if not isinstance(
                router_data_plane_evidence["release_image_supported"], bool
            ):
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "router_data_plane_evidence.release_image_supported "
                        "must be boolean",
                    ),
                )
        if not isinstance(ownership_conflicts, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in ownership_conflicts
        ):
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("ownership_conflicts must be a list of non-empty strings",),
            )
        if ownership_conflicts:
            return ProviderCheck(
                False,
                False,
                reachable=reachable,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + tuple(f"ownership conflict: {item}" for item in ownership_conflicts),
            )
        if reachable is True and not cluster_evidence:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("cluster_reachable=true requires cluster_evidence",),
            )
        if healthy is True and not rollout_evidence:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("rollout_healthy=true requires rollout_evidence",),
            )
        if healthy is True and reachable is not True:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("rollout_healthy=true requires cluster_reachable=true",),
            )
        if healthy is True:
            if missing_service_configuration:
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "rollout_healthy=true requires service configuration: "
                        + ", ".join(missing_service_configuration),
                    ),
                )
            supplied = (
                component_evidence if isinstance(component_evidence, dict) else {}
            )
            missing_component_evidence = tuple(
                name
                for name in self.required_component_evidence
                if name not in supplied
            )
            if missing_component_evidence:
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "rollout_healthy=true requires component_evidence for: "
                        + ", ".join(missing_component_evidence),
                    ),
                )
            if not isinstance(router_data_plane_evidence, dict):
                return ProviderCheck(
                    compatible,
                    False,
                    degraded=True,
                    evidence=compatibility_evidence
                    + (
                        "rollout_healthy=true requires structured "
                        "router_data_plane_evidence from a real model, "
                        "including failure and recovery",
                    ),
                )
        release_image_unsupported = (
            isinstance(router_data_plane_evidence, dict)
            and router_data_plane_evidence.get("release_image_supported") is False
        )
        degraded = (
            compatible is None
            or reachable is False
            or healthy is False
            or release_image_unsupported
        )
        runtime_evidence = tuple(
            item
            for item in (
                f"cluster evidence: {cluster_evidence}" if cluster_evidence else None,
                f"rollout evidence: {rollout_evidence}" if rollout_evidence else None,
                (
                    "required service configuration present: "
                    + ", ".join(required_service_keys)
                    if required_service_keys and not missing_service_configuration
                    else None
                ),
            )
            if item is not None
        )
        structured_evidence = tuple(
            f"{name.replace('_', ' ')} evidence: {value}"
            for name, value in (
                component_evidence.items()
                if isinstance(component_evidence, dict)
                else ()
            )
        )
        router_evidence: tuple[str, ...] = ()
        if isinstance(router_data_plane_evidence, dict):
            router_evidence = (
                "router data plane evidence: "
                f"model={router_data_plane_evidence['model']}, "
                f"failure_http_status="
                f"{router_data_plane_evidence['failure_http_status']}, "
                f"recovered_http_status="
                f"{router_data_plane_evidence['recovered_http_status']}, "
                f"response_marker="
                f"{router_data_plane_evidence['response_marker']}, "
                f"router_version="
                f"{router_data_plane_evidence['router_version']}, "
                f"architecture="
                f"{router_data_plane_evidence['architecture']}",
            )
            if release_image_unsupported:
                router_evidence += (
                    "release image is unavailable for this architecture; "
                    "a source-built Router artifact was used",
                )
        return ProviderCheck(
            compatible,
            configured,
            reachable=reachable,
            healthy=healthy,
            degraded=degraded,
            evidence=compatibility_evidence
            + runtime_evidence
            + structured_evidence
            + router_evidence
            + ("no cluster mutation was attempted",),
        )
