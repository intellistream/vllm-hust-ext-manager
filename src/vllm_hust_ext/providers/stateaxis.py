"""Provider for StateAxis-owned, evidence-gated research mods."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vllm_hust_ext.manifest import BundleManifest, activation_blocker
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)


def _mod_binding(manifest: BundleManifest) -> dict[str, Any]:
    value = dict(manifest.activation.additional_config).get("stateaxis_mod")
    if not isinstance(value, dict):
        raise ValueError("StateAxis manifest requires activation.additional_config.stateaxis_mod")
    required = {"mod_id", "version", "manifest_sha256", "performance_qualified"}
    if set(value) != required:
        raise ValueError("StateAxis mod binding has unexpected or missing fields")
    digest = value["manifest_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("StateAxis mod binding has an invalid manifest_sha256")
    if not isinstance(value["performance_qualified"], bool):
        raise ValueError("StateAxis performance_qualified must be boolean")
    return value


def _verify_manifest_file(configuration: dict[str, Any], expected: str) -> tuple[bool | None, str]:
    raw = configuration.get("research_manifest_path")
    if raw is None:
        return None, "research manifest path is unavailable; digest binding is unverified"
    path = Path(raw)
    if path.is_symlink() or not path.is_file():
        return False, "research manifest must be a regular non-symlink file"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        return False, f"research manifest digest mismatch: expected {expected}, got {actual}"
    return True, f"research manifest digest verified at {path}"


class StateAxisProvider:
    name = "stateaxis"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name and manifest.host.name == "stateaxis"

    def plan(self, manifest: BundleManifest, configuration: dict[str, Any], *, enabled: bool) -> ProviderPlan:
        binding = _mod_binding(manifest)
        blocker = activation_blocker(manifest)
        experiment_mode = configuration.get("experiment_mode") is True
        if blocker is not None or (
            not binding["performance_qualified"] and not experiment_mode
        ):
            reasons = [
                reason
                for reason in (
                    blocker,
                    None
                    if binding["performance_qualified"]
                    else "StateAxis mod has no performance qualification",
                )
                if reason
            ]
            return ProviderPlan(
                manifest.bundle_id,
                self.name,
                (PlanAction("inspect_only", binding["mod_id"], manifest.lifecycle_owner, details={"enabled": False, "manifest_sha256": binding["manifest_sha256"]}),),
                {"stateaxis_mod": binding, "user_config": configuration},
                tuple(reasons),
            )
        if experiment_mode and not binding["performance_qualified"]:
            return ProviderPlan(
                manifest.bundle_id,
                self.name,
                (
                    PlanAction(
                        "configure_experiment_launch",
                        "stateaxis",
                        manifest.lifecycle_owner,
                        details={"enabled": enabled, "performance_qualified": False},
                    ),
                ),
                {
                    "stateaxis_additional_config": {"experiment_mode": True},
                    "stateaxis_mod": binding,
                    "user_config": configuration,
                },
                (
                    "experimental launch is not performance qualification; "
                    "preserve results with an experimental evidence label",
                ),
            )
        qualification = configuration.get("runtime_qualification")
        if not isinstance(qualification, dict) or qualification.get("status") != "passed":
            raise ValueError("qualified StateAxis mod requires a passed runtime_qualification record")
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            (PlanAction("configure_launch", "stateaxis", manifest.lifecycle_owner, details={"enabled": enabled}),),
            {"stateaxis_mod": binding, "runtime_qualification": qualification, "user_config": configuration},
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        return (RenderArtifact("stateaxis-mod-plan.json", "application/json", json.dumps(asdict(plan), indent=2, sort_keys=True)),)

    def check(self, manifest: BundleManifest, configuration: dict[str, Any]) -> ProviderCheck:
        try:
            binding = _mod_binding(manifest)
        except ValueError as error:
            return ProviderCheck(False, False, degraded=True, evidence=(str(error),))
        compatible, evidence = assess_compatibility(manifest, configuration, default_api_version="1.0")
        verified, digest_evidence = _verify_manifest_file(configuration, binding["manifest_sha256"])
        evidence += (digest_evidence,)
        if verified is False:
            compatible = False
        blocker = activation_blocker(manifest)
        qualified = binding["performance_qualified"] is True
        experiment_mode = configuration.get("experiment_mode") is True
        if blocker or (not qualified and not experiment_mode):
            reasons = tuple(reason for reason in (blocker, None if qualified else "performance qualification is absent") if reason)
            return ProviderCheck(compatible, False, degraded=True, evidence=evidence + reasons)
        if experiment_mode and not qualified:
            return ProviderCheck(
                compatible,
                verified is True,
                degraded=True,
                evidence=evidence
                + (
                    "experimental activation is configured without performance qualification",
                ),
            )
        qualification = configuration.get("runtime_qualification")
        configured = verified is True and isinstance(qualification, dict) and qualification.get("status") == "passed"
        if not configured:
            evidence += ("passed runtime qualification bound to the manifest is unavailable",)
        return ProviderCheck(compatible, configured, degraded=not configured or compatible is None, evidence=evidence)
