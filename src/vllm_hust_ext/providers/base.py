"""Host-provider contracts for non-mutating extension orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from vllm_hust_ext.manifest import BundleManifest, ResourceClaim


@dataclass(frozen=True, slots=True)
class PlanAction:
    operation: str
    target: str
    lifecycle_owner: str
    mutating: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProviderPlan:
    extension_id: str
    provider: str
    actions: tuple[PlanAction, ...]
    generated_config: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    resource_claims: tuple[ResourceClaim, ...] = ()


@dataclass(frozen=True, slots=True)
class RenderArtifact:
    name: str
    media_type: str
    content: str


@dataclass(frozen=True, slots=True)
class ProviderCheck:
    compatible: bool | None
    configured: bool
    reachable: bool | None = None
    healthy: bool | None = None
    degraded: bool = False
    evidence: tuple[str, ...] = ()


class HostProvider(Protocol):
    """A host-owned adapter. No apply/delete operation is part of this API."""

    name: str

    def supports(self, manifest: BundleManifest) -> bool: ...

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan: ...

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]: ...

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck: ...


def assess_compatibility(
    manifest: BundleManifest,
    configuration: dict[str, Any],
    *,
    detected_host_version: str | None = None,
    default_api_version: str | None = None,
    default_protocol_versions: dict[str, str] | None = None,
) -> tuple[bool | None, tuple[str, ...]]:
    """Assess declared ranges without guessing unavailable host evidence."""

    evidence: list[str] = []
    unknown = False
    host_version = configuration.get("host_version", detected_host_version)
    if host_version is None:
        unknown = True
        evidence.append("host version is unavailable; compatibility is unverified")
    elif not _matches(str(host_version), manifest.host.version_range):
        return False, (
            f"host version {host_version} is outside {manifest.host.version_range}",
        )
    else:
        evidence.append(f"host version {host_version} satisfies the declared range")

    if manifest.host.api_range is not None:
        api_version = configuration.get("host_api_version", default_api_version)
        if api_version is None:
            unknown = True
            evidence.append("host API version is unavailable")
        elif not _matches(str(api_version), manifest.host.api_range):
            return False, (
                f"host API {api_version} is outside {manifest.host.api_range}",
            )
        else:
            evidence.append(f"host API {api_version} satisfies the declared range")

    supplied_protocols = configuration.get("protocol_versions", {})
    if not isinstance(supplied_protocols, dict):
        return False, ("protocol_versions must be an object",)
    protocol_versions = dict(default_protocol_versions or {})
    protocol_versions.update(supplied_protocols)
    for protocol in manifest.protocols:
        if protocol.version_range is None:
            evidence.append(
                f"protocol {protocol.name} is not independently versioned; "
                "compatibility is governed by host ranges and acceptance evidence"
            )
            continue
        version = protocol_versions.get(protocol.name)
        if version is None:
            unknown = True
            evidence.append(f"protocol {protocol.name} version is unavailable")
        elif not _matches(str(version), protocol.version_range):
            return False, (
                f"protocol {protocol.name} {version} is outside "
                f"{protocol.version_range}",
            )
        else:
            evidence.append(
                f"protocol {protocol.name} {version} satisfies the declared range"
            )
    return (None if unknown else True), tuple(evidence)


def _matches(version: str, specifier: str) -> bool:
    try:
        return Version(version) in SpecifierSet(specifier)
    except InvalidVersion:
        return False
