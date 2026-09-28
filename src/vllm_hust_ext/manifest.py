"""Static vLLM-HUST Extension Bundle v1 manifest model and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

HOST_API_VERSION = Version("1.0")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
_IMPLEMENTATION = re.compile(
    r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$"
)
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "bundle_id",
    "bundle_version",
    "host_api_range",
    "components",
    "activation",
}
_COMPONENT_FIELDS = {
    "component_id",
    "contracts",
    "execution_planes",
    "isolation",
    "implementation_ref",
    "permissions",
}
_ISOLATIONS = {"trusted_in_process", "process_isolated", "sandboxed_process"}
_PLANES = {"api", "scheduler", "worker", "native", "device", "bridge"}
_PERMISSIONS = {
    "device_access",
    "filesystem_read",
    "filesystem_write",
    "ipc",
    "network_egress",
    "shared_memory",
    "subprocess",
}
_KINDS = {
    "in_process_plugin",
    "scheduler_policy",
    "kv_connector",
    "kv_service_adapter",
    "control_plane_extension",
    "runtime_bridge",
}
_RUNTIMES = {"python", "external_service", "oci", "kubernetes", "composite"}
_LIFECYCLE_OWNERS = {"vllm", "host", "external_operator", "kubernetes", "user"}
_CARRIERS = {
    "host_builtin",
    "python_entry_point",
    "python_module",
    "external_service",
    "oci_image",
    "helm_values",
    "kubernetes_manifest",
    "crd",
    "controller",
}
_RESOURCE_CLAIM_FIELDS = {"resource", "scope", "mode"}
_RESOURCE_CLAIM_MODES = {"exclusive", "shared"}
_RESOURCE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*$")


class ManifestError(ValueError):
    """A Bundle manifest is malformed or incompatible."""


@dataclass(frozen=True, slots=True)
class ActivationEntryPoint:
    group: str
    name: str


@dataclass(frozen=True, slots=True)
class BundleActivation:
    entry_points: tuple[ActivationEntryPoint, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    additional_config: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class BundleComponent:
    component_id: str
    contracts: tuple[str, ...]
    execution_planes: tuple[str, ...]
    isolation: str
    implementation_ref: str
    permissions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HostSpec:
    provider: str
    name: str
    version_range: str
    api_range: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    type: str
    process_scope: str
    isolation: str


@dataclass(frozen=True, slots=True)
class ProtocolSpec:
    name: str
    version_range: str | None


@dataclass(frozen=True, slots=True)
class ImplementationCarrier:
    type: str
    attributes: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class RequiredService:
    service_id: str
    protocol: str
    version_range: str | None
    endpoint_config: str
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ResourceClaim:
    resource: str
    scope: str
    mode: str


@dataclass(frozen=True, slots=True)
class BundleManifest:
    bundle_id: str
    bundle_version: str
    host_api_range: str
    components: tuple[BundleComponent, ...]
    activation: BundleActivation
    schema_version: str = "1.0"
    kind: str = "legacy_vllm_bundle"
    host: HostSpec = field(
        default_factory=lambda: HostSpec("vllm", "vllm", ">=0", ">=1,<2")
    )
    runtime: RuntimeSpec = field(
        default_factory=lambda: RuntimeSpec(
            "python", "vllm_processes", "trusted_in_process"
        )
    )
    lifecycle_owner: str = "vllm"
    protocols: tuple[ProtocolSpec, ...] = ()
    implementation: tuple[ImplementationCarrier, ...] = ()
    requires_services: tuple[RequiredService, ...] = ()
    resource_claims: tuple[ResourceClaim, ...] = ()
    experimental: bool = True


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ManifestError(f"{location} must be an object with string keys")
    return value


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{location} must be a non-empty string")
    return value


def _strings(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ManifestError(f"{location} must be an array of strings")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise ManifestError(f"{location} must not contain duplicates")
    return result


def _known(values: tuple[str, ...], allowed: set[str], location: str) -> None:
    unknown = set(values) - allowed
    if unknown:
        raise ManifestError(
            f"{location} contains unsupported values: {sorted(unknown)}"
        )


def _parse_activation(value: Any) -> BundleActivation:
    if value is None:
        return BundleActivation()
    activation = _object(value, "activation")
    unknown = activation.keys() - {"entry_points", "environment", "additional_config"}
    if unknown:
        raise ManifestError(f"activation contains unknown fields: {sorted(unknown)}")
    entries: list[ActivationEntryPoint] = []
    for index, raw in enumerate(activation.get("entry_points", [])):
        item = _object(raw, f"activation.entry_points[{index}]")
        if item.keys() != {"group", "name"}:
            raise ManifestError(
                f"activation.entry_points[{index}] requires group and name"
            )
        entries.append(
            ActivationEntryPoint(
                _string(item["group"], f"activation.entry_points[{index}].group"),
                _string(item["name"], f"activation.entry_points[{index}].name"),
            )
        )
    environment = _object(activation.get("environment", {}), "activation.environment")
    if not all(isinstance(v, str) for v in environment.values()):
        raise ManifestError("activation.environment values must be strings")
    additional = _object(
        activation.get("additional_config", {}), "activation.additional_config"
    )
    return BundleActivation(
        entry_points=tuple(entries),
        environment=tuple(sorted(environment.items())),
        additional_config=tuple(sorted(additional.items())),
    )


def _parse_legacy_manifest(payload: Any) -> BundleManifest:
    manifest = _object(payload, "manifest")
    unknown = manifest.keys() - _TOP_LEVEL_FIELDS
    if unknown:
        raise ManifestError(f"manifest contains unknown fields: {sorted(unknown)}")
    required = _TOP_LEVEL_FIELDS - {"activation"}
    missing = required - manifest.keys()
    if missing:
        raise ManifestError(f"manifest is missing fields: {sorted(missing)}")
    if manifest["schema_version"] != "1.0":
        raise ManifestError("unsupported schema_version")

    bundle_id = _string(manifest["bundle_id"], "bundle_id")
    if not _IDENTIFIER.fullmatch(bundle_id):
        raise ManifestError(
            "bundle_id must use lowercase letters, digits, dots, or hyphens"
        )
    bundle_version = _string(manifest["bundle_version"], "bundle_version")
    try:
        Version(bundle_version)
    except InvalidVersion as error:
        raise ManifestError("bundle_version is not a valid version") from error
    host_api_range = _string(manifest["host_api_range"], "host_api_range")
    try:
        compatible = HOST_API_VERSION in SpecifierSet(host_api_range)
    except InvalidSpecifier as error:
        raise ManifestError("host_api_range is not a valid specifier") from error
    if not compatible:
        raise ManifestError(
            f"bundle requires host API {host_api_range}, "
            f"host provides {HOST_API_VERSION}"
        )

    raw_components = manifest["components"]
    if not isinstance(raw_components, list) or not raw_components:
        raise ManifestError("components must be a non-empty array")
    components: list[BundleComponent] = []
    for index, raw in enumerate(raw_components):
        item = _object(raw, f"components[{index}]")
        unknown = item.keys() - _COMPONENT_FIELDS
        missing = (_COMPONENT_FIELDS - {"permissions"}) - item.keys()
        if unknown or missing:
            raise ManifestError(
                f"components[{index}] has unknown={sorted(unknown)} "
                f"missing={sorted(missing)}"
            )
        component_id = _string(
            item["component_id"], f"components[{index}].component_id"
        )
        if not _IDENTIFIER.fullmatch(component_id):
            raise ManifestError(f"components[{index}].component_id is invalid")
        contracts = _strings(item["contracts"], f"components[{index}].contracts")
        if not contracts or not all(
            contract.startswith("vllm.") for contract in contracts
        ):
            raise ManifestError(f"components[{index}].contracts is invalid")
        planes = _strings(
            item["execution_planes"], f"components[{index}].execution_planes"
        )
        _known(planes, _PLANES, f"components[{index}].execution_planes")
        isolation = _string(item["isolation"], f"components[{index}].isolation")
        _known((isolation,), _ISOLATIONS, f"components[{index}].isolation")
        implementation = _string(
            item["implementation_ref"], f"components[{index}].implementation_ref"
        )
        if not _IMPLEMENTATION.fullmatch(implementation):
            raise ManifestError(f"components[{index}].implementation_ref is invalid")
        permissions = _strings(
            item.get("permissions", []), f"components[{index}].permissions"
        )
        _known(permissions, _PERMISSIONS, f"components[{index}].permissions")
        components.append(
            BundleComponent(
                component_id,
                contracts,
                planes,
                isolation,
                implementation,
                permissions,
            )
        )
    ids = [component.component_id for component in components]
    if len(ids) != len(set(ids)):
        raise ManifestError("component_id values must be unique")
    return BundleManifest(
        bundle_id,
        bundle_version,
        host_api_range,
        tuple(components),
        _parse_activation(manifest.get("activation")),
    )


def _specifier(value: Any, location: str) -> str:
    result = _string(value, location)
    try:
        SpecifierSet(result)
    except InvalidSpecifier as error:
        raise ManifestError(f"{location} is not a valid version range") from error
    return result


def _optional_specifier(value: Any, location: str) -> str | None:
    """Parse an upstream range without inventing one for unversioned surfaces."""

    if value is None:
        return None
    return _specifier(value, location)


def _parse_host(value: Any) -> HostSpec:
    host = _object(value, "host")
    required = {"provider", "name", "version_range"}
    unknown = host.keys() - (required | {"api_range"})
    missing = required - host.keys()
    if unknown or missing:
        raise ManifestError(
            f"host has unknown={sorted(unknown)} missing={sorted(missing)}"
        )
    provider = _string(host["provider"], "host.provider")
    if not _IDENTIFIER.fullmatch(provider):
        raise ManifestError("host.provider is invalid")
    api_range = host.get("api_range")
    return HostSpec(
        provider,
        _string(host["name"], "host.name"),
        _specifier(host["version_range"], "host.version_range"),
        None if api_range is None else _specifier(api_range, "host.api_range"),
    )


def _parse_runtime(value: Any) -> RuntimeSpec:
    runtime = _object(value, "runtime")
    if runtime.keys() != {"type", "process_scope", "isolation"}:
        raise ManifestError("runtime requires type, process_scope, and isolation")
    runtime_type = _string(runtime["type"], "runtime.type")
    _known((runtime_type,), _RUNTIMES, "runtime.type")
    return RuntimeSpec(
        runtime_type,
        _string(runtime["process_scope"], "runtime.process_scope"),
        _string(runtime["isolation"], "runtime.isolation"),
    )


def _parse_protocols(value: Any) -> tuple[ProtocolSpec, ...]:
    if not isinstance(value, list):
        raise ManifestError("protocols must be an array")
    result: list[ProtocolSpec] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"protocols[{index}]")
        if item.keys() != {"name", "version_range"}:
            raise ManifestError(f"protocols[{index}] requires name and version_range")
        result.append(
            ProtocolSpec(
                _string(item["name"], f"protocols[{index}].name"),
                _optional_specifier(
                    item["version_range"], f"protocols[{index}].version_range"
                ),
            )
        )
    return tuple(result)


def _parse_implementation(value: Any) -> tuple[ImplementationCarrier, ...]:
    if not isinstance(value, list) or not value:
        raise ManifestError("implementation must be a non-empty array")
    result: list[ImplementationCarrier] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"implementation[{index}]")
        carrier_type = _string(item.get("type"), f"implementation[{index}].type")
        _known((carrier_type,), _CARRIERS, f"implementation[{index}].type")
        attributes = {key: val for key, val in item.items() if key != "type"}
        if not attributes:
            raise ManifestError(f"implementation[{index}] has no carrier attributes")
        if carrier_type == "python_module":
            expected = {"module", "object", "status"}
            if attributes.keys() != expected:
                raise ManifestError(
                    f"implementation[{index}] python_module requires "
                    "module, object, and status"
                )
            module = _string(attributes["module"], f"implementation[{index}].module")
            obj = _string(attributes["object"], f"implementation[{index}].object")
            status = _string(attributes["status"], f"implementation[{index}].status")
            if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
                raise ManifestError(f"implementation[{index}].module is invalid")
            if not re.fullmatch(r"[A-Za-z_]\w*", obj):
                raise ManifestError(f"implementation[{index}].object is invalid")
            if status not in {"active", "import_only", "legacy_unregistered"}:
                raise ManifestError(f"implementation[{index}].status is unsupported")
        result.append(
            ImplementationCarrier(carrier_type, tuple(sorted(attributes.items())))
        )
    return tuple(result)


def _parse_services(value: Any) -> tuple[RequiredService, ...]:
    if not isinstance(value, list):
        raise ManifestError("requires_services must be an array")
    result: list[RequiredService] = []
    required = {"service_id", "protocol", "version_range", "endpoint_config"}
    for index, raw in enumerate(value):
        item = _object(raw, f"requires_services[{index}]")
        unknown = item.keys() - (required | {"optional"})
        missing = required - item.keys()
        if unknown or missing:
            raise ManifestError(
                f"requires_services[{index}] has unknown={sorted(unknown)} "
                f"missing={sorted(missing)}"
            )
        optional = item.get("optional", False)
        if not isinstance(optional, bool):
            raise ManifestError(f"requires_services[{index}].optional must be boolean")
        result.append(
            RequiredService(
                _string(item["service_id"], f"requires_services[{index}].service_id"),
                _string(item["protocol"], f"requires_services[{index}].protocol"),
                _optional_specifier(
                    item["version_range"],
                    f"requires_services[{index}].version_range",
                ),
                _string(
                    item["endpoint_config"],
                    f"requires_services[{index}].endpoint_config",
                ),
                optional,
            )
        )
    return tuple(result)


def _parse_resource_claims(value: Any) -> tuple[ResourceClaim, ...]:
    if not isinstance(value, list):
        raise ManifestError("resource_claims must be an array")
    result: list[ResourceClaim] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"resource_claims[{index}]")
        if item.keys() != _RESOURCE_CLAIM_FIELDS:
            raise ManifestError(
                f"resource_claims[{index}] requires resource, scope, and mode"
            )
        resource = _string(item["resource"], f"resource_claims[{index}].resource")
        scope = _string(item["scope"], f"resource_claims[{index}].scope")
        mode = _string(item["mode"], f"resource_claims[{index}].mode")
        if not _RESOURCE.fullmatch(resource) or not _RESOURCE.fullmatch(scope):
            raise ManifestError(f"resource_claims[{index}] has an invalid identifier")
        _known((mode,), _RESOURCE_CLAIM_MODES, f"resource_claims[{index}].mode")
        result.append(ResourceClaim(resource, scope, mode))
    if len(result) != len(set(result)):
        raise ManifestError("resource_claims must not contain duplicates")
    return tuple(result)


def _parse_experimental_manifest(payload: Any) -> BundleManifest:
    manifest = _object(payload, "manifest")
    fields = {
        "schema_version",
        "extension_id",
        "extension_version",
        "kind",
        "host",
        "runtime",
        "lifecycle_owner",
        "protocols",
        "implementation",
        "requires_services",
        "resource_claims",
        "components",
        "activation",
    }
    required = fields - {"components", "activation", "resource_claims"}
    unknown = manifest.keys() - fields
    missing = required - manifest.keys()
    if unknown or missing:
        raise ManifestError(
            f"experimental manifest has unknown={sorted(unknown)} "
            f"missing={sorted(missing)}"
        )
    extension_id = _string(manifest["extension_id"], "extension_id")
    if not _IDENTIFIER.fullmatch(extension_id):
        raise ManifestError("extension_id is invalid")
    version = _string(manifest["extension_version"], "extension_version")
    try:
        Version(version)
    except InvalidVersion as error:
        raise ManifestError("extension_version is not a valid version") from error
    kind = _string(manifest["kind"], "kind")
    _known((kind,), _KINDS, "kind")
    owner = _string(manifest["lifecycle_owner"], "lifecycle_owner")
    _known((owner,), _LIFECYCLE_OWNERS, "lifecycle_owner")
    components: tuple[BundleComponent, ...] = ()
    if manifest.get("components"):
        legacy = {
            "schema_version": "1.0",
            "bundle_id": extension_id,
            "bundle_version": version,
            "host_api_range": ">=1,<2",
            "components": manifest["components"],
            "activation": manifest.get("activation"),
        }
        components = _parse_legacy_manifest(legacy).components
    schema_version = manifest["schema_version"]
    if schema_version not in {"0.2-experimental", "0.3-experimental"}:
        raise ManifestError("unsupported experimental schema_version")
    if schema_version == "0.2-experimental" and "resource_claims" in manifest:
        raise ManifestError("resource_claims requires schema_version 0.3-experimental")
    return BundleManifest(
        extension_id,
        version,
        ">=0",
        components,
        _parse_activation(manifest.get("activation")),
        schema_version=schema_version,
        kind=kind,
        host=_parse_host(manifest["host"]),
        runtime=_parse_runtime(manifest["runtime"]),
        lifecycle_owner=owner,
        protocols=_parse_protocols(manifest["protocols"]),
        implementation=_parse_implementation(manifest["implementation"]),
        requires_services=_parse_services(manifest["requires_services"]),
        resource_claims=_parse_resource_claims(manifest.get("resource_claims", [])),
    )


def parse_manifest(payload: Any) -> BundleManifest:
    manifest = _object(payload, "manifest")
    schema_version = manifest.get("schema_version")
    if schema_version == "1.0":
        return _parse_legacy_manifest(manifest)
    if schema_version in {"0.2-experimental", "0.3-experimental"}:
        return _parse_experimental_manifest(manifest)
    raise ManifestError("unsupported schema_version")


def load_manifest(path: Path) -> BundleManifest:
    if path.is_symlink() or not path.is_file():
        raise ManifestError("manifest must be a regular non-symlink file")
    try:
        return parse_manifest(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError("manifest cannot be read as JSON") from error


def activation_blocker(manifest: BundleManifest) -> str | None:
    """Explain why a descriptor-only Python extension cannot be enabled."""

    carriers = tuple(getattr(manifest, "implementation", ()))
    statuses = [dict(carrier.attributes).get("status") for carrier in carriers]
    has_active_carrier = any(
        status == "active" or (status is None and carrier.type != "python_module")
        for carrier, status in zip(carriers, statuses, strict=True)
    )
    declared_inactive = [
        str(status)
        for status in statuses
        if status in {"import_only", "legacy_unregistered"}
    ]
    if declared_inactive and not has_active_carrier:
        status_names = ", ".join(sorted(set(declared_inactive)))
        return (
            "extension is descriptor-only and cannot be enabled "
            f"(implementation status: {status_names})"
        )
    return None
