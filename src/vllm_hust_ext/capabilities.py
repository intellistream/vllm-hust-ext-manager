"""Fail-closed discovery of host-owned extension capabilities."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import import_module

from packaging.version import InvalidVersion, Version

CAPABILITY_SCHEMA = "vllm.extension-capabilities/v1"


@dataclass(frozen=True, slots=True)
class HostCapabilities:
    host_api_version: str | None
    protocol_versions: dict[str, str]
    source: str
    evidence: tuple[str, ...] = ()


def _version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        Version(value)
    except InvalidVersion:
        return None
    return value


def _v1_version(value: object) -> str | None:
    parsed = _version(value)
    return parsed if parsed is not None and Version(parsed).major == 1 else None


def _snapshot(value: object) -> HostCapabilities:
    source = "vllm.plugins.extension_capabilities"
    if not isinstance(value, Mapping):
        return HostCapabilities(
            None,
            {},
            source,
            ("host capability snapshot is not an object",),
        )
    expected = {"schema_version", "host_api_version", "protocols"}
    if set(value) != expected:
        return HostCapabilities(
            None,
            {},
            source,
            ("host capability snapshot has unknown or missing fields",),
        )
    if value["schema_version"] != CAPABILITY_SCHEMA:
        return HostCapabilities(
            None,
            {},
            source,
            (f"unsupported host capability schema {value['schema_version']!r}",),
        )
    host_api_version = _version(value["host_api_version"])
    protocols = value["protocols"]
    if host_api_version is None or not isinstance(protocols, Mapping):
        return HostCapabilities(
            None,
            {},
            source,
            ("host capability snapshot contains invalid versions",),
        )
    validated: dict[str, str] = {}
    for name, version in protocols.items():
        parsed = _version(version)
        if not isinstance(name, str) or not name.strip() or parsed is None:
            return HostCapabilities(
                None,
                {},
                source,
                ("host capability snapshot contains an invalid protocol entry",),
            )
        validated[name] = parsed
    return HostCapabilities(
        host_api_version,
        validated,
        source,
        (f"loaded {len(validated)} protocols from the host capability registry",),
    )


def detect_vllm_capabilities() -> HostCapabilities:
    """Prefer the host registry; use narrow legacy probes only when absent."""

    try:
        module = import_module("vllm.plugins.extension_capabilities")
    except ModuleNotFoundError as error:
        absent_registry_names = {
            "vllm",
            "vllm.plugins",
            "vllm.plugins.extension_capabilities",
        }
        if error.name not in absent_registry_names:
            return HostCapabilities(
                None,
                {},
                "vllm.plugins.extension_capabilities",
                (f"host capability registry import failed: missing {error.name}",),
            )
        return _detect_legacy_vllm_capabilities()
    except ImportError:
        return _detect_legacy_vllm_capabilities()
    try:
        getter = module.get_extension_capabilities
        snapshot = getter()
    except (AttributeError, TypeError, ValueError) as error:
        return HostCapabilities(
            None,
            {},
            "vllm.plugins.extension_capabilities",
            (f"host capability registry failed closed: {type(error).__name__}",),
        )
    return _snapshot(snapshot)


def _detect_legacy_vllm_capabilities() -> HostCapabilities:
    """Compatibility probes for hosts predating the capability registry."""

    detected: dict[str, str] = {}
    probes: tuple[tuple[str, str, str], ...] = (
        (
            "vllm.v1.core.sched.preemption",
            "PREEMPTION_POLICY_API_VERSION",
            "vllm.preemption-policy",
        ),
        (
            "vllm.v1.core.sched.batch_admission",
            "BATCH_ADMISSION_POLICY_API_VERSION",
            "vllm.batch-admission-policy",
        ),
        (
            "vllm.plugins.request_processing",
            "REQUEST_PROCESSING_HOOK_API_VERSION",
            "vllm.request-processing-hook",
        ),
        (
            "vllm.v1.core.kv_materialization",
            "KV_MATERIALIZATION_RUNTIME_CONTROL_API_VERSION",
            "vllm.kv-materialization-runtime-control",
        ),
    )
    for module_name, attribute, protocol in probes:
        try:
            value = getattr(import_module(module_name), attribute)
        except (AttributeError, ImportError):
            continue
        if parsed := _v1_version(value):
            detected[protocol] = parsed
    return HostCapabilities(
        None,
        detected,
        "legacy-module-probes",
        ("host capability registry is unavailable; used legacy module probes",),
    )
