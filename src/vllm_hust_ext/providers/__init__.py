"""Built-in and third-party host-provider discovery."""

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from typing import cast

from vllm_hust_ext.providers.base import HostProvider
from vllm_hust_ext.providers.mooncake import MooncakeProvider
from vllm_hust_ext.providers.production_stack import ProductionStackProvider
from vllm_hust_ext.providers.stateaxis import StateAxisProvider
from vllm_hust_ext.providers.vllm import VllmProvider

ENTRY_POINT_GROUP = "vllm_hust_ext.providers"


def _builtin_providers() -> dict[str, HostProvider]:
    return {
        "vllm": VllmProvider(),
        "mooncake": MooncakeProvider(),
        "production-stack": ProductionStackProvider(),
        "stateaxis": StateAxisProvider(),
    }


def _load_external_provider(entry_point: EntryPoint) -> HostProvider:
    name = entry_point.name
    try:
        provider = cast(HostProvider, entry_point.load()())
    except Exception as error:
        raise ValueError(
            f"host provider {name!r} failed to load: {type(error).__name__}: {error}"
        ) from error
    if provider.name != name:
        raise ValueError(f"provider entry point {name!r} returned {provider.name!r}")
    return provider


def providers(*, include_external: bool = True) -> dict[str, HostProvider]:
    result = _builtin_providers()
    if include_external:
        for entry_point in entry_points(group=ENTRY_POINT_GROUP):
            if entry_point.name in result:
                raise ValueError(f"duplicate host provider: {entry_point.name}")
            provider = _load_external_provider(entry_point)
            result[provider.name] = provider
    return result


def provider_for(name: str, *, include_external: bool = True) -> HostProvider:
    builtins = _builtin_providers()
    if not include_external:
        try:
            return builtins[name]
        except KeyError as error:
            raise ValueError(f"unknown host provider: {name}") from error

    matches = tuple(
        entry_point
        for entry_point in entry_points(group=ENTRY_POINT_GROUP)
        if entry_point.name == name
    )
    if name in builtins:
        if matches:
            raise ValueError(f"duplicate host provider: {name}")
        return builtins[name]
    if len(matches) > 1:
        raise ValueError(f"duplicate host provider: {name}")
    if not matches:
        raise ValueError(f"unknown host provider: {name}")
    return _load_external_provider(matches[0])
