"""Built-in and third-party host-provider discovery."""

from __future__ import annotations

from importlib.metadata import entry_points

from vllm_hust_ext.providers.base import HostProvider
from vllm_hust_ext.providers.mooncake import MooncakeProvider
from vllm_hust_ext.providers.production_stack import ProductionStackProvider
from vllm_hust_ext.providers.stateaxis import StateAxisProvider
from vllm_hust_ext.providers.vllm import VllmProvider

ENTRY_POINT_GROUP = "vllm_hust_ext.providers"


def providers(*, include_external: bool = True) -> dict[str, HostProvider]:
    result: dict[str, HostProvider] = {
        "vllm": VllmProvider(),
        "mooncake": MooncakeProvider(),
        "production-stack": ProductionStackProvider(),
        "stateaxis": StateAxisProvider(),
    }
    if include_external:
        for entry_point in entry_points(group=ENTRY_POINT_GROUP):
            if entry_point.name in result:
                raise ValueError(f"duplicate host provider: {entry_point.name}")
            provider = entry_point.load()()
            if provider.name != entry_point.name:
                raise ValueError(
                    f"provider entry point {entry_point.name!r} returned "
                    f"{provider.name!r}"
                )
            result[provider.name] = provider
    return result


def provider_for(name: str, *, include_external: bool = True) -> HostProvider:
    available = providers(include_external=include_external)
    try:
        return available[name]
    except KeyError as error:
        raise ValueError(f"unknown host provider: {name}") from error
