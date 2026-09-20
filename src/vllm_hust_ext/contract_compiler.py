"""Deterministic compiler for ECPA capability and resource contracts.

This module is deliberately pure: it resolves a set of declarative contracts
into an immutable plan without importing plugin implementation code or applying
host configuration.
"""

from __future__ import annotations

import hashlib
import heapq
import re
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .ecpa_model import canonical_bytes, content_id

_IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$")
_RESOURCE_MODES = {"exclusive", "shared-read", "mediated"}
_COMPLETION_MODES = {"all", "quorum", "optional"}
_EVENTS = {"loaded", "invoked", "health-observed"}
_AUTHORITY_KINDS = {"provider", "runtime", "external"}
_CAPABILITY_DIRECTIONS = {"provides", "requires"}
_TAXONOMY_DECISION_PRECEDENCE = (
    "unknown-resource",
    "invalid-mode",
    "capability-cardinality",
    "resource-mode",
    "mediator-consistency",
    "mediator-presence",
)
_TAXONOMY_SCOPE = "vLLM-HUST-static-contract-study"


class PlanningErrorCode(str, Enum):
    INVALID_CONTRACT = "INVALID_CONTRACT"
    DUPLICATE_PLUGIN = "DUPLICATE_PLUGIN"
    INCOMPATIBLE_HOST = "INCOMPATIBLE_HOST"
    MISSING_CAPABILITY = "MISSING_CAPABILITY"
    INCOMPATIBLE_CAPABILITY = "INCOMPATIBLE_CAPABILITY"
    AMBIGUOUS_CAPABILITY = "AMBIGUOUS_CAPABILITY"
    DEPENDENCY_CYCLE = "DEPENDENCY_CYCLE"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    AUTHORITY_VIOLATION = "AUTHORITY_VIOLATION"
    UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE"
    INVALID_RESOURCE_MODE = "INVALID_RESOURCE_MODE"


class ContractPlanningError(ValueError):
    """A stable, machine-readable plan-admission failure."""

    def __init__(self, code: PlanningErrorCode, detail: str):
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    version: str


@dataclass(frozen=True, slots=True)
class ContractResource:
    name: str
    mode: str
    mediator: str | None


@dataclass(frozen=True, slots=True)
class TaxonomyResource:
    canonical: str
    aliases: tuple[str, ...]
    allowed_modes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ContractTaxonomy:
    schema: str
    scope: str
    decision_precedence: tuple[str, ...]
    capabilities: tuple[str, ...]
    resources: tuple[TaxonomyResource, ...]


@dataclass(frozen=True, slots=True)
class ProcessObligationContract:
    role: str
    event: str
    completion: str
    authority: str
    capability_direction: str
    capability: str
    quorum: int | None


@dataclass(frozen=True, slots=True)
class RollbackContract:
    manager_owned: tuple[str, ...]
    external_operator_owned: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    role: str
    event: str
    capability_direction: str
    capability: str


@dataclass(frozen=True, slots=True)
class AuthorityContract:
    provider: tuple[AuthorityGrant, ...]
    runtime: tuple[AuthorityGrant, ...]
    external: tuple[AuthorityGrant, ...]


@dataclass(frozen=True, slots=True)
class ExtensionContract:
    extension_id: str
    version: str
    manifest_sha256: str
    host_runtime: str
    host_version_range: str
    provides: tuple[Capability, ...]
    requires: tuple[Capability, ...]
    resources: tuple[ContractResource, ...]
    process_obligations: tuple[ProcessObligationContract, ...]
    rollback: RollbackContract
    authority: AuthorityContract


@dataclass(frozen=True, slots=True)
class CapabilityBinding:
    capability: str
    required_range: str
    consumer: str
    provider: str
    provided_version: str


@dataclass(frozen=True, slots=True)
class ResourceOwnership:
    resource: str
    mode: str
    owners: tuple[str, ...]
    mediator: str | None


@dataclass(frozen=True, slots=True)
class ObligationBinding:
    extension_id: str
    role: str
    event: str
    completion: str
    authority: str
    capability_direction: str
    capability: str
    capability_provider: str
    quorum: int | None


@dataclass(frozen=True, slots=True)
class ContractPlan:
    host_runtime: str
    host_version: str
    ordered_contracts: tuple[ExtensionContract, ...]
    capability_bindings: tuple[CapabilityBinding, ...]
    resource_ownership: tuple[ResourceOwnership, ...]
    obligation_bindings: tuple[ObligationBinding, ...]

    @property
    def plan_id(self) -> str:
        return content_id("contract-plan", asdict(self))


def _object(value: Any, location: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} requires exactly {sorted(fields)}",
        )
    return value


def _string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} must be a non-empty trimmed string",
        )
    return value


def _identifier(value: Any, location: str) -> str:
    result = _string(value, location)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} is not a canonical ECPA identifier",
        )
    return result


def _string_array(value: Any, location: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, f"{location} must be an array"
        )
    result = tuple(_string(item, f"{location}[]") for item in value)
    if len(result) != len(set(result)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} contains duplicates",
        )
    return tuple(sorted(result))


def _capabilities(
    value: Any, location: str, *, requirements: bool
) -> tuple[Capability, ...]:
    if not isinstance(value, list):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, f"{location} must be an array"
        )
    result: list[Capability] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"{location}[{index}]", {"name", "version"})
        name = _identifier(item["name"], f"{location}[{index}].name")
        version = _string(item["version"], f"{location}[{index}].version")
        if requirements:
            version = _public_specifier(version, f"{location}[{index}].version")
        else:
            version = _public_version(version, f"{location}[{index}].version")
        result.append(Capability(name, version))
    names = [item.name for item in result]
    if len(names) != len(set(names)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} contains duplicate capability names",
        )
    return tuple(sorted(result, key=lambda item: item.name))


def _public_version(value: Any, location: str) -> str:
    raw = _string(value, location)
    try:
        parsed = Version(raw)
    except InvalidVersion as exc:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} is not a PEP 440 version",
        ) from exc
    if parsed.local is not None:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} must not contain a PEP 440 local version label",
        )
    return str(parsed)


def _public_specifier(value: Any, location: str) -> str:
    raw = _string(value, location)
    try:
        parsed = SpecifierSet(raw)
        for specifier in parsed:
            candidate = specifier.version.removesuffix(".*")
            if Version(candidate).local is not None:
                raise ContractPlanningError(
                    PlanningErrorCode.INVALID_CONTRACT,
                    f"{location} must not contain a PEP 440 local version label",
                )
    except (InvalidSpecifier, InvalidVersion) as exc:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            f"{location} is not a PEP 440 specifier set",
        ) from exc
    return str(parsed)


def _authority_grants(
    value: Any, location: str, authority_kind: str
) -> tuple[AuthorityGrant, ...]:
    if not isinstance(value, list):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, f"{location} must be an array"
        )
    grants: list[AuthorityGrant] = []
    for index, raw in enumerate(value):
        item = _object(
            raw,
            f"{location}[{index}]",
            {"role", "event", "capability_direction", "capability"},
        )
        role = _string(item["role"], f"{location}[{index}].role")
        event = _string(item["event"], f"{location}[{index}].event")
        if event not in _EVENTS:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"{location}[{index}].event is unsupported",
            )
        if event in {"loaded", "invoked"} and authority_kind != "runtime":
            raise ContractPlanningError(
                PlanningErrorCode.AUTHORITY_VIOLATION,
                f"{location}[{index}] cannot claim {event} outside runtime authority",
            )
        capability_direction = _string(
            item["capability_direction"],
            f"{location}[{index}].capability_direction",
        )
        if capability_direction not in _CAPABILITY_DIRECTIONS:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"{location}[{index}].capability_direction is unsupported",
            )
        capability = _identifier(item["capability"], f"{location}[{index}].capability")
        grants.append(AuthorityGrant(role, event, capability_direction, capability))
    if len(grants) != len(set(grants)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, f"{location} contains duplicates"
        )
    return tuple(
        sorted(
            grants,
            key=lambda item: (
                item.role,
                item.event,
                item.capability_direction,
                item.capability,
            ),
        )
    )


def parse_contract_taxonomy(payload: Any) -> ContractTaxonomy:
    """Parse the frozen resource alias and ownership-mode taxonomy."""
    item = _object(
        payload,
        "taxonomy",
        {"schema", "scope", "decision_precedence", "capabilities", "resources"},
    )
    schema = _string(item["schema"], "taxonomy.schema")
    if schema != "ecpa-contract-taxonomy/0.1-draft":
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.schema is unsupported",
        )
    scope = _string(item["scope"], "taxonomy.scope")
    if scope != _TAXONOMY_SCOPE:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.scope is unsupported",
        )
    raw_precedence = item["decision_precedence"]
    if not isinstance(raw_precedence, list):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.decision_precedence must be an array",
        )
    precedence = tuple(
        _string(value, "taxonomy.decision_precedence[]") for value in raw_precedence
    )
    if precedence != _TAXONOMY_DECISION_PRECEDENCE:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.decision_precedence is unsupported",
        )

    raw_capabilities = item["capabilities"]
    if not isinstance(raw_capabilities, list) or not raw_capabilities:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.capabilities must be a non-empty array",
        )
    capabilities: list[str] = []
    for index, raw in enumerate(raw_capabilities):
        capability = _object(
            raw,
            f"taxonomy.capabilities[{index}]",
            {"name", "description"},
        )
        capabilities.append(
            _identifier(capability["name"], f"taxonomy.capabilities[{index}].name")
        )
        _string(
            capability["description"],
            f"taxonomy.capabilities[{index}].description",
        )
    if len(capabilities) != len(set(capabilities)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.capabilities contains duplicate names",
        )

    raw_resources = item["resources"]
    if not isinstance(raw_resources, list) or not raw_resources:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy.resources must be a non-empty array",
        )
    resources: list[TaxonomyResource] = []
    all_names: list[str] = []
    for index, raw in enumerate(raw_resources):
        resource = _object(
            raw,
            f"taxonomy.resources[{index}]",
            {"canonical", "aliases", "allowed_modes", "description"},
        )
        canonical = _identifier(
            resource["canonical"], f"taxonomy.resources[{index}].canonical"
        )
        aliases = _string_array(
            resource["aliases"], f"taxonomy.resources[{index}].aliases"
        )
        for alias_index, alias in enumerate(aliases):
            _identifier(alias, f"taxonomy.resources[{index}].aliases[{alias_index}]")
        allowed_modes = _string_array(
            resource["allowed_modes"],
            f"taxonomy.resources[{index}].allowed_modes",
        )
        if not allowed_modes or not set(allowed_modes) <= _RESOURCE_MODES:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"taxonomy.resources[{index}].allowed_modes is unsupported",
            )
        _string(
            resource["description"],
            f"taxonomy.resources[{index}].description",
        )
        resources.append(TaxonomyResource(canonical, aliases, allowed_modes))
        all_names.extend((canonical, *aliases))
    if len(all_names) != len(set(all_names)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "taxonomy resource canonical names and aliases must be globally unique",
        )
    return ContractTaxonomy(
        schema=schema,
        scope=scope,
        decision_precedence=precedence,
        capabilities=tuple(sorted(capabilities)),
        resources=tuple(sorted(resources, key=lambda value: value.canonical)),
    )


def parse_contract(payload: Any) -> ExtensionContract:
    """Parse the complete ECPA 0.1 draft contract without executing a plugin."""
    fields = {
        "schema",
        "id",
        "version",
        "host",
        "capabilities",
        "resources",
        "process_obligations",
        "rollback",
        "authority",
    }
    if not isinstance(payload, dict) or set(payload) not in (
        fields,
        fields | {"deprecated"},
    ):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "contract fields do not match ecpa-manifest/0.1-draft",
        )
    if payload.get("schema") != "ecpa-manifest/0.1-draft":
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, "unsupported contract schema"
        )
    extension_id = _identifier(payload["id"], "id")
    version = _public_version(payload["version"], "version")
    host = _object(payload["host"], "host", {"runtime", "version"})
    host_runtime = _string(host["runtime"], "host.runtime")
    host_range = _public_specifier(host["version"], "host.version")
    capabilities = _object(
        payload["capabilities"], "capabilities", {"provides", "requires"}
    )
    provides = _capabilities(
        capabilities["provides"], "capabilities.provides", requirements=False
    )
    requires = _capabilities(
        capabilities["requires"], "capabilities.requires", requirements=True
    )

    raw_resources = payload["resources"]
    if not isinstance(raw_resources, list):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, "resources must be an array"
        )
    resources: list[ContractResource] = []
    for index, raw in enumerate(raw_resources):
        if not isinstance(raw, dict) or set(raw) not in (
            {"name", "mode"},
            {"name", "mode", "mediator"},
        ):
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"resources[{index}] requires name/mode and optional mediator",
            )
        item = raw
        name = _identifier(item["name"], f"resources[{index}].name")
        mode = _string(item["mode"], f"resources[{index}].mode")
        mediator = item.get("mediator")
        if mode not in _RESOURCE_MODES:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"resources[{index}].mode is unsupported",
            )
        if mode == "mediated":
            mediator = _identifier(mediator, f"resources[{index}].mediator")
        elif mediator is not None:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"resources[{index}] cannot declare a mediator for {mode}",
            )
        resources.append(ContractResource(name, mode, mediator))
    resource_names = [item.name for item in resources]
    if len(resource_names) != len(set(resource_names)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "resources contains duplicate resource names",
        )

    raw_obligations = payload["process_obligations"]
    if not isinstance(raw_obligations, list) or not raw_obligations:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "process_obligations must be a non-empty array",
        )
    obligations: list[ProcessObligationContract] = []
    for index, raw in enumerate(raw_obligations):
        if not isinstance(raw, dict):
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"process_obligations[{index}] must be an object",
            )
        completion = _string(
            raw.get("completion"), f"process_obligations[{index}].completion"
        )
        required_fields = {
            "role",
            "event",
            "completion",
            "authority",
            "capability_direction",
            "capability",
        }
        expected_fields = (
            required_fields | {"quorum"} if completion == "quorum" else required_fields
        )
        item = _object(raw, f"process_obligations[{index}]", expected_fields)
        role = _string(item["role"], f"process_obligations[{index}].role")
        event = _string(item["event"], f"process_obligations[{index}].event")
        if event not in _EVENTS or completion not in _COMPLETION_MODES:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"process_obligations[{index}] has unsupported semantics",
            )
        authority_kind = _string(
            item["authority"], f"process_obligations[{index}].authority"
        )
        if authority_kind not in _AUTHORITY_KINDS:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"process_obligations[{index}].authority is unsupported",
            )
        if event in {"loaded", "invoked"} and authority_kind != "runtime":
            raise ContractPlanningError(
                PlanningErrorCode.AUTHORITY_VIOLATION,
                f"process_obligations[{index}] {event} must use runtime authority",
            )
        capability_direction = _string(
            item["capability_direction"],
            f"process_obligations[{index}].capability_direction",
        )
        if capability_direction not in _CAPABILITY_DIRECTIONS:
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"process_obligations[{index}].capability_direction is unsupported",
            )
        capability = _identifier(
            item["capability"], f"process_obligations[{index}].capability"
        )
        declared_capabilities = {
            item.name
            for item in (provides if capability_direction == "provides" else requires)
        }
        if capability not in declared_capabilities:
            raise ContractPlanningError(
                PlanningErrorCode.AUTHORITY_VIOLATION,
                f"process_obligations[{index}] references an undeclared capability",
            )
        quorum = item.get("quorum")
        if completion == "quorum" and (
            not isinstance(quorum, int) or isinstance(quorum, bool) or quorum < 1
        ):
            raise ContractPlanningError(
                PlanningErrorCode.INVALID_CONTRACT,
                f"process_obligations[{index}].quorum must be a positive integer",
            )
        obligations.append(
            ProcessObligationContract(
                role,
                event,
                completion,
                authority_kind,
                capability_direction,
                capability,
                quorum,
            )
        )
    obligation_keys = [
        (item.role, item.event, item.capability_direction, item.capability)
        for item in obligations
    ]
    if len(obligation_keys) != len(set(obligation_keys)):
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT,
            "process_obligations contains duplicate "
            "role/event/direction/capability keys",
        )

    rollback = _object(
        payload["rollback"],
        "rollback",
        {"manager_owned", "external_operator_owned"},
    )
    authority = _object(
        payload["authority"], "authority", {"provider", "runtime", "external"}
    )
    if "deprecated" in payload:
        deprecated = _object(
            payload["deprecated"], "deprecated", {"since", "replacement"}
        )
        _string(deprecated["since"], "deprecated.since")
        _identifier(deprecated["replacement"], "deprecated.replacement")
    authority_contract = AuthorityContract(
        _authority_grants(authority["provider"], "authority.provider", "provider"),
        _authority_grants(authority["runtime"], "authority.runtime", "runtime"),
        _authority_grants(authority["external"], "authority.external", "external"),
    )
    declared_capabilities = {
        "provides": {item.name for item in provides},
        "requires": {item.name for item in requires},
    }
    for authority_kind in sorted(_AUTHORITY_KINDS):
        for grant in getattr(authority_contract, authority_kind):
            if (
                grant.capability
                not in declared_capabilities[grant.capability_direction]
            ):
                raise ContractPlanningError(
                    PlanningErrorCode.AUTHORITY_VIOLATION,
                    f"authority.{authority_kind} grant references an undeclared "
                    f"{grant.capability_direction} capability {grant.capability}",
                )
    return ExtensionContract(
        extension_id=extension_id,
        version=version,
        manifest_sha256=hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        host_runtime=host_runtime,
        host_version_range=host_range,
        provides=provides,
        requires=requires,
        resources=tuple(sorted(resources, key=lambda item: item.name)),
        process_obligations=tuple(
            sorted(
                obligations,
                key=lambda item: (
                    item.role,
                    item.event,
                    item.completion,
                    item.authority,
                    item.capability_direction,
                    item.capability,
                    item.quorum or 0,
                ),
            )
        ),
        rollback=RollbackContract(
            _string_array(rollback["manager_owned"], "rollback.manager_owned"),
            _string_array(
                rollback["external_operator_owned"],
                "rollback.external_operator_owned",
            ),
        ),
        authority=authority_contract,
    )


def _resolve_capabilities(
    contracts: tuple[ExtensionContract, ...],
) -> tuple[tuple[CapabilityBinding, ...], dict[str, set[str]]]:
    providers: dict[str, list[tuple[ExtensionContract, Capability]]] = {}
    for contract in contracts:
        for capability in contract.provides:
            providers.setdefault(capability.name, []).append((contract, capability))
    bindings: list[CapabilityBinding] = []
    dependencies = {contract.extension_id: set() for contract in contracts}
    for consumer in contracts:
        for requirement in consumer.requires:
            candidates = providers.get(requirement.name, [])
            compatible = [
                candidate
                for candidate in candidates
                if Version(candidate[1].version) in SpecifierSet(requirement.version)
            ]
            if not compatible:
                code = (
                    PlanningErrorCode.INCOMPATIBLE_CAPABILITY
                    if candidates
                    else PlanningErrorCode.MISSING_CAPABILITY
                )
                raise ContractPlanningError(
                    code,
                    f"{consumer.extension_id} requires "
                    f"{requirement.name}{requirement.version}",
                )
            if len(compatible) != 1:
                owners = sorted(candidate[0].extension_id for candidate in compatible)
                raise ContractPlanningError(
                    PlanningErrorCode.AMBIGUOUS_CAPABILITY,
                    f"{consumer.extension_id} requirement {requirement.name} "
                    f"matches {owners}",
                )
            provider, provision = compatible[0]
            bindings.append(
                CapabilityBinding(
                    requirement.name,
                    requirement.version,
                    consumer.extension_id,
                    provider.extension_id,
                    provision.version,
                )
            )
            if provider.extension_id != consumer.extension_id:
                dependencies[consumer.extension_id].add(provider.extension_id)
    return tuple(
        sorted(bindings, key=lambda item: (item.consumer, item.capability))
    ), dependencies


def _order_contracts(
    contracts: tuple[ExtensionContract, ...], dependencies: dict[str, set[str]]
) -> tuple[ExtensionContract, ...]:
    by_id = {contract.extension_id: contract for contract in contracts}
    dependents = {extension_id: set() for extension_id in by_id}
    indegree = {
        extension_id: len(required) for extension_id, required in dependencies.items()
    }
    for consumer, required in dependencies.items():
        for provider in required:
            dependents[provider].add(consumer)
    ready = [extension_id for extension_id, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[ExtensionContract] = []
    while ready:
        extension_id = heapq.heappop(ready)
        ordered.append(by_id[extension_id])
        for dependent in sorted(dependents[extension_id]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered) != len(contracts):
        cycle = sorted(
            extension_id for extension_id, count in indegree.items() if count
        )
        raise ContractPlanningError(
            PlanningErrorCode.DEPENDENCY_CYCLE,
            f"capability dependency cycle includes {cycle}",
        )
    return tuple(ordered)


def _resolve_resources(
    contracts: tuple[ExtensionContract, ...],
) -> tuple[ResourceOwnership, ...]:
    claims: dict[str, list[tuple[str, ContractResource]]] = {}
    for contract in contracts:
        for resource in contract.resources:
            claims.setdefault(resource.name, []).append(
                (contract.extension_id, resource)
            )
    summaries = []
    for resource_name, raw_claims in sorted(claims.items()):
        owners = tuple(sorted(owner for owner, _ in raw_claims))
        modes = {claim.mode for _, claim in raw_claims}
        mediators = {claim.mediator for _, claim in raw_claims}
        summaries.append((resource_name, raw_claims, owners, modes, mediators))

    resource_mode_errors = [
        (resource_name, owners)
        for resource_name, raw_claims, owners, modes, _ in summaries
        if len(owners) != len(set(owners))
        or (len(raw_claims) > 1 and modes not in ({"shared-read"}, {"mediated"}))
    ]
    if resource_mode_errors:
        resource_name, owners = resource_mode_errors[0]
        raise ContractPlanningError(
            PlanningErrorCode.RESOURCE_CONFLICT,
            f"{resource_name} has incompatible or duplicate claims from {list(owners)}",
        )

    mediator_consistency_errors = [
        (resource_name, owners)
        for resource_name, _, owners, modes, mediators in summaries
        if modes == {"mediated"} and len(mediators) != 1
    ]
    if mediator_consistency_errors:
        resource_name, owners = mediator_consistency_errors[0]
        raise ContractPlanningError(
            PlanningErrorCode.RESOURCE_CONFLICT,
            f"{resource_name} has inconsistent mediators from {list(owners)}",
        )

    mediator_presence_errors = [
        (resource_name, next(iter(mediators)))
        for resource_name, _, owners, modes, mediators in summaries
        if modes == {"mediated"} and next(iter(mediators)) not in owners
    ]
    if mediator_presence_errors:
        resource_name, mediator = mediator_presence_errors[0]
        raise ContractPlanningError(
            PlanningErrorCode.AUTHORITY_VIOLATION,
            f"{resource_name} mediator {mediator!r} has no selected ownership claim",
        )

    result: list[ResourceOwnership] = []
    for resource_name, raw_claims, owners, modes, mediators in summaries:
        if modes == {"mediated"}:
            mode = "mediated"
            mediator = next(iter(mediators))
        elif len(raw_claims) == 1:
            mode = raw_claims[0][1].mode
            mediator = raw_claims[0][1].mediator
        else:
            mode = "shared-read"
            mediator = None
        result.append(ResourceOwnership(resource_name, mode, owners, mediator))
    return tuple(result)


def _normalize_taxonomy_resources(
    contracts: tuple[ExtensionContract, ...], taxonomy: ContractTaxonomy
) -> tuple[ExtensionContract, ...]:
    lookup = {
        name: resource
        for resource in taxonomy.resources
        for name in (resource.canonical, *resource.aliases)
    }
    unknown = sorted(
        (contract.extension_id, claim.name)
        for contract in contracts
        for claim in contract.resources
        if claim.name not in lookup
    )
    if unknown:
        extension_id, resource_name = unknown[0]
        raise ContractPlanningError(
            PlanningErrorCode.UNKNOWN_RESOURCE,
            f"{extension_id} claims unknown resource {resource_name}",
        )
    invalid_modes = sorted(
        (contract.extension_id, lookup[claim.name].canonical, claim.mode)
        for contract in contracts
        for claim in contract.resources
        if claim.mode not in lookup[claim.name].allowed_modes
    )
    if invalid_modes:
        extension_id, resource_name, mode = invalid_modes[0]
        allowed_modes = lookup[resource_name].allowed_modes
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_RESOURCE_MODE,
            f"{extension_id} claims {resource_name} as {mode}; "
            f"allowed modes are {list(allowed_modes)}",
        )

    normalized: list[ExtensionContract] = []
    for contract in contracts:
        resources: list[ContractResource] = []
        for claim in contract.resources:
            rule = lookup[claim.name]
            resources.append(
                ContractResource(rule.canonical, claim.mode, claim.mediator)
            )
        normalized.append(
            replace(
                contract,
                resources=tuple(sorted(resources, key=lambda value: value.name)),
            )
        )
    return tuple(normalized)


def _validate_obligation_authority(contracts: tuple[ExtensionContract, ...]) -> None:
    for contract in contracts:
        for obligation in contract.process_obligations:
            grants = getattr(contract.authority, obligation.authority)
            expected = AuthorityGrant(
                obligation.role,
                obligation.event,
                obligation.capability_direction,
                obligation.capability,
            )
            if expected not in grants:
                raise ContractPlanningError(
                    PlanningErrorCode.AUTHORITY_VIOLATION,
                    f"{contract.extension_id} obligation "
                    f"{obligation.role}/{obligation.event}/"
                    f"{obligation.capability_direction}/{obligation.capability} "
                    f"has no matching {obligation.authority} authority grant",
                )


def _bind_obligations(
    contracts: tuple[ExtensionContract, ...],
    capability_bindings: tuple[CapabilityBinding, ...],
) -> tuple[ObligationBinding, ...]:
    requirement_providers = {
        (binding.consumer, binding.capability): binding.provider
        for binding in capability_bindings
    }
    result: list[ObligationBinding] = []
    for contract in contracts:
        for obligation in contract.process_obligations:
            provider = (
                requirement_providers[(contract.extension_id, obligation.capability)]
                if obligation.capability_direction == "requires"
                else contract.extension_id
            )
            result.append(
                ObligationBinding(
                    extension_id=contract.extension_id,
                    role=obligation.role,
                    event=obligation.event,
                    completion=obligation.completion,
                    authority=obligation.authority,
                    capability_direction=obligation.capability_direction,
                    capability=obligation.capability,
                    capability_provider=provider,
                    quorum=obligation.quorum,
                )
            )
    return tuple(
        sorted(
            result,
            key=lambda item: (
                item.extension_id,
                item.role,
                item.event,
                item.capability_direction,
                item.capability,
            ),
        )
    )


def compile_contracts(
    contracts: tuple[ExtensionContract, ...],
    *,
    host_runtime: str,
    host_version: str,
    resource_taxonomy: ContractTaxonomy | None = None,
) -> ContractPlan:
    """Compile compatible contracts into one deterministic immutable plan."""
    if not contracts:
        raise ContractPlanningError(
            PlanningErrorCode.INVALID_CONTRACT, "at least one contract is required"
        )
    runtime = _string(host_runtime, "host_runtime")
    version = Version(_public_version(host_version, "host_version"))
    ids = [contract.extension_id for contract in contracts]
    if len(ids) != len(set(ids)):
        raise ContractPlanningError(
            PlanningErrorCode.DUPLICATE_PLUGIN, "extension ids must be unique"
        )
    for contract in contracts:
        if contract.host_runtime != runtime or version not in SpecifierSet(
            contract.host_version_range
        ):
            raise ContractPlanningError(
                PlanningErrorCode.INCOMPATIBLE_HOST,
                f"{contract.extension_id} requires "
                f"{contract.host_runtime}{contract.host_version_range}",
            )
    normalized = tuple(sorted(contracts, key=lambda item: item.extension_id))
    if resource_taxonomy is not None:
        normalized = _normalize_taxonomy_resources(normalized, resource_taxonomy)
    _validate_obligation_authority(normalized)
    bindings, dependencies = _resolve_capabilities(normalized)
    ordered = _order_contracts(normalized, dependencies)
    resources = _resolve_resources(normalized)
    obligations = _bind_obligations(normalized, bindings)
    return ContractPlan(
        runtime, str(version), ordered, bindings, resources, obligations
    )
