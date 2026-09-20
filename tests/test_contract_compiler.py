import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from vllm_hust_ext.contract_compiler import (
    ContractPlanningError,
    PlanningErrorCode,
    compile_contracts,
    parse_contract,
    parse_contract_taxonomy,
)


def manifest(
    extension_id: str,
    *,
    provides: list[tuple[str, str]] | None = None,
    requires: list[tuple[str, str]] | None = None,
    resources: list[tuple[str, str, str | None]] | None = None,
    host_range: str = ">=0.11,<0.12",
):
    provisions = list(provides or [])
    requirements = list(requires or [])
    if provisions:
        obligation_capability = provisions[0][0]
        obligation_direction = "provides"
    elif requirements:
        obligation_capability = requirements[0][0]
        obligation_direction = "requires"
    else:
        obligation_capability = f"{extension_id}.lifecycle"
        obligation_direction = "provides"
        provisions.append((obligation_capability, "1"))
    return {
        "schema": "ecpa-manifest/0.1-draft",
        "id": extension_id,
        "version": "1.0.0",
        "host": {"runtime": "vllm", "version": host_range},
        "capabilities": {
            "provides": [
                {"name": name, "version": version} for name, version in provisions
            ],
            "requires": [
                {"name": name, "version": version} for name, version in requirements
            ],
        },
        "resources": [
            {
                "name": name,
                "mode": mode,
                **({"mediator": mediator} if mediator is not None else {}),
            }
            for name, mode, mediator in resources or []
        ],
        "process_obligations": [
            {
                "role": "worker",
                "event": "invoked",
                "completion": "all",
                "authority": "runtime",
                "capability_direction": obligation_direction,
                "capability": obligation_capability,
            }
        ],
        "rollback": {
            "manager_owned": ["rendered configuration"],
            "external_operator_owned": [],
        },
        "authority": {
            "provider": [],
            "runtime": [
                {
                    "role": "worker",
                    "event": "invoked",
                    "capability_direction": obligation_direction,
                    "capability": obligation_capability,
                }
            ],
            "external": [],
        },
    }


def compile_raw(*items):
    return compile_contracts(
        tuple(parse_contract(item) for item in items),
        host_runtime="vllm",
        host_version="0.11.2",
    )


def assert_code(code, *items):
    with pytest.raises(ContractPlanningError) as error:
        compile_raw(*items)
    assert error.value.code is code


def test_compiles_dependency_order_and_content_addressed_plan_deterministically():
    provider = manifest(
        "org.example.provider",
        provides=[("org.example.scheduler-interface", "2.1")],
        resources=[("org.example.health-source", "shared-read", None)],
    )
    consumer = manifest(
        "org.example.consumer",
        requires=[("org.example.scheduler-interface", ">=2,<3")],
        resources=[("org.example.health-source", "shared-read", None)],
    )

    forward = compile_raw(provider, consumer)
    reverse = compile_raw(consumer, provider)

    assert [item.extension_id for item in forward.ordered_contracts] == [
        "org.example.provider",
        "org.example.consumer",
    ]
    assert forward == reverse
    assert forward.plan_id == reverse.plan_id
    assert forward.capability_bindings[0].provider == "org.example.provider"
    assert forward.capability_bindings[0].consumer == "org.example.consumer"
    consumer_obligation = next(
        item
        for item in forward.obligation_bindings
        if item.extension_id == "org.example.consumer"
    )
    assert consumer_obligation.capability == "org.example.scheduler-interface"
    assert consumer_obligation.capability_direction == "requires"
    assert consumer_obligation.capability_provider == "org.example.provider"
    assert forward.resource_ownership[0].owners == (
        "org.example.consumer",
        "org.example.provider",
    )


def test_checked_in_minimal_contract_compiles_without_importing_plugin_code():
    payload = json.loads(Path("spec/0.1/examples/minimal-valid.json").read_text())
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())
    Draft7Validator(schema).validate(payload)
    contract = parse_contract(payload)

    plan = compile_contracts((contract,), host_runtime="vllm", host_version="0.11.2")

    assert plan.ordered_contracts == (contract,)
    assert plan.resource_ownership[0].resource == (
        "org.vllm-hust.scheduler.policy-slot"
    )
    assert plan.plan_id.startswith("contract-plan:sha256:")


def test_missing_incompatible_and_ambiguous_capabilities_are_distinct():
    consumer = manifest(
        "org.example.consumer",
        requires=[("org.example.scheduler-interface", ">=2,<3")],
    )
    assert_code(PlanningErrorCode.MISSING_CAPABILITY, consumer)

    old_provider = manifest(
        "org.example.old-provider",
        provides=[("org.example.scheduler-interface", "1.9")],
    )
    assert_code(PlanningErrorCode.INCOMPATIBLE_CAPABILITY, old_provider, consumer)

    provider_a = manifest(
        "org.example.provider-a",
        provides=[("org.example.scheduler-interface", "2.0")],
    )
    provider_b = manifest(
        "org.example.provider-b",
        provides=[("org.example.scheduler-interface", "2.2")],
    )
    assert_code(
        PlanningErrorCode.AMBIGUOUS_CAPABILITY,
        provider_a,
        provider_b,
        consumer,
    )


def test_capability_cycles_are_rejected_instead_of_arbitrarily_ordered():
    first = manifest(
        "org.example.first",
        provides=[("org.example.first-capability", "1")],
        requires=[("org.example.second-capability", ">=1,<2")],
    )
    second = manifest(
        "org.example.second",
        provides=[("org.example.second-capability", "1")],
        requires=[("org.example.first-capability", ">=1,<2")],
    )
    assert_code(PlanningErrorCode.DEPENDENCY_CYCLE, first, second)


def test_same_resource_different_plugin_names_conflict():
    resource = "org.vllm-hust.scheduler.policy-slot"
    first = manifest("org.example.alpha", resources=[(resource, "exclusive", None)])
    second = manifest("org.example.beta", resources=[(resource, "exclusive", None)])

    assert_code(PlanningErrorCode.RESOURCE_CONFLICT, first, second)


def test_frozen_taxonomy_normalizes_aliases_and_fails_unknown_resources_closed():
    taxonomy = parse_contract_taxonomy(
        json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())
    )
    first = parse_contract(
        manifest(
            "org.example.alpha",
            resources=[("org.vllm-hust.scheduler.preemption-slot", "exclusive", None)],
        )
    )
    alias = parse_contract(
        manifest(
            "org.example.beta",
            resources=[("org.vllm.scheduler.victim-selector", "exclusive", None)],
        )
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (first, alias),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.RESOURCE_CONFLICT

    unknown = parse_contract(
        manifest(
            "org.example.unknown",
            resources=[("org.example.hidden-resource", "exclusive", None)],
        )
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (unknown,),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.UNKNOWN_RESOURCE


def test_frozen_taxonomy_rejects_disallowed_mode_before_capability_resolution():
    taxonomy = parse_contract_taxonomy(
        json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())
    )
    item = manifest(
        "org.example.invalid-mode",
        requires=[("org.example.missing", ">=1")],
        resources=[("org.vllm-hust.platform.backend-slot", "shared-read", None)],
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (parse_contract(item),),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.INVALID_RESOURCE_MODE


def test_taxonomy_precedence_is_global_not_resource_traversal_order():
    taxonomy = parse_contract_taxonomy(
        json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())
    )
    item = manifest(
        "org.example.multiple-invalid",
        resources=[
            ("org.vllm-hust.platform.backend-slot", "mediated", "org.example.m"),
            ("org.zzz.unknown-resource", "exclusive", None),
        ],
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (parse_contract(item),),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.UNKNOWN_RESOURCE


def test_alias_normalization_rejects_duplicate_claim_by_same_contract():
    taxonomy = parse_contract_taxonomy(
        json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())
    )
    duplicate = parse_contract(
        manifest(
            "org.example.duplicate-reader",
            resources=[
                ("org.vllm-hust.runtime.lifecycle-events", "shared-read", None),
                ("org.vllm.runtime.lifecycle-observation", "shared-read", None),
            ],
        )
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (duplicate,),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.RESOURCE_CONFLICT


def test_resource_mode_and_mediator_checks_use_global_precedence():
    taxonomy = parse_contract_taxonomy(
        json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())
    )
    ghost = manifest(
        "org.example.deployment-client",
        resources=[
            (
                "org.vllm-hust.deployment.replicas",
                "mediated",
                "org.example.absent-mediator",
            )
        ],
    )
    exclusive_a = manifest(
        "org.example.preemption-a",
        resources=[("org.vllm-hust.scheduler.preemption-slot", "exclusive", None)],
    )
    exclusive_b = manifest(
        "org.example.preemption-b",
        resources=[("org.vllm.scheduler.victim-selector", "exclusive", None)],
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            tuple(parse_contract(item) for item in (ghost, exclusive_a, exclusive_b)),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.RESOURCE_CONFLICT

    mediated_a = manifest(
        "org.example.preemption-mediated-a",
        resources=[
            (
                "org.vllm-hust.scheduler.preemption-slot",
                "mediated",
                "org.example.mediator-a",
            )
        ],
    )
    mediated_b = manifest(
        "org.example.preemption-mediated-b",
        resources=[
            (
                "org.vllm.scheduler.victim-selector",
                "mediated",
                "org.example.mediator-b",
            )
        ],
    )
    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            tuple(parse_contract(item) for item in (ghost, mediated_a, mediated_b)),
            host_runtime="vllm",
            host_version="0.11.2",
            resource_taxonomy=taxonomy,
        )
    assert error.value.code is PlanningErrorCode.RESOURCE_CONFLICT


def test_taxonomy_parser_rejects_scope_order_and_alias_ambiguity():
    payload = json.loads(Path("spec/0.1/contract-taxonomy.json").read_text())

    wrong_scope = copy.deepcopy(payload)
    wrong_scope["scope"] = "another-runtime"
    with pytest.raises(ContractPlanningError) as error:
        parse_contract_taxonomy(wrong_scope)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    wrong_order = copy.deepcopy(payload)
    wrong_order["decision_precedence"].reverse()
    with pytest.raises(ContractPlanningError) as error:
        parse_contract_taxonomy(wrong_order)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    duplicate_alias = copy.deepcopy(payload)
    duplicate_alias["resources"][1]["aliases"].append(
        duplicate_alias["resources"][0]["canonical"]
    )
    with pytest.raises(ContractPlanningError) as error:
        parse_contract_taxonomy(duplicate_alias)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_mediated_sharing_requires_one_explicit_mediator():
    resource = "org.vllm-hust.scheduler.policy-slot"
    first = manifest(
        "org.example.alpha",
        resources=[(resource, "mediated", "org.example.policy-mediator")],
    )
    second = manifest(
        "org.example.beta",
        resources=[(resource, "mediated", "org.example.policy-mediator")],
    )
    mediator = manifest(
        "org.example.policy-mediator",
        resources=[(resource, "mediated", "org.example.policy-mediator")],
    )
    plan = compile_raw(first, second, mediator)
    assert plan.resource_ownership[0].mode == "mediated"
    assert plan.resource_ownership[0].mediator == "org.example.policy-mediator"

    assert_code(PlanningErrorCode.AUTHORITY_VIOLATION, first, second)

    different = copy.deepcopy(second)
    different["resources"][0]["mediator"] = "org.example.other-mediator"
    assert_code(PlanningErrorCode.RESOURCE_CONFLICT, first, different, mediator)


def test_host_duplicate_and_contract_shape_fail_closed():
    item = manifest("org.example.extension")
    assert_code(
        PlanningErrorCode.INCOMPATIBLE_HOST,
        manifest("org.example.extension", host_range=">=0.12"),
    )
    assert_code(
        PlanningErrorCode.DUPLICATE_PLUGIN,
        item,
        copy.deepcopy(item),
    )

    malformed = copy.deepcopy(item)
    malformed["unexpected"] = True
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(malformed)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_nonoptional_invocation_obligation_requires_runtime_authority():
    item = manifest("org.example.extension")
    item["authority"]["runtime"] = []

    assert_code(PlanningErrorCode.AUTHORITY_VIOLATION, item)

    item["process_obligations"][0]["completion"] = "optional"
    assert_code(PlanningErrorCode.AUTHORITY_VIOLATION, item)


@pytest.mark.parametrize(
    ("mode", "mediator"),
    [("mediated", None), ("exclusive", "org.example.mediator")],
)
def test_resource_mediator_semantics_are_strict(mode, mediator):
    item = manifest(
        "org.example.extension",
        resources=[("org.example.resource", mode, mediator)],
    )
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_schema_valid_resource_without_mediator_matches_reference_parser():
    item = manifest(
        "org.example.extension",
        resources=[("org.example.resource", "exclusive", None)],
    )
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())

    Draft7Validator(schema).validate(item)
    contract = parse_contract(item)

    assert contract.resources[0].mediator is None


def test_capability_versions_use_canonical_pep440_public_semantics():
    provider = manifest(
        "org.example.provider",
        provides=[("org.example.capability", "1.0.0")],
    )
    consumer = manifest(
        "org.example.consumer",
        requires=[("org.example.capability", "==1.0")],
    )
    plan = compile_raw(provider, consumer)
    assert plan.capability_bindings[0].provided_version == "1.0.0"

    local_provider = manifest(
        "org.example.local-provider",
        provides=[("org.example.capability", "1.0+unreviewed")],
    )
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(local_provider)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    local_requirement = manifest(
        "org.example.local-consumer",
        requires=[("org.example.capability", "==1.0+unreviewed")],
    )
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(local_requirement)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    with pytest.raises(ContractPlanningError) as error:
        compile_contracts(
            (parse_contract(provider),),
            host_runtime="vllm",
            host_version="0.11.2+unreviewed",
        )
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_quorum_requires_explicit_positive_threshold_and_matching_authority():
    item = manifest("org.example.extension")
    item["process_obligations"][0]["completion"] = "quorum"
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())

    assert list(Draft7Validator(schema).iter_errors(item))
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    item["process_obligations"][0]["quorum"] = 0
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    item["process_obligations"][0]["quorum"] = 2
    plan = compile_raw(item)
    assert plan.ordered_contracts[0].process_obligations[0].quorum == 2

    item["authority"]["runtime"][0]["role"] = "different-worker"
    assert_code(PlanningErrorCode.AUTHORITY_VIOLATION, item)


def test_invocation_cannot_be_satisfied_by_provider_self_report():
    item = manifest("org.example.extension")
    grant = item["authority"]["runtime"].pop()
    item["authority"]["provider"].append(grant)
    item["process_obligations"][0]["authority"] = "provider"
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())

    assert list(Draft7Validator(schema).iter_errors(item))
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.AUTHORITY_VIOLATION


def test_free_form_authority_prose_cannot_satisfy_an_obligation():
    item = manifest("org.example.extension")
    item["authority"]["runtime"] = ["not an observation mapping"]
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())

    assert list(Draft7Validator(schema).iter_errors(item))
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_obligation_capability_is_required_and_must_be_declared():
    item = manifest("org.example.extension")
    item["process_obligations"][0]["capability"] = None
    item["authority"]["runtime"][0]["capability"] = None
    schema = json.loads(Path("spec/0.1/manifest.schema.json").read_text())

    assert list(Draft7Validator(schema).iter_errors(item))
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT

    undeclared = manifest("org.example.undeclared")
    undeclared["process_obligations"][0]["capability"] = "org.example.missing"
    undeclared["authority"]["runtime"][0]["capability"] = "org.example.missing"
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(undeclared)
    assert error.value.code is PlanningErrorCode.AUTHORITY_VIOLATION

    undeclared_grant = manifest("org.example.undeclared-grant")
    undeclared_grant["authority"]["runtime"].append(
        {
            "role": "worker",
            "event": "health-observed",
            "capability_direction": "provides",
            "capability": "org.example.missing",
        }
    )
    with pytest.raises(ContractPlanningError) as error:
        parse_contract(undeclared_grant)
    assert error.value.code is PlanningErrorCode.AUTHORITY_VIOLATION


def test_obligation_key_cannot_carry_conflicting_completion_policies():
    item = manifest("org.example.extension")
    duplicate = copy.deepcopy(item["process_obligations"][0])
    duplicate["completion"] = "quorum"
    duplicate["quorum"] = 1
    item["process_obligations"].append(duplicate)

    with pytest.raises(ContractPlanningError) as error:
        parse_contract(item)
    assert error.value.code is PlanningErrorCode.INVALID_CONTRACT


def test_same_named_provided_and_required_capabilities_bind_by_direction():
    capability = "org.example.bridge-capability"
    upstream = manifest(
        "org.example.upstream",
        provides=[(capability, "2")],
    )
    bridge = manifest(
        "org.example.bridge",
        provides=[(capability, "1")],
        requires=[(capability, ">=2,<3")],
    )
    bridge["process_obligations"].append(
        {
            "role": "worker",
            "event": "invoked",
            "completion": "all",
            "authority": "runtime",
            "capability_direction": "requires",
            "capability": capability,
        }
    )
    bridge["authority"]["runtime"].append(
        {
            "role": "worker",
            "event": "invoked",
            "capability_direction": "requires",
            "capability": capability,
        }
    )

    plan = compile_raw(upstream, bridge)
    bindings = {
        item.capability_direction: item.capability_provider
        for item in plan.obligation_bindings
        if item.extension_id == "org.example.bridge"
    }

    assert bindings == {
        "provides": "org.example.bridge",
        "requires": "org.example.upstream",
    }
