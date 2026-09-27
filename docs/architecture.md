# Core and Host Provider architecture

The Extension Manager is a provider-neutral intent and inspection layer. It
does not become the runtime owner of every system that can cooperate with
vLLM.

## Ownership

| Layer | Owns | Does not own |
| --- | --- | --- |
| Core | discovery, manifest validation, compatibility evidence, saved configuration, enablement intent, state projection, conflict rejection | plugin loading, shared services, drivers, KV data, Kubernetes resources |
| vLLM Provider | vLLM launch configuration, delegation to vLLM entry points, and supervision of the process tree started by `run` | processes or services not launched by `run` |
| Mooncake Provider | official connector configuration, transport compatibility, service health, and connector-operation evidence | Mooncake service start/stop/upgrade and internal C++ factories |
| Production Stack Provider | Helm values, render plan, server-dry-run inputs, rollout checks, and structured real-model Router failure/recovery evidence | Helm apply/uninstall, CRD mutation, controller deployment, model-service lifecycle and cluster credentials |

Third-party Provider factories use `vllm_hust_ext.providers`. Static extension
registrations use `vllm_hust.extension_bundles`. A Provider may delegate to an
official `vllm.*` entry point, but vLLM-HUST does not invent new entry-point
groups in the upstream namespace.

## State projection

State is evidence-based rather than one enabled flag:

`installed`, `discovered`, `compatible`, `configured`, `enabled`, `reachable`,
`healthy`, `degraded`, and `incompatible`.

These states are not a single linear finite-state machine. For example, an
enabled Mooncake adapter can remain enabled while its external service is
unreachable; the projected state is then `enabled + degraded`, preserving the
operator's intent and the failure evidence. That intent does not authorize a
new launch: `run` fails closed while a non-optional required service lacks a
healthy check.

For an external KV service, a serving-process `/health` result is not sufficient
for `healthy`. The Mooncake Provider can also consume windowed lookup/save/load
and failed-key evidence. The validated Ascend path requires the NPU-aware
`ascend` transport; TCP liveness cannot prove that NPU virtual addresses are
transferable.

## Delegation safety

The initial Provider protocol intentionally has only `plan`, `render`, and
`check`. A plan containing a mutating action is rejected by Core. Apply,
delete, driver changes, KV deletion, and production-cluster mutation require a
separate operator-owned workflow and explicit authorization.
