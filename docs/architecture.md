# Core and Host Provider architecture

The Extension Manager is a provider-neutral intent and inspection layer. It
does not become the runtime owner of every system that can cooperate with
vLLM.

## Ownership

| Layer | Owns | Does not own |
| --- | --- | --- |
| Core | discovery, manifest validation, compatibility evidence, saved configuration, enablement intent, state projection, conflict rejection | plugin loading, shared services, drivers, KV data, Kubernetes resources |
| vLLM Provider | vLLM launch configuration, delegation to vLLM entry points, and supervision of the process tree started by `run` | processes or services not launched by `run` |
| StateAxis Provider | Hash-bound StateAxis mod plans; explicit experimental launch for active, unqualified carriers; qualified launch only with matching runtime evidence | descriptor-only candidates, implicit qualification, or production enablement from an experimental result |
| Mooncake Provider | official connector configuration, transport compatibility, service health, and connector-operation evidence | Mooncake service start/stop/upgrade and internal C++ factories |
| Production Stack Provider | Helm values, render plan, server-dry-run inputs, rollout checks, and structured real-model Router failure/recovery evidence | Helm apply/uninstall, CRD mutation, controller deployment, model-service lifecycle and cluster credentials |

Third-party Provider factories use `vllm_hust_ext.providers`. Static extension
registrations use `vllm_hust.extension_bundles`. A Provider may delegate to an
official `vllm.*` entry point, but vLLM-HUST does not invent new entry-point
groups in the upstream namespace.

Provider resolution loads only the factory selected by the Bundle. A broken or
host-dependent third-party Provider therefore cannot break checks and plans for
unrelated Bundles. Failure to import the selected Provider is reported as an
explicit incompatibility or planning error, without a Python traceback.

Inventory discovery isolates validation failures by Bundle id so a broken,
disabled distribution cannot deny visibility into every other installed MOD.
The invalid registration remains visible as a diagnostic. This tolerance is
limited to `extension list`; inspect, check, enable, plan, render, and launch
resolve their selected Bundle set strictly and fail closed.

For vLLM in-process plugins, a manifest may declare installed entry points in
`vllm.general_plugins` and `vllm.platform_plugins`. Discovery verifies that the
declaring distribution publishes both each entry-point record and its target
module. This check uses wheel/editable file metadata and never imports plugin
code. At launch, Core
merges their names with the user's `VLLM_PLUGINS`, retains `ascend`, rejects
cross-extension name ownership conflicts, and computes a stable order. This is
launch intent, not evidence that plugin code ran; only a process-owned observer
may add `runtime_effective`. A supervised launch receives Manager-owned plan
and launch IDs plus a strict evidence sink. Core accepts only bound
`runtime_effective` events whose PID/start identity still names a live process;
loader discovery, resolution, and invocation events remain insufficient.

Manifest 0.3 adds typed resource claims for composition. Core rejects two
plans when either one claims the same scoped resource exclusively. This models
scheduler, KV connector, process-carrier, port, and device ownership without
hard-coding MOD names. Shared observer claims may coexist. Providers cannot
invent claims that were absent from the installed manifest.

vLLM-HUST exposes one host-owned capability snapshot containing its host API
and protocol versions. The vLLM Provider consumes that snapshot rather than
growing one import probe per MOD. Legacy probes remain a migration path only
when the registry is absent; a present but malformed registry fails closed.

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

`run` supervises only the process tree it creates. Stop/release means signalling
that Manager-owned launch and waiting for its children to exit. Disabling an
in-process plugin affects the next host start; rollback is disable plus a clean
host restart. Package uninstall is performed by the Python package operator
only after disable and `forget`. None of these actions authorizes stopping an
external KV service or mutating Kubernetes resources.
