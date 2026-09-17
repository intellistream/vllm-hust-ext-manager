# Evidence-Carrying Plugin Architecture for LLM Inference Systems

Accountable owner and project lead: `ShuhaoZhangTony` (张书豪). This is a
PI-led, self-driven research line. Student contributions may be accepted as
optional collaboration but are not ownership or delivery dependencies.

## 大模型推理插件体系结构

## Research question

How can an LLM inference plugin architecture make extensions discoverable,
composable, verifiable, and rollback-safe when the host and plugin versions
drift, workers load code in multiple processes, providers expose heterogeneous
capabilities, plugins conflict in combinations, lifecycle state diverges across
layers, and runtime effectiveness cannot be proved by static configuration?

The decision object is an activation plan for a concrete host, provider set,
plugin set, process topology, and version tuple. The plan is admissible only
when its declared capabilities, ownership, conflicts, lifecycle transitions,
and required runtime evidence are explicit. A saved enable flag is intent, not
proof that a running process used the plugin.

## Proposed contribution boundary

The research contribution is a jointly evaluated architecture, not any one
manifest field or command:

1. **Typed static manifests.** Discovery and compatibility checks operate on
   distribution metadata without importing plugin implementation modules.
2. **Capability negotiation.** Host, provider, and plugin requirements resolve
   against explicit versioned capabilities rather than package presence.
3. **Conflict planning.** A planner rejects unsatisfied or multiply owned
   resources before launch and emits a reviewable activation plan.
4. **Explicit lifecycle state.** `installed`, `configured`, `enabled`, and
   `runtime_effective` remain separate predicates with separate evidence.
5. **Process-owned evidence.** Only the process that invokes an implementation
   (or an observer owned by that process) may attest `runtime_effective`.
6. **Fail-closed activation and rollback.** Missing, stale, contradictory, or
   unauthoritative evidence blocks a new launch and preserves a deterministic
   rollback target.
7. **Provider/runtime authority separation.** The Manager validates intent and
   plans; providers translate plans; the runtime or external service retains
   operational authority. Configuration does not grant cluster, service, data,
   or driver ownership.

The architectural invariant is that no state transition may claim more than
its evidence proves. In particular, install does not imply configuration,
configuration does not imply enabled intent, and enabled intent does not imply
runtime effectiveness.

## Threat and failure model

The design must expose rather than mask:

- host/plugin API and schema version skew;
- parent/worker discovery or loading disagreement;
- heterogeneous providers reporting overlapping or incomparable capabilities;
- flag, hook, connector, scheduler, or service ownership conflicts;
- stale configured or enabled intent after package or provider changes;
- process crash, partial rollout, observer loss, and rollback interruption;
- a plugin that imports successfully but is never invoked;
- evidence replayed from a different process, launch, host, or version tuple.

Security is bounded to activation authority, provenance, and fail-closed
behavior. This project does not claim that Python plugins are a sandbox or that
manifest validation makes untrusted code safe.

## Non-goals

- It is not a plugin store, marketplace, ranking, or package-curation service.
- It is not a deployment control plane and does not operate shared services,
  clusters, drivers, or user data.
- It is not an engineering contest measured by the number of supported
  plugins, providers, entry points, or integrations.
- It does not replace provider-specific runtime validation or upstream vLLM
  compatibility testing.

## Relationship to upstream vLLM

The system builds on, rather than renames, vLLM's official plugin mechanism and
entry-point conventions. The baseline and authority boundaries follow the
official documentation:

- [vLLM Plugin System](https://docs.vllm.ai/en/latest/design/plugin_system/)
- [vLLM Architecture Overview](https://docs.vllm.ai/en/latest/design/arch_overview/)
- [vLLM Security](https://docs.vllm.ai/en/latest/usage/security/)

These links define upstream behavior at their published versions; they are not
evidence that this Manager is upstream-supported or universally compatible.

## Success criterion

The line is successful only if controlled experiments show that evidence-aware
planning reduces false activation and undetected conflicts, preserves recovery
under upgrade/rollback and process failures, and does so with bounded startup
and steady-state overhead relative to the baselines in the evaluation plan.
Otherwise the result is a bounded negative finding or an engineering utility,
not a systems-research contribution.
