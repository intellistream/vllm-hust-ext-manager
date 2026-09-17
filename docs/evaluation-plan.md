# Falsifiable evaluation plan

Execution accountability belongs to `ShuhaoZhangTony` (张书豪). The plan is
PI-led/self-driven; no student is required to execute or unblock a gate.

This plan evaluates the architecture in
[the research charter](research-charter.md). It does not treat package
installation, command success, or the number of integrations as evidence of
runtime effectiveness.

## Systems and baselines

Use the same host/runtime versions, plugin implementations, process topology,
workload, and repetitions for all applicable arms:

1. **Vanilla vLLM entry points:** official plugin discovery and loading without
   Manager planning or evidence state.
2. **Manual integration:** repository-documented flags, configuration, and
   operator checks applied directly without Manager negotiation.
3. **This system:** typed manifests, capability/conflict planning, explicit
   lifecycle state, provider translation, and process-owned runtime evidence.

The official references are [vLLM Plugin System](https://docs.vllm.ai/en/latest/design/plugin_system/),
[Architecture Overview](https://docs.vllm.ai/en/latest/design/arch_overview/),
and [Security](https://docs.vllm.ai/en/latest/usage/security/). Baseline behavior
must be pinned to an exact vLLM commit or release; documentation links alone do
not establish runtime behavior.

## Falsifiable hypotheses

- **H1 — truthful activation:** Across the failure matrix, this system reduces
  false-enable rate to zero in the tested cells and increases activation-event
  coverage to at least 99%, without labeling `runtime_effective` from static
  state. Any false enabled/effective claim falsifies H1 for that cell.
- **H2 — conflict planning:** Across the preregistered composability matrix,
  conflict detection achieves precision and recall of at least 0.95 against an
  independently labeled ownership oracle. Either metric below 0.95 falsifies
  H2; rejecting all compositions cannot pass precision and utility checks.
- **H3 — version and recovery safety:** Across the version-skew and recovery
  matrices, every unsupported tuple fails closed before serving, every
  supported upgrade preserves correctness, and at least 95% of injected
  upgrade/rollback failures recover automatically or by the declared bounded
  operator action within the preregistered recovery objective. An unsupported
  tuple serving as effective or an unrecoverable loss of the previous valid
  plan falsifies H3.
- **H4 — bounded cost:** Relative to manual integration, median added startup
  latency is at most 5% or 250 ms (whichever is larger), steady-state throughput
  regression is at most 1%, and p99 request-latency regression is at most 2%
  in each supported formal cell. Crossing any bound falsifies H4 for that cell.

Report cell-level results and confidence intervals; aggregate means cannot hide
a failed provider, process topology, or version tuple.

## Matrices

### Failure matrix

| Failure injection | Expected decision/evidence | Required observation |
|---|---|---|
| missing plugin distribution | not installed; activation denied | no implementation import/invocation |
| malformed or unknown manifest schema | discovery error; fail closed | structured reason and unchanged prior plan |
| incompatible host capability/version | activation denied | incompatible capability edge identified |
| provider missing or ambiguous | activation denied | no silent provider selection |
| parent discovers, worker cannot load | launch/effectiveness fails | per-process evidence identifies missing worker |
| plugin imports but hook is never invoked | enabled may remain true; not runtime-effective | zero valid invocation attestations |
| required external service unavailable | new launch denied or degraded per declared policy | provider evidence and authority owner recorded |
| stale/replayed evidence | evidence rejected | launch/process/version identity mismatch recorded |
| process crash or partial worker rollout | partial effectiveness, never global success | failed process set identified |
| rollback interrupted | last valid plan retained or bounded recovery invoked | recovery time and final state recorded |

### Composability matrix

Test single plugins, compatible pairs, incompatible pairs, and at least one
three-plugin set across these ownership classes: CLI/config key, Python hook,
scheduler/policy slot, KV connector, external service dependency, and provider
translation. Label each pair/set independently as compatible, conflicting, or
conditionally compatible before running the planner. Include conflicts with
the same resource under different names and non-conflicting plugins that share
a provider so precision cannot be inflated by blanket rejection.

### Version-skew matrix

For each formal provider, test the current supported host/plugin/manifest tuple,
the previous supported host, the next available host release, one plugin below
and above its declared range, one older manifest schema, and mixed parent/worker
versions. Separate syntactic parse compatibility, declared capability
compatibility, launch success, functional correctness, and runtime-effective
evidence. An untested tuple remains unverified, not compatible.

## Metrics and accounting

- **Activation-event coverage:** observed required activation/process events
  divided by the preregistered event oracle.
- **False-enable rate:** runs claiming enabled or runtime-effective while the
  corresponding intent or invocation oracle is false.
- **Conflict precision/recall:** compare planner decisions with the independent
  ownership oracle, including conditional conflicts.
- **Upgrade/rollback recovery:** success rate, time to recover, operator actions,
  lost/duplicated requests, and preservation of the last valid plan.
- **Startup overhead:** discovery, validation, planning, provider rendering,
  worker loading, and evidence setup reported separately and end to end.
- **Steady-state overhead:** throughput, median/p95/p99 latency, CPU time,
  memory, process messages, and evidence bytes per request or lifecycle event.

Every result records model/workload, hardware, host and plugin commits,
provider versions, process topology, warm/cold state, repetitions, raw logs,
failures, and model/API calls where applicable.

## Milestones and gates

- **M0 — taxonomy and oracle:** freeze capability/resource taxonomy, lifecycle
  predicates, failure matrix, labeled composition oracle, and exact baselines.
  **Go:** independent review finds no implicit state transition and fixtures are
  reproducible. **Stop:** an oracle cannot distinguish enabled intent from
  runtime effect.
- **M1 — negotiation and planner:** implement typed negotiation and conflict
  plans; run the full composability matrix. **Go:** H2 thresholds pass without
  blanket rejection. **Stop/redesign:** precision or recall remains below 0.95
  after one preregistered correction cycle.
- **M2 — lifecycle evidence and recovery:** implement process-owned evidence,
  fail-closed transitions, upgrade and rollback experiments. **Go:** H1 and H3
  pass in all formal cells. **Stop:** any false runtime-effective claim remains,
  or the last valid plan cannot be recovered deterministically.
- **M3 — end-to-end cost:** run matched formal baselines with at least three
  independent service starts per cell and alternating arm order. **Go:** H4
  passes together with H1-H3 and artifacts are replayable. **Stop/reclassify:**
  overhead bounds fail, evidence is incomplete, or benefits reduce to manual
  checks with no architectural advantage.

At every gate, a negative result is retained. No later milestone may convert an
unsupported or unmeasured cell into a general compatibility claim.
