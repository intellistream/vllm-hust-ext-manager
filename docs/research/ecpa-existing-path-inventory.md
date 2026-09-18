# ECPA existing plugin-path inventory and next experiments

Snapshot: vLLM-HUST `feature/upstream-sync-20260917`, Phase A branch
`codex/ecpa-plugin-evidence-phase-a`.

## Existing paths and Phase A coverage

The existing `vllm.plugins.load_plugins_by_group` uses Python entry-point
metadata, applies `VLLM_PLUGINS`, and calls `EntryPoint.load()`. No replacement
loader was added. `load_general_plugins` remains guarded once per process and
is reached from argument/config construction, async CLI parser construction,
V1 EngineCore construction, worker construction, and lazy model-registry
loading. Consequently process0, engine-core, and worker processes can each
produce their own host identity and epoch.

Phase A instruments that shared discovery/resolution path and the general
plugin callable path. It proves synthetic ordering and negative behavior:
discovery does not imply resolution, resolution does not imply invocation,
call failure does not emit invocation, an allowlist skip is explicit, repeated
general loading does not duplicate evidence, and the disabled observer leaves
the existing behavior unchanged.

Known gaps are explicit. Endpoint plugins have additional factory,
required-task, router-attachment, and app-state initialization stages. Platform
plugins execute detection functions and choose exactly one platform. IO
processor and stat-logger groups have their own consumers. Phase A observes
their common entry-point discovery/resolution only; it does **not** call their
later stages `invoked`. This avoids false evidence until each consumer's true
effect boundary is separately instrumented.

## Field provenance

| Field | Authoritative source |
|---|---|
| event and entry-point tuple | host loader around `importlib.metadata.EntryPoint` |
| hostname/PID/start identity | running host process and `/proc/self/stat` |
| role/ordinal/epoch | trusted launch environment |
| observation time | host clock at the observation site |
| Plan/launch ID | trusted launch environment; checked at ingestion |
| plugin ID/artifact digest | absent in raw event; selected Plan only |
| evidence digest | SHA-256 of exact received raw bytes |

## Frozen real-plugin experiments for Apei

Phase A infrastructure is PI-owned and already implemented. Apei's later task
is limited to these two experiments; neither result may be claimed until raw
artifacts and commands are checked in.

1. Run one pinned BidKV general-plugin cell across process0, engine-core, and
   every worker. Preserve commit IDs, launch environment, raw events, accepted
   signed statements, process inventory, and a negative missing-worker or
   stale-epoch case. Report startup and event-to-acceptance latency plus event
   bytes and signing/verifying cost.
2. Run one pinned second plugin on a different existing consumer path
   (endpoint or platform). Instrument that consumer's actual effect boundary,
   then preserve the same artifacts plus one factory/detection failure and one
   Plan/entry-point mismatch. Do not reuse general-plugin `resolved` as proof
   that endpoint routes or a platform became effective.

Each experiment must link its implementation PR, record hardware/software
versions and exact reproduction commands, and report failures as failures. A
synthetic test, import, package installation, or unsigned host event is not a
real-plugin E2E result.

