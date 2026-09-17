# Durable activation coordinator reference MVP

`vllm_hust_ext.durable_coordinator` is a single-host, single-manager reference
implementation of the ECPA activation transaction. SQLite is an implementation
choice for this MVP, not a requirement of the interoperability contract.

## Transaction and recovery contract

Each durable mutation uses one SQLite transaction. An operation records its WAL
intent and transition before invoking an adapter-owned side effect; its receipt
is committed only after the side effect returns. Plans and predecessor inputs
are immutable canonical JSON. Inventory rows bind role/ordinal to process start
identity and epoch. Nonces are database-primary-key unique. Generation commit
uses a conditional SQL update and rolls the state/WAL transaction back when the
CAS misses.

Opening a coordinator increments a durable manager epoch and invalidates prior
runtime evidence. Recovery of `Preparing`, `Launching`, or `CommitReady`
restores the predecessor traffic gate and enters `Reconcile`; `Observing`
also re-enters `Reconcile`. The manager must refresh process inventory and
re-observe fresh evidence before returning to `Observing` and attempting a
commit. A failed rollback compensation enters `FailedSafe` with a durable
outcome.

## Adapter boundary

- `HostAdapter` owns prepare, launch, inventory, and host compensation.
- `EvidenceIssuer` and `EvidenceVerifier` separate evidence production from
  policy verification.
- `TrafficGate` keeps predecessor routing until evidence-complete commit.
- `ExternalServiceAdapter` reports lease validity without transferring service
  authority to the manager.

Only deterministic fake adapters exist in this MVP. They are test doubles, not
vLLM, Kubernetes, Mooncake, or production traffic integrations.

## Minimal operation demo

Create a `SQLiteActivationStore`, construct `ActivationCoordinator` with the
fake adapters, call `plan`, `prepare`, `launch`, issue one attestation for every
required process, call `observe` for each, then call `commit` with the expected
generation. `status` reports the durable state. After a process restart, create
a new coordinator on the same database, call `recover`, refresh inventory,
resume observing, and collect fresh attestations.

The executable examples in `tests/test_durable_coordinator.py` are the current
canonical demo because they also prove crash behavior and cleanup.

## Migration and versioning

The schema is reference-MVP schema version 1 by code identity. Before a second
release, add an explicit `schema_version` table and transactional migration
runner. Migrations must be monotonic, backup-tested, and refuse unknown future
versions. Canonical plan/evidence fields may only gain optional fields within a
minor contract version; semantic changes, identity changes, or field removal
require a new major contract version and an explicit replay policy.

## Limitations

No multi-manager consensus, remote database, authenticated attestation,
production host adapter, real traffic gate, elastic membership protocol,
throughput measurement, durability benchmark, or storage compaction exists.
SQLite process-local durability does not imply distributed atomicity or
physical exactly-once side effects.
