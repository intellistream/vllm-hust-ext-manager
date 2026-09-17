# Protocol and state machine

Public progression is `Intent -> Resolved -> Planned -> Preparing -> Prepared
-> Launching -> Observing -> CommitReady -> Effective`. Exceptional paths are
`Degraded`, `Reconcile`, `Rollback`, `RolledBack`, and `FailedSafe`.
`PartiallyLaunched` may exist as an internal observation; ECPA never exposes or
claims `PartiallyEffective`.

Protocol phases are Discover, Resolve, Plan, Prepare, Launch, Observe, Commit,
and Rollback. Every external side effect requires a WAL record before dispatch
and a receipt afterward. Delivery is at least once; operation IDs, epochs and
fences provide logical-once interpretation. This is not physical exactly-once.

Commit CASes the predecessor generation and atomically publishes only the
effectiveness claim. It does not make distributed side effects atomic. Recovery
must reacquire host inventory and new attestations; old evidence cannot be
replayed. Rollback convergence is conditional on the recorded authority and
reachable predecessor operations.
