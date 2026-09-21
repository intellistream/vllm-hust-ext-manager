# Reference ExposureGate M1

The M1 gate is a single-host, SQLite-backed reference implementation around an
in-process scheduler-admission model. It is not a production proxy, Kubernetes
readiness controller, multi-host routing system, or production performance
result.

## State and transition contract

| Current | Operation | Next | Durable/traffic rule |
|---|---|---|---|
| `PREDECESSOR_OPEN` | `stage` | `CANDIDATE_STAGED` | predecessor remains routed |
| `CANDIDATE_STAGED` | `close` | `CANDIDATE_CLOSED` | intent before adapter close |
| `CANDIDATE_CLOSED` | `open` | `OPENING` | proof and CAS checked; intent committed first |
| `OPENING` | adapter open | `CANDIDATE_OPEN` | receipt only after side effect |
| `CANDIDATE_OPEN` | `drain` | `DRAINING` | no new predecessor admissions |
| `DRAINING` | old requests finish | `CANDIDATE_OPEN` | receipt records zero unfinished old requests |
| closed/open/draining | rollback | `ROLLED_BACK`, `FAILED_SAFE`, or `SAFETY_UNKNOWN` | actual route measured, never assumed |

The generation is a compare-and-swap fence and each open creates a route fence.
`open` accepts a non-empty `OpenProof` bound to the plan and generation. The
proof commits to durable evidence and coverage digests plus a typed lease grant
(`holder`, fencing token, expiry). The adapter revalidates that exact grant at
the traffic side effect. It also commits to the canonical candidate snapshot
digest; the digest is embedded in the route fence and persisted in the open
intent, receipt, and gate state. Normal open, recovery, and admission each
query and compare the generation, fence, and candidate snapshot digest. The
coordinator constructs this proof only after
signed-receipt verification and complete required-process coverage. Discovery,
readiness, load, or resolution do not satisfy these fields.

Every adapter side effect has an earlier intent row and a later receipt row.
Each pair carries an explicit `operation_id`; recovery suboperations use their
own IDs rather than deriving identity by splitting an operation name.
Operation IDs are stable idempotency keys. A retry that finds a pending close
or recovery-close intent reuses it, queries/retries the side effect, and appends
only its matching receipt; it never appends a second intent.
If the process dies after actual open but before its receipt, recovery queries
the adapter's actual generation and exact route fence. An exact match records a
reconciliation receipt; any unknown or predecessor-only result closes both
routes and records `FAILED_SAFE` rather than guessing success.

Admission records are immutable by request ID and contain route fence, chosen
generation, admission/finish times, result/abort, and gate transition sequence.
Finish time cannot precede admission, exactly one of result or abort is needed,
and completion is one-shot. An append-only admission event log preserves both
admit and finish observations for independent replay.
Opening changes only future admissions. Draining allows already admitted
predecessor requests to finish.

`evaluate_trace` independently reads raw transition and admission-event tables.
It does not call gate decision methods. It replays transition sources and
targets, pairs intents with receipts, and checks candidate-before-open,
unknown generation/fence, and per-request generation uniqueness. Missing state,
sequence gaps, unmatched intents, or unknown transitions fail the oracle;
unavailable counts are `null`, not zero.

Rollback is `RESTORED_STRONG` only when predecessor snapshot and route fence
match exactly and `BEHAVIORAL` only with a structured external oracle result.
`FAILED_SAFE` is reported only after an actual route query proves all traffic
closed. If closure or the route query fails, the terminal result is
`SAFETY_UNKNOWN`; new admissions remain blocked and the implementation does not
claim safety it could not observe.

## Persistence and authority boundary

The database schema is explicitly versioned as `2` and unknown versions are
rejected. Schema 2 is intentionally one-shot and requires a new database; this
reference artifact does not provide an in-place schema-1 migration. SQLite
connections use `BEGIN IMMEDIATE` for writes and state updates
also use a revision CAS. This is a one-process/single-writer reference contract,
not multi-manager coordination. Database commit and external routing cannot be
atomic; intent-before-effect, receipt-after-effect, exact route queries, and
terminal unknown outcomes are the recovery mechanism.

Open reconciliation reloads the persisted proof and typed lease and checks the
current authority grant, fencing token, and expiry before ratifying an observed
candidate route. Superseded or expired grants trigger fail-close. Pending
fail-close is reconciled before open or rollback: only an observed doubly closed
route becomes `FAILED_SAFE`; failed queries and still-open routes become
`SAFETY_UNKNOWN`.

Staging validates the adapter's actual predecessor generation, canonical
snapshot, and route fence before accepting a candidate. Coordinator staging is
compensated if the host prepare step fails. The capability is selected by the
explicit `ecpa.reference-exposure-gate/0.2` contract, not by method-name
inspection.

The canonical predecessor digest is persisted at stage. Every pre-open
admission and the post-close route query must match predecessor generation,
exact fence, and snapshot digest. Close receipts record the observed digest.
A post-stage or close-side-effect mutation triggers verified fail-close (or
`SAFETY_UNKNOWN` if closure cannot be observed) and cannot continue serving the
mutated predecessor.

```bash
PYTHONPATH=src python3 experiments/exposure_gate/reproduce.py --output /tmp/ecpa
PYTHONPATH=src python3 -m pytest -q tests/test_exposure_gate.py
```

The runner executes every scenario and writes the trace, fault matrix, and
summary; a test byte-compares fresh output with checked artifacts. They use a
fixed clock and request IDs and are explicitly synthetic/reference. This proves
reference state-machine behavior only. It does not prove a real vLLM data path,
distributed leases, throughput, latency, or production rollback.
`BEHAVIORAL` rollback in the matrix is also synthetic: it exercises the typed
oracle boundary but is not an independently measured equivalence result.

The complementary finite abstraction under
`experiments/transaction_model/` explores every reachable abstract state and
state-action pair to a fixed point. It checks admission, intent/receipt,
predecessor preservation, failed-safe, safety-unknown, and rollback invariants.
This is modeled design evidence only: it does not replace the real host adapter,
authority-owned observations, fault injection, or matched H3 recovery cells.
