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
| closed/open/draining | rollback | `ROLLED_BACK` or `FAILED_SAFE` | outcome measured, never assumed |

The generation is a compare-and-swap fence and each open creates a route fence.
`open` requires signed-receipt verification, complete required-process
coverage, a valid lease, and successful generation CAS. Discovery, readiness,
load, or resolution do not satisfy these fields.

Every adapter side effect has an earlier intent row and a later receipt row.
If the process dies after actual open but before its receipt, recovery queries
the adapter's actual generation and exact route fence. An exact match records a
reconciliation receipt; any unknown or predecessor-only result closes both
routes and records `FAILED_SAFE` rather than guessing success.

Admission records are immutable by request ID and contain route fence, chosen
generation, admission/finish times, result/abort, and gate transition sequence.
Opening changes only future admissions. Draining allows already admitted
predecessor requests to finish.

`evaluate_trace` independently reads raw transition and admission tables. It
does not call gate routing methods. It checks candidate-before-open, unknown
generation/fence, and per-request generation uniqueness; missing state or
transitions is a failure and unavailable counts are `null`, not zero.

Rollback is `RESTORED_STRONG` only when predecessor snapshot and route fence
match exactly, `BEHAVIORAL` only with an explicit equivalence oracle, and
`FAILED_SAFE` when restoration fails or cannot be proved. Failed-safe closes
both generations rather than allowing mixed traffic.

```bash
PYTHONPATH=src python3 experiments/exposure_gate/reproduce.py
pytest -q tests/test_exposure_gate.py
```

The checked artifacts use a fixed clock and request IDs and are explicitly
synthetic/reference. Real Issue #9 receipts can replace the synthetic signed
inputs later without changing the gate protocol.
