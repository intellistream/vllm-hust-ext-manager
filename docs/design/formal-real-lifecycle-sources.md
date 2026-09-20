# Formal-real lifecycle source profile

Status: implementation candidate; not registered; no formal-real result.

The formal runner treats a target ACK only as control-plane progress. A
separate command must establish each lifecycle fact. The runner pins that
command in `verified-adapters.json`, launches it in a new process group, and
accepts exactly one canonical fact datagram whose kernel credentials identify
that process. The source then waits for the runner's challenge-bound commit.

`ecpa-formal-source` implements five production-oriented commands:

| Command | Owned fact | Independent operation |
|---|---|---|
| `readiness-http` | service ready | total-wall-clock-bounded GET to an exact `127.0.0.1` or `::1` HTTP endpoint; proxies and redirects are disabled and the exact status is required |
| `workload-http` | workload complete | bounded POST of a canonical request whose required digest is part of the registered command; a non-empty OpenAI `choices` response is required |
| `partial-coverage-quarantine` | partial-worker-coverage fault applied | validates a canonical, digest-pinned fault descriptor and atomically moves exactly one bound worker's journal into a deployment-owned same-filesystem quarantine while retaining its exact bytes and identity |
| `journal-capture` | observer captured | strict read of the deployment-owned host journal at its frozen device/inode; at least one host-assigned, bound scheduler dispatch for the exact Plan, launch, and controller is required |
| `shutdown-process` | service shutdown | PID/start-ticks/argv verification followed by a pidfd wait for that exact controller process |

Every command writes a canonical audit record to stderr. The runner retains
the exact stderr bytes and digest in its source-process record. The audit embeds
the exact bounded HTTP request/response bytes and every record returned by the
strict bounded host-journal read as base64, so the runner generation retains
the raw evidence rather than only a source-generated summary. HTTP sources accept only numeric
loopback plain-HTTP URLs, ignore proxy environment variables, reject redirects,
cap response bytes, and enforce a total wall-clock deadline. Workload request
bytes must already be canonical JSON and match the required `--request-sha256`
argument; the runner also rechecks every fingerprinted argument file immediately
before launch.

## Bounded partial-coverage actuator

The first actuator is intentionally scenario-specific. It accepts only
`partial-worker-coverage`, requires a digest-pinned descriptor for the stable
target slot and entry point, and binds each dynamic Plan, launch, controller,
and frozen process snapshot through the challenge-bound runner request. This
avoids a command-fingerprint/Plan-ID fixed-point for the vanilla and manual
arms. It observes a target worker effect plus at least one different logical
worker slot from that snapshot. Only Plan- and launch-bound loader lifecycle
events qualify; a replacement epoch of the target slot is not a peer.

Actuation is two-phase. The source prepares and emits a proposed fact without
changing the journal. The runner validates its canonical schema, dynamic
identity, challenge, and process identity before sending commit. Only then does
the source move the target's complete journal to a private quarantine using a
same-filesystem `renameat2(RENAME_NOREPLACE)`. It verifies the source directory
and quarantine device/inode, rejects destination collisions and mixed-process
journals, and requires the moved bytes to equal the parsed prepare snapshot.
After the move it re-reads the source journal directory: target evidence must
remain absent and every previously observed peer slot must remain present. Any
catchable post-move validation or audit failure attempts to restore the exact
quarantined inode without overwriting new evidence; a rollback collision is a
hard failure and preserves the quarantine artifact. SIGKILL, host loss, or a
runner timeout after commit can bypass in-process rollback and leave the exact
journal in quarantine. That state is fail-closed for coverage certification,
but requires a durable reconciliation procedure before adapter registration.
The audit retains exact raw target and peer prerequisite records, rather than
only source-generated slot summaries.

For the ECPA arm, runner startup separately verifies that the frozen process
snapshot is covered by the immutable execution Plan. The descriptor's entry
point is registry-pinned but is not yet mechanically derived from a Plan
obligation, because vanilla and manual arms have no ECPA Plan artifact.
Independent registration review must bind that entry point to each arm's real
activation contract; automating that cross-arm binding remains part of the
registration gate.

This is an evidence-delivery fault: it does not kill the worker, mutate the
Plan, or claim that the plugin ceased executing. The formal oracle may use it
only to test whether deployment evidence incorrectly certifies complete worker
coverage. Other scenarios, including compatible positive controls, still need
their own real actuators or an explicit phase-protocol revision; a no-op must
never be labelled `fault-injected`. The current registry has one fault command
per adapter, so registering this command enables only the first
`partial-worker-coverage` cell; a scenario dispatcher or schema revision is a
prerequisite for running the full matrix through one adapter registration.

## Registration and experiment gate

Registration requires the merged vLLM-HUST host producer, exact
manager/target/observer/source fingerprints, a deployment-owned quarantine,
one frozen Plan and fault descriptor, durable post-crash quarantine
reconciliation, and an independent review of every command and configuration
artifact. Until then:

- `verified-adapters.json` stays empty;
- generated formal cells stay `planned`;
- source unit/integration tests are protocol evidence only;
- no runtime-effect, overhead, or false-effective result is claimed.

The first accepted cell must preserve the model, request body, endpoint,
hardware/software identity, process snapshot, Plan, exact bounded host-journal
read, source audit bytes, and runner generation. BidKV remains an
independent case-study algorithm; this source profile does not replace or
rewrite it.
