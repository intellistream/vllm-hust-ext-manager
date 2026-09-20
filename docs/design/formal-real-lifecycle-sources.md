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
During prepare, the source atomically publishes and fsyncs a canonical intent
containing the exact journal bytes, inode, both directory identities, and
challenge-bound transaction binding; this record does not fence or move the
journal. After commit, the source reacquires the directory lock, rejects any
terminal change to the intent, revalidates the exact snapshot, and installs a
durable per-journal source fence. Host writers take the same directory lock and
refuse to recreate a fenced journal. After the rename it atomically publishes
and fsyncs an applied record
chained to that intent. Each stage is written to a same-directory temporary
inode, fsynced, and published with `renameat2(RENAME_NOREPLACE)`; startup safely
discards unpublished temporary inodes. It then re-reads the source journal
directory: target evidence must
remain absent and every previously observed peer slot must remain present. Any
catchable post-move validation or audit failure attempts to restore the exact
quarantined inode without overwriting new evidence; a rollback collision is a
hard failure and preserves both artifacts. In the intended control flow, the
runner publishes finalized only after the source has exited normally and its
receipt and audit have been independently checked; that record chains the
applied record and receipt digest. This is not a separate-UID or cryptographic
authority boundary: under the stated trusted same-UID extension model, a
compromised peer could call the same library or rewrite owner-writable files.
The records provide crash consistency and auditable control-flow evidence, not
tamper resistance.

At every later source startup, reconciliation scans the private transaction
directory before reading evidence. A nonblocking exclusive process lease
serializes startup reconciliation and the brief prepare reservation; it is
released before the proposal. Commit reacquires it for snapshot revalidation
through audit. Kernel release on process death lets the next source recover,
while a concurrent actuator fails closed; host writers wait for the lease and
then either append normally before commit or observe the durable fence after
commit. An
intent without a valid finalized record is restored exactly and its writer
fence is removed; a source journal that only appended after a completed
restore remains valid. A finalized transaction stays quarantined. If both the
old quarantine artifact and a replacement source journal exist (including
after finalization), or if any canonical record, digest chain, inode, or byte
receipt differs, reconciliation
records a blocked state, preserves all bytes, and fails closed. Kill tests cover
the boundaries after rename and after applied-record fsync. This handles source
and runner crashes when the deployment-owned same-filesystem state survives;
it does not claim recovery from node or storage loss. The audit retains exact
raw target and peer prerequisite records, rather than only source-generated
slot summaries.

For the ECPA arm, runner startup separately verifies that the frozen process
snapshot is covered by the immutable execution Plan. Every reviewed adapter
entry now declares a scenario-scoped binding containing the exact fault-source
subcommand, descriptor digest, and plugin entry point. The validator derives the
subcommand position by strictly parsing the production actuator's complete
option grammar rather than trusting a registry-declared index. Admission reopens the
canonical descriptor and rejects an unsupported scenario, a different entry
point, a different descriptor digest, or a different actuator subcommand.
Offline validation repeats that check, and a complete three-arm cell is rejected
unless vanilla, manual, and ECPA records carry the same runner-derived
comparison binding over the scenario, descriptor digest, entry point, and
actuator semantics. The entry point is not inferred from an ECPA Plan
obligation because vanilla and manual arms have no such Plan; it is an explicit,
reviewed comparison contract whose concrete deployment value must still be
verified before registration.

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
one frozen Plan and fault descriptor, and an independent review of every
command and configuration artifact. Durable post-crash reconciliation now has
an implementation candidate and local kill/collision tests, but remains part of
the registration review rather than a claimed experiment result. Until then:

- `verified-adapters.json` stays empty;
- generated formal cells stay `planned`;
- source unit/integration tests are protocol evidence only;
- no runtime-effect, overhead, or false-effective result is claimed.

The first accepted cell must preserve the model, request body, endpoint,
hardware/software identity, process snapshot, Plan, exact bounded host-journal
read, source audit bytes, and runner generation. BidKV remains an
independent case-study algorithm; this source profile does not replace or
rewrite it.
