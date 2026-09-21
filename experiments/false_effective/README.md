# False-effective three-arm harness M1

This directory implements the experiment control plane and a subprocess-based
reference self-test. It does not contain a real vLLM result.

The frozen arms are `vanilla-vllm-entry-points`, `manual-integration`, and
`ecpa`. Formal cells use a three-repetition Latin-square schedule and require
three independent starts per arm. The checked formal matrix is entirely
`planned` because no real service command, model/workload, and process-owned
observer were supplied. Missing metrics remain JSON `null` or empty CSV cells.

The first executable preregistration is
[`first-formal-real-study.json`](first-formal-real-study.json): a nine-start,
three-arm `partial-worker-coverage` comparison. It fixes separate authority for
all five lifecycle phases, assumes no baseline outcome, and remains
`pre-admission` until its producer, deployment identity, commands, and adapter
registry satisfy every recorded blocker.

[`first-formal-real-deployment.json`](first-formal-real-deployment.json) is the
machine-checked registration packet for that transition. It currently keeps
every deployment and command slot null. Registration is all-or-nothing across
the three arms and five lifecycle sources, is digest-bound to the study and
protocol, and must agree with the runtime registry. The packet cannot authorize
a process; `verified-adapters.json` remains the sole runtime command authority.

```bash
PYTHONPATH=src python3 experiments/false_effective/reproduce.py --output /tmp/false-effective
# Or ingest the runner-owned manifest (hand-written JSONL is rejected):
PYTHONPATH=src python3 experiments/false_effective/reproduce.py \
  --records /path/to/formal-record-index.json --output /tmp/formal-result
```

The reference helper executes 45 real subprocess lifecycles: five scenarios
(including compatible and conditional conflict negatives), three repetitions,
and three arms. Those records are explicitly
`reference-synthetic` and the formal validator rejects them.

## Threat model

The experiment host, runner, and observer are trusted. The SUT may crash,
hang, omit events, or return incorrect behavior, but code running as the same
OS user is **not** treated as an active attacker trying to inspect `/proc`,
rewrite artifacts, or bypass process isolation. The evidence is
runner-consistent and tamper-evident under that boundary; it is not
cryptographically unforgeable and does not claim malicious-code isolation.

Executed records are runner-owned: a receipt binds evidence class,
identity, scenario/protocol digests, arm, repetition, and order. A runner receipt
binds a canonical record core, final status/cell, exact command and oracle,
exit/timeout, sanitized environment, raw observations, raw stdout/stderr,
scenario, protocol, and intake. Only `artifact_root` and the receipt's own digest
are cycle-excluded, explicitly in the receipt.
The validator reruns JSON Schema and the oracle; relabeling a reference record
as formal, omitting required lifecycle/scenario observations, or changing any
bound artifact fails validation.

The external formal runner exposes dedicated vanilla/manual/ECPA adapter
interfaces with distinct activation contracts. The runner starts the SUT and
observer as different processes and records both argv/PID/start identities.
Only the observer inherits a dedicated anonymous result-pipe write FD. The SUT
uses `close_fds`, receives no result path/FD or observer-control environment,
and its stdout cannot become formal truth. Each instruction carries a random
challenge and sequence plus a runner-generated plan ID, launch ID, controller
instance, and invocation ID. An ACK proves only that this process answered that
instruction; it is not evidence that the requested workload, fault, hook, or
policy effect occurred. Formal-real observer instructions do not include the
SUT stdout response, and a formal observation carrying `causal_ack` is rejected.
Readiness, workload completion, fault application, effect capture, and shutdown
instead carry exact canonical receipt bytes from their declared probe, driver,
actuator, host observer, or process monitor. Those bytes and their digest bind
the challenge, sequence, invocation, Plan/launch/controller, value, timestamp,
and observed process identity. The runner launches each source with a dedicated
control pipe and `SO_PASSCRED` Unix datagram channel. The kernel credential on
the receipt must identify the registered source PID, rejecting an inherited
channel used by a forked child. The runner records PID/UID/GID together with
Linux PID/start-ticks/argv and the registry-pinned executable fingerprint;
source stdout is diagnostic-only and must stay empty. A source must remain
alive after sending exactly one receipt: the runner re-reads PID/start-ticks/argv/executable
before sending a challenge-bound commit message, so an intervening `exec` fails
closed. The entire source process group is terminated on every success or
failure path. The generic observer receives no phase message in formal-real
runs. Duplicate, missing, reordered, inconsistent, unregistered, or
source-process-mismatched bindings fail closed. The canonical
receipt payload is machine-checked by `formal-lifecycle-fact.schema.json`; the
enclosing observation retains the exact datagram payload bytes as base64 and a
SHA-256 digest. Registry review remains responsible for establishing that each source
command measures or actuates its named fact rather than echoing the request.
The production-oriented `ecpa-formal-source` candidate, including its bounded
`partial-worker-coverage` evidence-quarantine actuator and remaining
deployment-registration gate, is specified in
[`docs/design/formal-real-lifecycle-sources.md`](../../docs/design/formal-real-lifecycle-sources.md).

`formal-real` is fail closed behind the canonical `verified-adapters.json`
registry. Registry schema v2 additionally requires a producer-admission
receipt before any activation probe or target process can run. The receipt
binds the exact producer repository identity, pull request, reviewed head and
tree, base, merge commit, default branch, observation time, and affirmative
human line, command, activation-path, and observer-independence reviews. An
open producer, an unreviewed producer, a v1 registry downgrade, or an
incomplete receipt fails both runtime admission and offline validation. The
receipt is a repository-owned, code-reviewed assertion: it makes the reviewed
merge facts mandatory and auditable, but it is not a live GitHub oracle,
cryptographic attestation, or runtime-effect proof. Reviewers must independently
recheck those facts before adding an entry. A registered entry pins the
resolved executable, every file-backed argv component, observer command, arm
contract, and a `vllm-hust-host`-owned event channel. It also enumerates
supported scenarios: the first
`partial-worker-coverage` binding pins the actuator subcommand by strictly
parsing the production actuator's complete option grammar, canonical fault descriptor digest, and exact plugin entry
point. Runtime and offline validators
reopen that descriptor, and formal aggregation requires the same derived
scenario/descriptor/entry-point/actuator comparison identity across all three
arms. The registry is
intentionally empty until the vLLM-HUST producer is merged after its required
human line review and a real adapter and host observer are reviewed. The runner
gives no SUT-authored telemetry path to the observer. Effectiveness, invocation,
activation path, and coverage must be emitted by the registry-pinned observer after reading
host-owned evidence; lifecycle facts come from the separately pinned sources
described above. Every event must carry the same
plan/launch/controller/invocation identity. Linux process identity is PID plus
`/proc/PID/stat` start ticks and exact `/proc/PID/cmdline` argv. The runner reads
start ticks both before and after argv to reject PID-reuse races, and each
evidence source records the SUT identity it saw. A formal run must additionally freeze a non-empty
`required_processes` target snapshot (host, role, ordinal, and process epoch)
in the runner-bound identity. The runner validates exact fields, values, and
uniqueness before it executes the registered activation probe or starts the
SUT, so an invalid target set cannot launch and be rejected only after the
experiment. `plugin-invoked` carries the distinct
host-assigned process identities observed at the real effect boundary. The
oracle derives coverage from those identities and rejects caller- or
observer-reported coverage that does not match; a controller ACK therefore
cannot stand in for EngineCore/worker execution, and one process identity
cannot cover multiple target roles. Controlled services are labeled
`interface-fixture`, may test protocol mechanics, never create a formal
manifest, and are rejected from formal aggregation even if copied, renamed, or
reached through a symlink. Direct and textual interpreter references to known
fixture paths, byte-identical fixture command files, and reviewed command files
that reference the fixture tree are also rejected. The registry remains a
trusted code-review boundary rather than a sandbox against malicious registered
code. The harness can generate raw formal records only
from registry-approved commands, but the
checked matrix stays planned because no real vLLM commands or frozen non-null
formal identity were supplied. Ready, workload, fault, observer, and shutdown
events are mandatory; startup is launch-to-ready.

Admission also executes a registry-pinned, bounded activation probe before the
service starts. Vanilla and manual arms probe the exact registered SUT command
with their activation options. ECPA instead probes the separately pinned
manager through `formal-run --ecpa-formal-activation-probe`; its real execution
must then use the same manager with a frozen execution Plan and the separately
pinned target command. The manager, target, observer, Plan ID, Plan bytes,
launch ID, and controller instance are rechecked offline. Probe stdout/stderr
are sealed so validation can recompute the output digest and receipt. This is
parser-admission evidence, not runtime-effect truth; help text, a substring
match, a separate self-reporting helper, or a caller assertion cannot substitute
for it.

`write_formal_manifest` writes each canonical JSONL/index pair into a new
generation directory, then atomically swaps one canonical current pointer.
The reader opens every pointer, generation, JSONL, and record path component
with `O_NOFOLLOW`, reads each artifact once, and validates its digest against
those same bytes.
Paper generation accepts only that runner current pointer (not arbitrary
hand-written JSON or JSONL),
verifies both representations, validates the complete batch in a temporary
directory, and atomically publishes a new output tree only after success.
Fixture commands require explicit test mode and are rejected from formal
aggregation. A caller-provided `adapter_contract_verified` boolean is rejected;
real runs require an exact command fingerprint from the code-reviewed registry.

`raw-record.schema.json` is a start-level provenance extension beside the
paper's `ecpa-result/v1`: it preserves the arm/status/null conventions while
adding evidence class, measurement source, command lifecycle, and raw
observations. Only validated `formal-real` aggregates may be projected into
paper results.
