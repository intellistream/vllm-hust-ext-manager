# False-effective three-arm harness M1

This directory implements the experiment control plane and a subprocess-based
reference self-test. It does not contain a real vLLM result.

The frozen arms are `vanilla-vllm-entry-points`, `manual-integration`, and
`ecpa`. Formal cells use a three-repetition Latin-square schedule and require
three independent starts per arm. The checked formal matrix is entirely
`planned` because no real service command, model/workload, and process-owned
observer were supplied. Missing metrics remain JSON `null` or empty CSV cells.

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
policy effect occurred. Every observer event must echo the matching ACK result,
challenge, sequence, and invocation identity; duplicate, missing, reordered, or
inconsistent phase bindings fail closed.

`formal-real` is fail closed behind the canonical `verified-adapters.json`
registry. A registered entry pins the resolved executable, every file-backed
argv component, observer command, arm contract, and a `vllm-hust-host`-owned
event channel. The registry is intentionally empty until a real vLLM-HUST
adapter and host observer are reviewed. The runner gives no SUT-authored
telemetry path to the observer. Effectiveness, invocation, activation path, and
lifecycle facts must be emitted by the registry-pinned observer after reading
host-owned evidence and must carry the same plan/launch/controller/invocation
identity. Linux process identity is PID plus `/proc/PID/stat` start ticks and
exact `/proc/PID/cmdline` argv. The runner reads start ticks both before and
after argv to reject PID-reuse races, and the observer independently records
the SUT identity it saw. A formal run must additionally freeze a non-empty
`required_processes` target snapshot (host, role, ordinal, and process epoch)
in the runner-bound identity. `plugin-invoked` carries the distinct
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
service starts. The runner constructs the probe from the exact registered SUT
executable and base argv, appends the actual arm activation options and a fixed
`--ecpa-formal-activation-probe`, then fingerprints that complete command. The
target parser must accept that complete argv and emit the exact canonical JSON
receipt naming its activation contract and accepted options. Its bounded raw
stdout/stderr are sealed so offline validation can recompute the output digest
and receipt. This is parser-admission evidence, not runtime-effect truth; help
text, a substring match, a separate self-reporting helper, or a caller assertion
cannot substitute for it.

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
