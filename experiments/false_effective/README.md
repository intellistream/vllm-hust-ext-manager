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
trusted observer as different processes and records both argv/PID/start identities.
Only the observer inherits a dedicated anonymous pipe write FD. The SUT uses
`close_fds`, receives no result path/FD or observer-control environment, and its
stdout cannot directly become formal evidence. The runner drives and confirms
ready/workload/fault/observe/shutdown against SUT process signals and records
actual monotonic bounds. It can generate
raw formal records from supplied commands, but the
checked matrix stays planned because no real vLLM commands or frozen non-null
formal identity were supplied. Ready, workload, fault, observer, and shutdown
events are mandatory; startup is launch-to-ready.

`write_formal_manifest` writes canonical JSONL plus an index containing every
runner-owned `record.json` digest. Paper generation accepts only that index,
verifies both representations, validates the complete batch in a temporary
directory, and atomically publishes a new output tree only after success.

`raw-record.schema.json` is a start-level provenance extension beside the
paper's `ecpa-result/v1`: it preserves the arm/status/null conventions while
adding evidence class, measurement source, command lifecycle, and raw
observations. Only validated `formal-real` aggregates may be projected into
paper results.
