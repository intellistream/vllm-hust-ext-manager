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
# Or ingest runner-produced formal JSONL (artifacts resolve from its directory):
PYTHONPATH=src python3 experiments/false_effective/reproduce.py \
  --records /path/to/formal-records.jsonl --output /tmp/formal-result
```

The reference helper executes 45 real subprocess lifecycles: five scenarios
(including compatible and conditional conflict negatives), three repetitions,
and three arms. Those records are explicitly
`reference-synthetic` and the formal validator rejects them.

Executed records are runner-owned: an immutable intake binds evidence class,
identity, scenario/protocol digests, arm, repetition, and order. A runner receipt
binds a canonical record core, final status/cell, exact command and oracle,
exit/timeout, sanitized environment, raw observations, raw stdout/stderr,
scenario, protocol, and intake. Only `artifact_root` and the receipt's own digest
are cycle-excluded, explicitly in the receipt.
The validator reruns JSON Schema and the oracle; relabeling a reference record
as formal, omitting required lifecycle/scenario observations, or changing any
bound artifact fails validation.

The external formal runner exposes dedicated vanilla/manual/ECPA adapter
interfaces with distinct activation contracts. Formal observations are read
only from the independent `ECPA_OBSERVER_RESULT_FILE`, never command stdout;
the reference helper is forbidden at the formal entry point. It can generate
raw formal records from supplied commands, but the
checked matrix stays planned because no real vLLM commands or frozen non-null
formal identity were supplied. Ready, workload, fault, observer, and shutdown
events are mandatory; startup is launch-to-ready.

`raw-record.schema.json` is a start-level provenance extension beside the
paper's `ecpa-result/v1`: it preserves the arm/status/null conventions while
adding evidence class, measurement source, command lifecycle, and raw
observations. Only validated `formal-real` aggregates may be projected into
paper results.
