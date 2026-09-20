# Formal-real lifecycle source profile

Status: implementation candidate; not registered; no formal-real result.

The formal runner treats a target ACK only as control-plane progress. A
separate command must establish each lifecycle fact. The runner pins that
command in `verified-adapters.json`, launches it in a new process group, and
accepts exactly one canonical fact datagram whose kernel credentials identify
that process. The source then waits for the runner's challenge-bound commit.

`ecpa-formal-source` implements four production-oriented commands:

| Command | Owned fact | Independent operation |
|---|---|---|
| `readiness-http` | service ready | bounded GET to an exact loopback HTTP endpoint; exact status required |
| `workload-http` | workload complete | bounded POST of a registry-fingerprinted canonical request file; a non-empty OpenAI `choices` response is required |
| `journal-capture` | observer captured | strict read of the deployment-owned host journal at its frozen device/inode; at least one exact Plan/launch event is required |
| `shutdown-process` | service shutdown | PID/start-ticks/argv verification followed by a pidfd wait for that exact controller process |

Every command writes a canonical audit record to stderr. The runner retains
the exact stderr bytes and digest in its source-process record. HTTP sources
accept only loopback plain-HTTP URLs, reject redirects, cap response bytes, and
use bounded timeouts. Workload request bytes must already be canonical JSON;
the command fingerprint therefore binds the request file and its digest.

## Intentionally missing fault source

The current frozen protocol names the third phase `fault-injected` for every
scenario, including compatible positive controls. Treating a no-op or a
runner-created marker as a real fault would recreate the false-effective
problem. This implementation therefore provides no fault command and the
trusted adapter registry remains empty.

Before the first cell, freeze one real actuator and its oracle. For the initial
`partial-worker-coverage` cell, the preferred design is a deployment-owned
evidence-delivery fault that withholds exactly one frozen worker slot without
killing the controller or changing the Plan. Its receipt must identify the
affected host/role/ordinal/epoch and retain the exact raw bytes moved or
withheld. If that mechanism cannot be implemented without a new vLLM-HUST
seam, revise the phase protocol explicitly; do not label a positive control as
`fault-injected`.

## Registration and experiment gate

Registration requires all five source commands, the merged vLLM-HUST host
producer, exact manager/target/observer/source fingerprints, one frozen Plan,
and an independent review of every command and configuration artifact. Until
then:

- `verified-adapters.json` stays empty;
- generated formal cells stay `planned`;
- source unit/integration tests are protocol evidence only;
- no runtime-effect, overhead, or false-effective result is claimed.

The first accepted cell must preserve the model, request body, endpoint,
hardware/software identity, process snapshot, Plan, host journal, source audit
bytes, and runner generation. BidKV remains an independent case-study
algorithm; this source profile does not replace or rewrite it.
