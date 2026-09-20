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
| `readiness-http` | service ready | total-wall-clock-bounded GET to an exact `127.0.0.1` or `::1` HTTP endpoint; proxies and redirects are disabled and the exact status is required |
| `workload-http` | workload complete | bounded POST of a canonical request whose required digest is part of the registered command; a non-empty OpenAI `choices` response is required |
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
hardware/software identity, process snapshot, Plan, exact bounded host-journal
read, source audit bytes, and runner generation. BidKV remains an
independent case-study algorithm; this source profile does not replace or
rewrite it.
