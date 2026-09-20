# Host plugin lifecycle evidence 0.1

Status: host wire contract and deployment-owned journal adapter. It does not
claim a real BidKV, serving, or two-plugin end-to-end result.

The runtime loader observes the existing entry-point path. General Python
plugins are trusted code in the same process and can call or alter Python
internals. Therefore Phase A proves loader control flow for non-adversarial
plugins; it is not an integrity boundary against a malicious plugin. The
vLLM-HUST observer is disabled unless `VLLM_ECPA_EVIDENCE_SINK=module:callable`
is set. Default sink failures are logged and counted without changing plugin
loading; `VLLM_ECPA_EVIDENCE_STRICT=1` is an explicit fail-closed opt-in.

## Event and identity contract

`discovered`, `resolved`, `invoked`, `failed`, and `skipped` describe distinct
host observations. `observation_kind` distinguishes loader lifecycle,
scheduler resolution, and scheduler dispatch. Only a bound `invoked` event,
emitted after a general-plugin callable returns or from the native scheduler
dispatch boundary, may satisfy an invocation obligation. Scheduler dispatch
events bind a controller instance, positive invocation sequence, occurrence
ID, and host-recomputed dispatch digest. Events are deduplicated by
the full process identity, full entry-point tuple, event, and failure detail.
An event becomes delivered only after the sink returns successfully. Failed
compatibility-mode deliveries remain retryable; strict failures are sticky and
repeat deterministically. `delivery_attempt` counts attempted sink writes in
one process, while the internal delivered count increases only on acceptance.
Fork detection clears inherited delivery and sink state.
Receivers also recompute `event_id` from the exact host field ordering used by
vLLM-HUST, rather than treating an arbitrary identifier as causal provenance.

The host supplies hostname, PID, Linux process start identity, integer process
epoch, and wall-clock observation time from `time.time_ns()`. It is not a
monotonic timestamp. Current vLLM-HUST processes also label role/ordinal
provenance as `assignment_source=host` after their native entry path freezes
that identity, or `assignment_source=environment` on the compatibility path.
Legacy events without this field and compatibility events remain parseable
audit inputs, but neither can satisfy formal invocation evidence. The
`assignment_source` value is included in `event_id`; it is consistency
metadata from trusted in-process host code, not a cryptographic claim against a
malicious same-process plugin. Plan and launch IDs are injected launch context.
Entry-point group/name/value come from import metadata. Phase A deliberately
emits `plugin_id=null` and `artifact_digest=null`: the loader cannot establish
either value and must not fabricate them.

The wire schema is
[`spec/0.1/host-plugin-evidence.schema.json`](../../spec/0.1/host-plugin-evidence.schema.json).
Receivers reject unknown or missing fields, duplicate JSON keys, non-integer
epochs, invented plugin identity/digests, inconsistent bound/unbound state,
malformed scheduler causality, non-`invoked` evidence, non-host-assigned formal
identity, and any Plan, launch, epoch, or entry-point mismatch.

## Deployment-owned journal adapter

`vllm_hust_ext.host_event_sink:append_event` is the first real vLLM-HUST sink
adapter. A trusted launcher pre-creates an absolute canonical directory, sets
`ECPA_HOST_EVENT_DIR`, and configures vLLM-HUST with:

```text
VLLM_ECPA_EVIDENCE_SINK=vllm_hust_ext.host_event_sink:append_event
```

The sink validates the current strict wire contract, canonicalizes the event,
and appends it to a process-specific mode-0600 JSONL journal. It restores mode
0600 before appending to a pre-existing owned journal and refuses symlink
destinations and non-owned/non-regular files. Existing journals and reader
inputs are opened nonblocking so a FIFO cannot stall the scheduler or evidence
ingestion before the regular-file check. To avoid silently adding a
synchronous scheduler-hot-path durability cost, fsync is off by default. With
`ECPA_HOST_EVENT_FSYNC=1`, the sink requests an fsync of each appended record
and, when it creates a journal, the containing directory entry. The environment
manifest and overhead results must record this choice. Filesystem and hardware
durability still follow the deployment's fsync guarantees; the adapter does not
claim stronger distributed or storage-device semantics.
`read_events` independently opens journals without following symlinks,
preserves each exact line, rejects partial records and duplicate event IDs, and
returns both the raw bytes and parsed event. The journal is an observer input,
not by itself a signed receipt or proof of complete worker coverage.

For manager-controlled launches, the launcher freezes the journal directory's
device and inode in `ECPA_HOST_EVENT_DEVICE` and `ECPA_HOST_EVENT_INODE`. Both
writer and reader open the directory itself with `O_DIRECTORY|O_NOFOLLOW`,
recheck that it is private and owned, compare the frozen identity, and perform
journal operations relative to that open directory descriptor. Permission
drift and replacement of the configured path fail closed at the use point.

## Trust boundary

Raw host bytes remain unsigned audit input and can never directly make a Plan
Effective. `translate_invocation` preserves the exact bytes, hashes those
bytes as `evidence_digest`, matches the entry-point tuple to an explicit
`EntryPointBinding`, and obtains plugin identity and artifact digest only from
the selected Plan. It returns an unsigned `AttestationStatement`. A trusted
host issuer must sign that statement; the coordinator accepts only the
existing signed-attestation verifier path and still checks obligation coverage.

Thus these are separate facts:

1. the host observed an entry point;
2. trusted ingestion bound it to one Plan artifact;
3. a trusted key signed that binding;
4. coordinator policy accepted complete process coverage.

No earlier fact implies a later one.

The journal sink must be configured by a deployment-controlled launcher before
its output is useful evidence. The manager-controller provides a single-host
launch binding, but the sink does not itself implement authenticated transport,
a multi-host durable outbox, production key custody, or malicious-plugin
isolation. Those remain frozen follow-up architecture and real-experiment
boundaries.

## Independent effect snapshot

`vllm_hust_ext.host_observer.observe_bound_invocations` is the production-side
primitive for turning the deployment-owned journal into an independently
auditable effect snapshot. It reopens the private journal directory against a
device/inode identity, rejects unbound, cross-launch, and non-host-assigned
records, matches explicit Plan plugin, obligation, and entry-point tuples,
and rereads each effect process from `/proc`. PID, field 22 start ticks, and
exact argv are captured with a before/after start-tick check so PID reuse or
process exit fails closed. Exact host-event bytes are retained as base64 plus a
SHA-256 digest. Stale-epoch invocation bytes remain auditable but contribute
zero coverage; an unrelated entry point cannot satisfy the selected binding;
one Linux identity cannot cover multiple logical targets. The observer requires
one explicit entry-point binding for every Plan obligation and evaluates the
whole required-process snapshot in one pass, rather than separately evaluating
roles and accidentally resetting the identity-uniqueness check.

Only scheduler resolution/dispatch events carry the host-produced controller
instance. A loader-only invocation therefore reports no controller binding,
even when its caller supplied an expected controller value. Plan and launch
binding still apply, but they are not relabeled as controller attribution.

The snapshot proves only the selected invocation obligation. In particular it
does not rename a target ACK into service readiness, workload completion,
fault application, or shutdown evidence. Those formal-run lifecycle facts
still require independently owned probes or actuator receipts before a first
cell may be complete. The verified adapter registry therefore remains empty.
