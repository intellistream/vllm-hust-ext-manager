# Host plugin lifecycle evidence 0.1

Status: Phase A synthetic contract. It does not claim a real BidKV or
two-plugin end-to-end result.

The runtime loader observes the existing entry-point path. General Python
plugins are trusted code in the same process and can call or alter Python
internals. Therefore Phase A proves loader control flow for non-adversarial
plugins; it is not an integrity boundary against a malicious plugin. The
vLLM-HUST observer is disabled unless `VLLM_ECPA_EVIDENCE_SINK=module:callable`
is set. Default sink failures are logged and counted without changing plugin
loading; `VLLM_ECPA_EVIDENCE_STRICT=1` is an explicit fail-closed opt-in.

## Event and identity contract

`discovered`, `resolved`, `invoked`, `failed`, and `skipped` describe distinct
host observations. Only `invoked`, emitted after the general-plugin callable
returns, may satisfy an invocation obligation. Events are deduplicated by
the full process identity, full entry-point tuple, event, and failure detail.
An event becomes delivered only after the sink returns successfully. Failed
compatibility-mode deliveries remain retryable; strict failures are sticky and
repeat deterministically. `delivery_attempt` counts attempted sink writes in
one process, while the internal delivered count increases only on acceptance.
Fork detection clears inherited delivery and sink state.

The host supplies hostname, role, ordinal, PID, Linux process start identity,
integer process epoch, and wall-clock observation time from `time.time_ns()`.
It is not a monotonic timestamp. Plan and launch IDs are injected
launch context. Entry-point group/name/value come from import metadata. Phase A
deliberately emits `plugin_id=null` and `artifact_digest=null`: the loader
cannot establish either value and must not fabricate them.

The wire schema is
[`spec/0.1/host-plugin-evidence.schema.json`](../../spec/0.1/host-plugin-evidence.schema.json).
Receivers reject unknown or missing fields, duplicate JSON keys, non-integer
epochs, invented plugin identity/digests, non-`invoked` evidence, and any Plan,
launch, epoch, or entry-point mismatch.

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

The sink must be configured through a deployment-controlled module and
authenticated channel before its output is security evidence. Phase A does
not implement a trusted launcher for environment injection, authenticated
transport, durable outbox, production key custody, or malicious-plugin
isolation. Those are frozen follow-up architecture/real-experiment boundaries.
