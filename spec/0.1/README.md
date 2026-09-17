# ECPA Interoperability Specification 0.1-draft

Specification lead and accountable owner: `ShuhaoZhangTony` (张书豪). The
draft is maintained as a PI-led/self-driven project; student participation is
optional and non-blocking.

Status: **research prototype / candidate interoperability specification**. It
is not an industry standard and does not claim adoption outside the listed
experiments.

An ECPA manifest describes identity, semantic capabilities, exclusive/shared
resources, host/provider compatibility, process evidence obligations, and a
rollback boundary. Project namespaces are reverse-DNS strings. Capability and
resource names are immutable within a major version; new optional fields are a
minor change, while removals, semantic changes, and tighter accepted values
require a major version. Deprecated names remain readable for one declared
transition window and must identify their replacement.

## Core semantics

- Discovery is static and does not import implementation code.
- Negotiation resolves every required capability to one authoritative provider.
- Exclusive resources have one owner or an explicit mediator; unknown
  ownership fails closed.
- `installed`, `configured`, `enabled`, and `runtime_effective` are independent.
- Runtime evidence binds launch, process, role, artifact digest, runtime
  version, capability, event, and monotonic timestamp.
- Global effectiveness requires all processes named by the obligation (or its
  explicit quorum policy); parent import never proves worker invocation.
- A deterministic activation plan records its predecessor. Commit happens only
  after required evidence; rollback restores manager-owned inputs and never
  claims authority over external services, data, clusters, or drivers.
- Providers translate and observe. The runtime executes. External operators
  retain service authority.

## Conformance levels

| Level | Name | Required proof |
|---|---|---|
| L0 | Discoverable | static registration resolves exactly one manifest |
| L1 | Statically Valid | schema, namespace, identity, version and capability checks pass |
| L2 | Plan Safe | negotiation is complete and resource conflicts are rejected/explained |
| L3 | Runtime Evidenced | required process-owned evidence proves the selected implementation ran |
| L4 | Rollback Verified | injected activation failure restores the recorded predecessor with evidence |

Levels are cumulative and cell-specific. A plugin may be L3 for one pinned
runtime tuple and unverified for another.

See `manifest.schema.json`, `conformance.md`, and `roadmap.md`. The checked-in
CLI skeleton validates L0/L1 artifacts and negative fixtures; L2--L4 remain
experimental gates.

The executable 0.1 protocol vocabulary is in `protocol.schema.json`, with a
checked instance in `protocol-instance.json`. Identifiers are SHA-256 content
IDs over UTF-8 JSON with sorted keys and no insignificant whitespace. Runtime
attestations bind the plan ID, launch ID, artifact ID, process identity and
epoch, obligation, event, validity interval, and a replay-fenced nonce. WAL
intent precedes each manager-owned side effect; receipts follow it. This is
logical-once recovery with generation CAS, not physical exactly-once execution.
