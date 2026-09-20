# ECPA Interoperability Specification 0.1-draft

Specification lead and accountable owner: `ShuhaoZhangTony` (张书豪). The
draft is maintained as a PI-led/self-driven project; student participation is
optional and non-blocking.

Status: **research prototype / candidate interoperability specification**. It
is not an industry standard and does not claim adoption outside the listed
experiments.

The candidate [Attestation Profile 0.1](../../docs/design/attestation-profile-0.1.md)
defines encoding-independent statement semantics plus an RFC 8785 JCS,
detached-JWS, Ed25519/EdDSA interoperability profile. Its
[`attestation.schema.json`](attestation.schema.json) and shared
[`attestation-vectors.json`](attestation-vectors.json) are consumed by Python
and an independent Go verifier. This is a candidate profile, not an industry
standard or production trust-root/key-management design.

The Phase A host event input is defined by
[`host-plugin-evidence.schema.json`](host-plugin-evidence.schema.json) and the
[host evidence trust-boundary contract](../../docs/design/host-plugin-evidence-0.1.md).
It is unsigned audit input, not an attestation and never direct proof of
effectiveness. Legacy input without `process.assignment_source` and
`assignment_source=environment` remain auditable, but formal translation
requires `assignment_source=host` and binds it into the event identifier.

The manager-controller launch boundary consumes
[`execution-plan.schema.json`](execution-plan.schema.json). The checked parser
also requires canonical bytes, recomputes the Plan content ID, and applies
semantic uniqueness/order checks that JSON Schema alone cannot express.

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
- Contract, host, and provided-capability versions are canonical public
  [PEP 440](https://peps.python.org/pep-0440/) versions. Host and capability
  requirements are PEP 440 specifier sets evaluated with the default
  prerelease rules. Local labels are forbidden on both sides, so `==1.0`
  cannot admit an unreviewed `1.0+local` build. The reference compiler stores
  normalized versions and specifier sets in the immutable plan.
- Exclusive resources have one owner. Mediated resources are admissible only
  when every claimant names the same selected extension and that mediator has
  its own claim on the same resource; an arbitrary mediator string grants no
  authority. Unknown ownership fails closed.
- `installed`, `configured`, `enabled`, and `runtime_effective` are independent.
- Runtime evidence binds launch, process, role, artifact digest, runtime
  version, capability, event, and wall-clock observation timestamp. Freshness
  is checked against issuer/verifier policy; this field is not a monotonic clock.
- Every process obligation names its evidence-authority class and an exact
  role/event/capability-direction/capability tuple. The direction distinguishes
  evidence for a capability the extension provides from evidence that its
  process consumed a negotiated requirement. That tuple must have a matching structured
  authority grant; free-form prose cannot satisfy an obligation. `loaded` and
  `invoked` are runtime-owned facts and cannot be established by provider
  or external self-report, including through an unused grant. The capability
  must be declared by that contract as provided or
  in the named direction; a required-capability obligation is frozen in the plan together
  with the unique provider selected by capability negotiation.
- Global effectiveness requires all processes named by the obligation (or its
  explicit positive integer quorum); parent import never proves worker
  invocation. Runtime planning must additionally reject a quorum larger than
  the frozen target set.
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
parser validates L0/L1 artifacts. The pure reference contract compiler now
implements L2 admission mechanics for host/version compatibility, unambiguous
capability resolution, deterministic dependency order, observation authority,
and exclusive/shared/mediated resource ownership. L2 still requires the
independently labeled corpus precision/recall gate; L3--L4 remain experimental.
The candidate L2 inputs and manual oracle are frozen under
`experiments/contract_planner` and have passed exact-digest independent label
review, but they have not been evaluated by the compiler. No L2
precision/recall result is claimed from those artifacts.

The executable 0.1 protocol vocabulary is in `protocol.schema.json`, with a
checked instance in `protocol-instance.json`. Identifiers are SHA-256 content
IDs over UTF-8 JSON with sorted keys and no insignificant whitespace. Runtime
attestations bind the plan ID, launch ID, artifact ID, process identity and
epoch, obligation, event, validity interval, and a replay-fenced nonce. WAL
intent precedes each manager-owned side effect; receipts follow it. This is
logical-once recovery with generation CAS, not physical exactly-once execution.

An implementation must durably represent enough logical information to audit
plan identity, predecessor, launch/process epochs, transition intent and
receipt, accepted evidence/nonces, committed generation, and rollback outcome.
The storage engine and schema are implementation choices. The reference MVP
uses SQLite; ECPA does not require SQLite or prescribe a database product.
