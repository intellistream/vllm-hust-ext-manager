# ECPA architecture

ECPA is an inference-system extension contract and transactional runtime.
Extension Manager is the reference implementation; discovery and plugin
management are inputs to the system, not its research contribution by
themselves.

## Authority graph

- Operator/control plane signs **Intent**, never runtime facts.
- Manager/planner resolves Intent into a content-hashed **Plan**, but cannot
  attest loading, invocation, traffic, lease, or health.
- Host runtime owns process inventory/epoch, actual loading, invocation, and
  traffic gates.
- Provider maps a Plan to host inputs and observations; mapping grants no new
  authority.
- Plugin self-report is supporting evidence only.
- External service proves only its lease/health/operation facts.
- Evidence store is append-only custody, not a fact issuer.

## MVP modules and order

1. Canonical IDs, immutable objects, error/state enums.
2. Single-host/single-manager planner and canonical conflict graph.
3. Append-only WAL plus receipts and fenced retries.
4. Host-owned all-worker inventory/epoch and traffic gate.
5. One external-service lease/fallback contract.
6. Fault injection for crash, replay, split brain, partial launch, and rollback.

The executable lifecycle model in `src/vllm_hust_ext/ecpa_model.py` and the
static compiler in `src/vllm_hust_ext/contract_compiler.py` are pure and
perform no external side effects. The compiler resolves normalized public
PEP 440 capability requirements to exactly one provider, derives a
deterministic dependency order, rejects cycles, binds each process obligation
to an exact role/event/capability-direction/capability authority grant, the
selected provider for a required capability, and an explicit quorum, and
builds a resource ownership graph from semantic resource names rather than
package names. A mediated resource is admissible only when the named mediator
is a selected contract that claims that same resource. Production integration
remains separately gated.

For the current vLLM-HUST-scoped study, research completion additionally
requires a formal model, cross-plugin/provider validation within vLLM-HUST, an
independent contract verifier, real process/service fault injection, and
matched overhead measurement. Cross-runtime validation is future external-
validity work, not a current paper exit gate.
