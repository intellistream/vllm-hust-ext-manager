# ECPA architecture

ECPA is a plugin management system centered on an evidence-carrying
interoperability contract. Extension Manager is the reference implementation.

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

The executable model in `src/vllm_hust_ext/ecpa_model.py` is pure and performs
no external side effects. Production integration is intentionally deferred.

For the current vLLM-HUST-scoped study, research completion additionally
requires a formal model, cross-plugin/provider validation within vLLM-HUST, an
independent contract verifier, real process/service fault injection, and
matched overhead measurement. Cross-runtime validation is future external-
validity work, not a current paper exit gate.
