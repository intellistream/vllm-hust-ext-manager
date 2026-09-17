# ADR 0001: Frozen ECPA core decisions

Status: accepted for executable-model validation. Each item records decision,
consequence, and rejected alternative.

1. **Intent authority.** Operator signs intent only; consequence: no runtime
   success from control-plane state. Reject operator-issued effective flags.
2. **Planner authority.** Manager creates plans but no runtime facts. Reject
   planner self-attestation.
3. **Host authority.** Host owns process set, epoch, load/invocation and traffic
   gate. Reject provider-invented worker inventory.
4. **Provider bounds.** Provider maps/observes only. Reject authority expansion
   through a manifest.
5. **Evidence custody.** Append-only store is not an issuer. Reject log presence
   as proof of truth.
6. **Content identity.** Plugin and Plan IDs hash canonical content. Reject
   mutable names as identity.
7. **Canonical namespaces.** Capability/resource URIs canonicalize before
   conflict checks. Reject string aliases and last-writer-wins.
8. **Launch/process identity.** LaunchID plus host/role/ordinal/start/epoch binds
   evidence. Reject PID-only or transferable evidence.
9. **Lifecycle.** Publish Effective only after CommitReady; partial launch stays
   internal. Reject PartiallyEffective.
10. **Obligations.** All required processes satisfy typed events. Reject parent
    import as worker proof.
11. **Fresh attestations.** Epoch, nonce, validity and artifact bind evidence.
    Reject replay after recovery.
12. **WAL/receipts.** Record before/after effects, at-least-once delivery and
    fenced logical-once. Reject physical exactly-once claims.
13. **CAS commit.** Effectiveness claim CASes predecessor generation. Reject
    split-brain commits and distributed atomicity claims.
14. **Conditional rollback.** Preserve predecessor and converge within owned
    authority; reject unconditional recovery claims.
15. **Layer boundary.** Contract defines interoperability semantics; policy
    chooses risk/fallback; provider/host performs runtime operations. Reject a
    monolithic implementation-defined standard.
