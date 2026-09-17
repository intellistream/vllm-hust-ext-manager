# Failure semantics and invariants

Invariants: no evidence amplification; host-owned process set/epoch;
all-required-process coverage; freshness/non-replay; canonicalized conflict
freedom; atomic effectiveness-claim commit or fail closed; bounded authority;
deterministic but conditional rollback; one committed generation; and evidence
non-transferability across launch, process, artifact, host, or epoch.

Errors are stable contract values, including UNKNOWN/AMBIGUOUS_RESOURCE,
RESOURCE_CONFLICT, INCOMPATIBLE_HOST, MISSING_PROCESS_EVIDENCE, STALE_EVIDENCE,
REPLAYED_NONCE, CAS_MISMATCH, EXTERNAL_LEASE_INVALID, and
AUTHORITY_VIOLATION. Policy chooses timeout, fallback, risk threshold, and
reconciliation budget. The contract never converts unknown into success.
