# ECPA open research questions

These questions are decision records for the paper, not claims or deferred
implementation tickets. A question leaves this file only when an artifact,
experiment, or explicit scope decision resolves it.

## Semantics

1. What is the weakest useful effect-obligation language that can express
   scheduler decisions, KV movement, and process coverage without embedding
   plugin-specific predicates in the core?
2. Which resource conflicts are soundly decidable from contracts, and which
   must remain runtime conflicts discovered by authority-owned evidence?
3. Is an exposure transaction scoped to one serving generation sufficient for
   disaggregated prefill/decode deployments, or is a multi-service transaction
   with explicit partial-order constraints required?

## Failure model

1. Which externally owned effects admit strong rollback, behavioral rollback,
   fail-closed isolation, or only bounded operator action?
2. What availability loss is acceptable when the traffic authority cannot be
   queried and the coordinator enters `SafetyUnknown`?
3. Does the single-manager lease/CAS model refine to a highly available
   coordinator without weakening stale-writer exclusion?

## Evidence and trust

1. Which vLLM-HUST execution points can emit host-owned effect evidence rather
   than merely invocation evidence?
2. How should evidence from a co-resident trusted host component be separated
   from self-report without claiming resistance to malicious same-user code?
3. Which identities survive worker replacement, process pools, Ray executors,
   and disaggregated serving without allowing stale coverage?

## Evaluation

1. Can the three arms implement genuinely different activation paths while
   keeping model, workload, topology, and injected fault identical?
2. Which existing plugins provide the smallest real case-study set that spans
   scheduler, KV, external-service, and observability authority domains?
3. Do the preregistered H1--H4 thresholds remain scientifically meaningful
   after the first complete pilot, or should the hypotheses be revised before
   (never after) the formal run?
4. What hardware/runtime matrix is feasible without treating unsupported CANN,
   vLLM, and vLLM-Ascend combinations as ECPA failures?

## Standardization boundary

1. Which fields belong in a portable ECPA contract and which must remain
   vLLM-HUST provider extensions?
2. What conformance level can be standardized without requiring a specific
   coordinator, evidence transport, or traffic controller implementation?
3. What evidence would justify calling ECPA a candidate interoperability
   specification rather than only a reference architecture?
