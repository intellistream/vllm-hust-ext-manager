# L2 contract-planner corpus

This directory freezes the modeled inputs and candidate oracle for the ECPA
L2 conflict study before the evaluator is implemented. It does **not** contain
a planner run, precision/recall result, runtime result, or formal-real result.

`cases.json` maps all 11 registered entries in `docs/corpus/plugins.json` to
minimal, evidence-backed contract abstractions. That mapping is evidence of an
extension surface only; it is not a claim that the source repositories already
ship ECPA 0.1 manifests or satisfy L2. Synthetic controls are explicitly marked
and exist only to exercise taxonomy boundaries that cannot be established from
the small registered corpus.

Capability version `1.0` in an evidence-backed abstraction is a frozen model
token for this study, not a claim about a source repository's released API or
runtime compatibility. The source corpus's unknown version fields remain
unknown.

`contract-taxonomy.json` freezes canonical resources and aliases. Aliases are
part of the oracle boundary: two plugins cannot escape a physical-resource
conflict merely by spelling the resource differently. Unknown resources fail
closed until the taxonomy is deliberately extended. Its ordered
`decision_precedence` also freezes which error is reported when a composition
violates more than one rule.

`oracle.json` is manually labeled from that taxonomy and the specification's
provider-cardinality and mediation rules. An independent Agent reconstructed
all 31 decisions and expected errors for the recorded content commit and three
raw-byte SHA-256 digests, then returned `MERGE`. The future evaluator must
consume this reviewed artifact; it must not generate or rewrite expected
labels.

The source corpus points to repository paths rather than immutable external
repository trees, so the modeled resource mapping remains a study assumption,
not independently reproduced source behavior. In particular, the real
lifecycle-profiler abstraction is conservatively exclusive because its
multi-subscriber safety is unverified; shared-read compatibility is tested only
with synthetic controls.

The five adaptation candidates remain excluded because the evidence corpus has
no verified registration surface for them. This study does not fabricate
conforming manifests from repository names or policy code.

The next change, after independent review of these frozen inputs, may add the
taxonomy-aware evaluator, preserve every raw decision, and compute per-class
and aggregate confusion matrices. Only that later measured artifact may support
precision or recall claims.
