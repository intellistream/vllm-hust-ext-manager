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

## Modeled static evaluation

`evaluate.py` converts each minimal descriptor into a complete in-memory ECPA
L2 contract object with no invented lifecycle capability or L3 evidence
obligation, invokes the reference compiler with the frozen taxonomy, and writes
canonical per-case decisions plus aggregate and per-dimension confusion
matrices. The checked-in `results/` artifacts bind the three reviewed inputs,
the exact reviewed oracle bytes and review commits, the evaluator source, the
compiler source, the exact repository/tree/evidence-object source snapshot,
and the raw-decision digest. The evaluator contains the
reviewed oracle digest as a code-reviewed constant, so editing status/verdict
or regenerating labels from compiler output fails before scoring.

Run:

```console
python experiments/contract_planner/evaluate.py
```

For the reviewed 31-case corpus, all 21 admits and 10 rejects match, including
all reject error codes. Reject precision, reject recall, and admit recall are
1.0. A reject-all baseline has precision 10/31 and admit recall 0, so blanket
rejection does not pass. Per-dimension metrics with zero positive or negative
support are reported as `null`, not 0 or 1.

These numbers establish conformance to a small, modeled static corpus; they do
not establish runtime effectiveness, real-plugin conflict prevalence, or
external validity. Every conflicting composition includes a synthetic boundary
control, and the evidence-backed descriptors remain study abstractions rather
than source-shipped ECPA manifests. Real manifest migration and runtime cells
remain separate work.

The source snapshot binds repository identity, redirect resolution, commits,
trees, and evidence-object Git IDs. It does not turn a modeled descriptor into
a source-shipped ECPA manifest and does not prove runtime effectiveness.
