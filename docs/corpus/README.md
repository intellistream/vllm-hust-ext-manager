# Evidence-backed plugin corpus

Corpus and paper-case accountability belongs to `ShuhaoZhangTony` (张书豪).
Student input is optional collaboration and is not a maintenance dependency.

The registry contains 11 extensions with a concrete entry point or static
bundle registration and five adaptation candidates with hook/adapter/policy
code but no verified registration surface. Repository names are not evidence.
Independent services, benchmarks, papers, and ordinary optimization repos are
excluded unless code establishes an extension boundary.

Representative paper cases are BidKV, Mooncake Provider, Production Stack
Provider, KV Admission, and Request Lifecycle Profiler. Together they span a
typed policy bundle, external KV connector, infrastructure provider, private
scheduler patch, and multi-process observer. The remaining entries are artifact
generality evidence; they are not all claimed to conform to ECPA 0.1.

The [L2 contract-planner corpus](../../experiments/contract_planner/README.md)
maps these 11 registered entries to minimal modeled contract abstractions and
freezes a canonical resource/alias taxonomy. Its separately stored labels are
independently reviewed oracle judgments bound to the cases, taxonomy, and
source-corpus digests; they are not compiler outputs or precision/recall
results. The five adaptation candidates remain
excluded rather than being assigned fabricated manifests.

Corpus paths were verified against shallow read-only clones on 2026-09-17.
Unavailable or unverified fields use the literal `unknown`. Ownership is copied
only from the authoritative llm-optimizations ledger; an empty/unknown owner is
not inferred from commit authorship.

`source-snapshots.json` freezes the requested and GitHub-resolved repository
identity, numeric repository identity, default branch, exact commit/tree, and
every corpus evidence object's Git object ID. The snapshot is source identity
evidence only: it prevents a later branch move or repository redirect from
silently changing the modeled inputs, but it does not establish that a plugin
was invoked, affected a runtime decision, or remained effective. A corpus path
must resolve inside its repository's frozen tree; line suffixes are annotations
on a pinned blob rather than independent identities.

Audit limitation: the read-only shallow clones for
`Qixin-Gaoke/kvdelta-plugin` and `Qixin-Gaoke/adaptive-selector-plugin` did not
complete during this pass. They are therefore not admitted from repository
names or workspace labels; a later corpus revision may add them only after an
entry point, manifest, hook, or adapter implementation is inspected.
