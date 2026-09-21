# Evidence-backed extension populations

Corpus and paper-case accountability belongs to `ShuhaoZhangTony` (张书豪).
Student input is optional collaboration and is not a maintenance dependency.

## Authoritative workshop population

`workshop-mods.json` is the external-validity entry point. It freezes the exact
24 MODs rendered by the vLLM-HUST plugin page from
`data/plugin-workshop-metadata.json` at website commit
`8336f5b67c69910aa7d5dfc3b5b94407e99928bd`. Repository names from our own
research portfolio are not substituted for, appended to, or sampled in place
of that population.

`plugin-workshop-metadata.snapshot.json` preserves the page input bytes. The
paper evidence generator requires the fixed website repository identity,
commit, metadata blob, byte digest, canonical repository/head-row digest, and
complete audit-row digest; it also verifies every MOD ID-to-repository mapping
against the snapshot. A syntactically valid substitute repository or a
coordinated count edit therefore fails closed.

The 2026-09-21 audit resolved all 24 repository identities and default-branch
heads. Sixteen wheels register the ECPA namespace and are discoverable without
importing implementation modules. DLA publishes the same kind of static bundle
under `vllm.extension_bundles`, exposing a namespace mismatch. Three MODs expose
only `vllm.general_plugins`, two use direct/non-entry integration, and two are
source-only migration scaffolds. All 21 generally buildable package projects
built in an isolated environment; BetterScale correctly requires its separately
qualified native release staging payload. Repository-local CPU/source tests
passed for 17 MODs, five were blocked at Ascend host dependencies, and the two
source scaffolds contain no automated tests.

Those observations are source/package/CPU evidence only. They do not prove NPU
execution, full worker coverage, runtime effect, exposure atomicity, or rollback.
An environment-blocked cell is not recorded as either a pass or a code defect.

## Modeled planner seed

`plugins.json` is an older 11-extension planner seed with a concrete entry point or static
bundle registration and five adaptation candidates with hook/adapter/policy
code but no verified registration surface. It is retained to keep the reviewed
31-case static planner oracle reproducible; it is not the authoritative
vLLM-HUST workshop population and must not be cited as 24-MOD coverage.
Repository names are not evidence.
Independent services, benchmarks, papers, and ordinary optimization repos are
excluded unless code establishes an extension boundary.

Representative paper cases are BidKV, Mooncake Provider, Production Stack
Provider, KV Admission, and Request Lifecycle Profiler. Together they span a
typed policy bundle, external KV connector, infrastructure provider, private
scheduler patch, and multi-process observer. The remaining entries are artifact
generality evidence; they are not all claimed to conform to ECPA 0.1.

The [L2 contract-planner seed](../../experiments/contract_planner/README.md)
maps these 11 registered entries to minimal modeled contract abstractions and
freezes a canonical resource/alias taxonomy. Its separately stored labels are
independently reviewed oracle judgments bound to the cases, taxonomy, and
source-corpus and source-snapshot digests; they are not compiler outputs or
precision/recall results. The five adaptation candidates remain
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
