# ECPA cross-implementation open questions

Only decisions that affect independent implementations belong here.

| Question | Recommendation | Alternatives | Decide by / required evidence | Cost of a wrong decision |
|---|---|---|---|---|
| Attestation envelope | Canonical signed envelope binding plan, launch, artifact, process epoch, event, freshness and nonce | Provider-specific envelopes; transport-auth only | Before second implementation; cross-language vectors and replay tests | Non-interoperable or replayable evidence |
| Namespace governance | Reverse-DNS owner plus versioned registry and collision process | Central numeric registry; repository-scoped names | Before public RFC; two-org collision exercise | Squatting, ambiguous ownership, migration cost |
| Trust root | Deployment-selected trust bundle, outside manifests | Host-only identity; public PKI | Before authenticated adapter; threat-model experiment | Forged effectiveness or unusable private deployments |
| Continuous effectiveness | Lease/heartbeat after initial commit for capabilities that can decay | Activation-only evidence; request sampling | Before claiming continuous state; outage/freshness experiments | Stale Effective claims or request-path overhead |
| Elastic target set | Epoch-scoped host inventory snapshot with explicit quorum policy | Fixed ordinal set; eventual membership | Before elastic worker support; scale/churn traces | Vacuous coverage or permanent inability to commit |
| Traffic-gate authority | Separate gate capability with predecessor retention and receipt | Manager-owned routing; provider-owned gate | Before real serving integration; crash matrix | Split routing, premature exposure, authority escalation |
| Rollback equivalence | Explicit equivalence predicate over manager-owned inputs and traffic | Byte equality; best-effort operator declaration | Before L4 claim; injected irreversible changes | False rollback success or needless failure |
| Second host/provider | Select one host with a different process model and one external provider | More vLLM-only cases; Kubernetes first | After MVP fault gate; adaptation effort and decision parity | Architecture overfits the first adapter |
| Standard governance | Two-organization review with published compatibility policy | Repository-owner decisions; foundation immediately | After independent implementation and RFC feedback | Premature standard claim or stalled evolution |

The 112 review may add or retire entries, but a question is not closed without
the listed evidence or an explicit rejection record.
