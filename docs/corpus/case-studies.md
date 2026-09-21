# Representative ECPA case fixtures

These cases are selected only from the 24 MODs in `workshop-mods.json`. They
cover different extension authorities; they do not imply that every repository
already conforms to ECPA 0.1.

| Case | Failure exposed by ECPA | Evidence obligation | Resource/conflict | Rollback boundary | Fixture status |
|---|---|---|---|---|---|
| BidKV | package/policy selected but scheduler never invokes it, or another policy owns the slot | scheduler-process invocation bound to launch, policy digest and API version | exclusive preemption-policy slot | restore built-in policy on next process; never rewrite scheduler state externally | adaptation required |
| DiffSpec / vSpec | bundle and general plugin load but no draft token is accepted | worker invocation plus accepted-token outcome bound to the exact model pair | speculative-decoding method and draft-model ownership | restore built-in decoding configuration on restart | bundle-discoverable; runtime fixture required |
| LatchMoE | offload setup runs on only part of the worker set or never changes placement | complete worker coverage plus host-owned placement/transfer evidence | expert placement and offload resources | disable the plan before exposure; reclaim only manager-owned state | bundle-discoverable; runtime fixture required |
| KVCompress | compressor loads but the active cache path remains uncompressed | cache-path invocation plus representation/effect evidence | KV representation and cache-path ownership | restore predecessor cache configuration; no in-place reinterpretation | bundle-discoverable; runtime fixture required |
| Request Lifecycle Profiler | parent enables observer while one runtime process emits no events | all required process roles emit launch-bound lifecycle evidence | lifecycle observation/patch seam | disable observer configuration; runtime process supervision remains external | adaptation required |
| BetterScale | direct worker class is selected with stale pins or a different worker path actually runs | exact host/pin identity plus worker-class and scheduling-path evidence | worker-class and scaling-policy ownership | relaunch the predecessor worker class | direct integration; adapter required |
| TraceLoom | capture starts but offline analysis is mistaken for execution-linked proof | capture provenance and host events separated from analyzer outputs | scheduler capture and artifact ownership | stop capture; preserve immutable evidence artifacts | direct integration; adapter required |
| DLA | wheel installs but ECPA discovers zero bundles due to a near-miss namespace | distribution metadata and selected-namespace discovery result | bundle namespace and victim-selector slot | reject before activation | concrete namespace-mismatch negative |

Each row becomes at least one positive fixture, one inert-import fixture, one
identity/version mismatch, and one conflict or authority-boundary fixture in
M0--M2. Unknown process scopes must be frozen before a case may claim L3.
