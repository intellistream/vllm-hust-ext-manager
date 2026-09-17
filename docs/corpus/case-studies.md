# Representative ECPA case fixtures

These cases cover different extension authorities; they do not imply that every
repository already conforms to ECPA 0.1.

| Case | Failure exposed by ECPA | Evidence obligation | Resource/conflict | Rollback boundary | Fixture status |
|---|---|---|---|---|---|
| BidKV | package/policy selected but scheduler never invokes it, or another policy owns the slot | scheduler-process invocation bound to launch, policy digest and API version | exclusive preemption-policy slot | restore built-in policy on next process; never rewrite scheduler state externally | adaptation required |
| Mooncake Provider | connector configured while wrong wheel variant/service/worker path is ineffective | per required worker connector invocation plus provider-owned service/operation evidence | exclusive KV transfer configuration; mutually exclusive wheel variants | restore Manager-owned connector config; service lifecycle remains operator-owned | registered experimental case |
| Production Stack Provider | rendered config mistaken for applied/healthy rollout; HPA and controller co-own replicas | controller reconciliation, router traffic and autoscaler decision from their owning authorities | Deployment.spec.replicas ownership | restore rendered predecessor only; cluster apply/rollback remains operator-owned | registered experimental case |
| KV Admission | general plugin imports but private scheduler patch misses the pinned seam or composes with another patch | scheduler registration and decision event on exact runtime identity | scheduler/admission patch seam | remove intent/restart to unpatched baseline; no claim over queued-request recovery | adaptation required |
| Request Lifecycle Profiler | parent enables observer while one runtime process emits no events | all required process roles emit launch-bound lifecycle evidence | lifecycle observation/patch seam | disable observer configuration; runtime process supervision remains external | adaptation required |

Each row becomes at least one positive fixture, one inert-import fixture, one
identity/version mismatch, and one conflict or authority-boundary fixture in
M0--M2. Unknown process scopes must be frozen before a case may claim L3.
