# Experimental support matrix

No row below is a stable v1 promise. “Passed” means a pinned combination has
real evidence; it does not widen the result to every version in an experimental
manifest range.

| Host path | Pinned passing evidence | Remaining release gate |
| --- | --- | --- |
| vLLM-HUST `762f85b3` / Ascend `4e57439e` / BidKV 0.2 | Qwen3.8-27B TP4 graph pressure run completed four long requests; 187 policy calls, zero selector failures, output and next-start rollback passed. | Human upstream contract review, public commit reachability and broader version/model matrix |
| vLLM-HUST `762f85b3` / Ascend `4e57439e` / DiffSpec 0.3 | Qwen3.8-27B plus `VirVen/Qwen3.5-27B-EAGLE3-v2` passed TP4 FULL_DECODE_ONLY graph, four-rank, correctness, concurrency, cancellation and recovery. Acceptance 103/534 (19.29%); performance is degraded, so this is not an acceleration recommendation. | Human upstream Ascend review, public commit reachability and a performance-viable draft/profile |
| vLLM-HUST `762f85b3` / Ascend `4e57439e` / LatchMoE | Dense Qwen3.8-27B is Not Applicable. Qwen3-30B-A3B passed TP4 PIECEWISE graph functional expert mapping, device/host movement, address stability, concurrency, cancellation and recovery. | Human upstream Ascend review and performance recovery; measured throughput was degraded |
| Mooncake standalone | Official non-CUDA 0.3.12.post1 TransferEngine TCP and Store REST on `a100-dev` | Cross-version, transport and multi-node matrix |
| MooncakeStoreConnector / Ascend | vLLM 0.23 + vLLM Ascend + NPU wheel 0.3.11.post1, nine-key save/load and outage/recovery on NPU 4 | Matrix beyond the pinned `ascend` transport and `load_async=true` combination |
| Production Stack control plane | Commit `1b87c11a`, chart 0.1.12, Helm 4.2.4, Kubernetes 1.34.11: render, dry-run, lifecycle rollback, controller, Router and HPA evidence | Additional Kubernetes/Helm versions and permission-denial matrix |
| Production Stack real-model Router | arm64 source build routed an absent backend as HTTP 500, then existing GLM-4-32B as HTTP 200/`ROUTER_OK` without restarting vLLM; commit `7611dfa` was built, smoke-tested and published to GHCR by GitHub-hosted runners, then pulled and entrypoint-tested on arm64 server 91 | Additional Kubernetes/Helm versions and permission-denial matrix; amd64 and self-hosted infrastructure are not required |
| KV materialization native plugin contract | Manager `2dffcf7f`, vLLM-HUST `e521b42e`, and arrival-control `15172b7c`: Manager 117 tests, plugin 104 tests, host contract/pre-commit suites, Python 3.10/3.12 wheel CI, and exact clean-wheel discover/check/enable/plan/render/run/live-observer/stop/disable/forget/uninstall passed. `runtime_effective` disappeared after the supervised PID exited; no Manager-owned process remained. | Native-current NPU execution, injected observer/host failure degradation, and a broader host/version matrix. The 0.23 Ascend run remains compatibility-adapter evidence only. |

## Rollback ownership

- In-process vLLM policies and connectors roll back on the next vLLM process
  start after Manager disable; hot unload is not promised.
- Mooncake owns its service and KV-data lifecycle. Manager disable never stops
  the service or clears data, and enabled intent survives a temporary outage.
- Kubernetes operators own Helm history, apply, rollback, and uninstall.
  Manager only plans, renders, dry-run checks and projects evidence.

Alpha remains **NO-GO** until the remaining version, permission, native-NPU,
failure-degradation, upstream-review, and performance gates are complete. No
old 0.23 result qualifies the current native host, and enabled intent, an
environment variable, or successful import is not runtime-effectiveness
evidence.
