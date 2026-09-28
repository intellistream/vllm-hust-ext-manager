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

## Organization-wide MOD contract audit (2026-09-28)

The authenticated organization inventory contained 71 repositories. Forty-five
runtime, plugin, research-carrier, or provider candidates were shallow-cloned
and inspected; documentation, websites, benchmarks, host forks, and unrelated
applications were not mislabeled as MODs.

Twenty-six distributions declared an ECPA Bundle entry point and all 26 built
clean wheels. Tested one distribution at a time against Manager `d6a21358`,
they produced these results:

| Result | Repositories / bundles | Interpretation |
| --- | --- | --- |
| Discovered and activation-ready | `vllm-ascend-split-batch-hust` (`fia-demask`, `split-batch-full-graph`, `zerocost-wiring`), `vllm-ascend-hust-LatchMoE`, `vllm-ascend-hust-diffspec`, `vllm-ascend-kvcompress-hust`, `vllm-ascend-quantized-kv-cache-hust`, `vllm-hust-bidkv`, `vllm-hust-vSpec`, `vllm-hust-kv-materialization-arrival-control`, `vllm-hust-legacy017-perf`, `vllm-hust-opset`, and `vllm-hust-pipeline-microbatch` | Thirteen bundles can express activation intent. This does not mean the current host accepts them. |
| Discovered but intentionally inspect-only | `vllm-ascend-adaptive-quantized-kv-hust`, `vllm-ascend-simllm-hust`, `vllm-ascend-split-batch-hust` (`rope-fix`), `vllm-hust-activation-sparsity`, `vllm-ascend-layered-prefill-hust`, `vllm-ascend-mapped-kv-offload-hust`, `vllm-ascend-pyramidkv-hust`, `vllm-ascend-quant-hust` runtime extension, `vllm-hust-stateharbor`, `vllm-hust-unified-comm`, `vllm-hust-dla`, `vllm-hust-kv-transfer-observability`, `vllm-hust-qos-scheduler`, and `vllm-hust-scheduler-policy-lab` | Fourteen bundles declare `import_only` or `legacy_unregistered` implementations and correctly fail closed. |
| Invalid distribution split | `pegaflow-hust` provider bundle | The provider wheel declares `vllm.general_plugins:pegaflow`, but that entry point is owned by the separate `pegaflow-llm-npu` wheel. Static discovery rejects the claim instead of trusting a different distribution. |
| Invalid discovery group | `vllm-hust-clm-lifecycle` | The released source uses `vllm.extension_bundles` instead of `vllm_hust.extension_bundles`; it is invisible until its ECPA 0.3 migration lands. |

Against host main `e521b42e` and the installed vLLM/vLLM-Ascend 0.23
distributions, the host capability registry exported four protocols. Only
`org.vllm-hust.ascend-int8-kv-cache` reached `compatible,configured` while
remaining activation-ready. Mapped KV offload and StateHarbor were compatible
but inspect-only/degraded. Every other bundle was rejected or degraded because
of an explicit host-version mismatch, an unavailable protocol, an unverified
host version, or its declared implementation status. Disabled `plan` and
`render` succeeded for every discoverable bundle.

Four additional general-plugin wheels built successfully but were not
discoverable because they have no ECPA manifest: `ascend-distributed-metadata`,
`quality-bounded-inference-plugin`, `Tricard/plugins/vllm-clm`, and
`vllm-hust-request-lifecycle-profiler`. `vllm-hust-knorm`,
`vllm-hust-kv-tiering`, `vllm-hust-prefix-router`, and `vllm-hust-slicegpt`
also lack a packaged ECPA Bundle on their audited main branches. Hardware
platform packages such as `vllm-ascend-hust` remain host prerequisites;
retaining the built-in `ascend` plugin is not evidence that ECPA owns the
platform lifecycle.

This audit is packaging and contract evidence only. It is not native NPU,
functional-correctness, runtime-effectiveness, or performance evidence.

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
