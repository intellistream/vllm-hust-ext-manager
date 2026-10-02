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
| Request lifecycle / CLM contract | vLLM-HUST `7620b23a` and CLM `efaae105`: host focused tests and pre-commit passed; CLM 23 tests, three-Python CI, wheel, isolated ECPA lifecycle, default-off installation, and explicit EventBus registration passed. | A live host-process observer receipt, stop/rollback evidence for a real serving process, native-current NPU execution, controller failure qualification, and performance evidence. |

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
| Discovered and activation-ready | `vllm-ascend-split-batch-hust` (`fia-demask`, `split-batch-full-graph`, `zerocost-wiring`), `vllm-ascend-hust-LatchMoE`, `vllm-ascend-hust-diffspec`, `vllm-ascend-kvcompress-hust`, `vllm-ascend-quantized-kv-cache-hust`, `vllm-hust-bidkv`, `vllm-hust-vSpec`, `vllm-hust-kv-materialization-arrival-control`, `vllm-hust-legacy017-perf`, `vllm-hust-opset`, `vllm-hust-pipeline-microbatch`, and `vllm-hust-clm-lifecycle` after its ECPA 0.3 migration | Fourteen bundles can express activation intent. This does not mean the current host accepts them. |
| Discovered but intentionally inspect-only | `vllm-ascend-adaptive-quantized-kv-hust`, `vllm-ascend-simllm-hust`, `vllm-ascend-split-batch-hust` (`rope-fix`), `vllm-hust-activation-sparsity`, `vllm-ascend-layered-prefill-hust`, `vllm-ascend-mapped-kv-offload-hust`, `vllm-ascend-pyramidkv-hust`, `vllm-ascend-quant-hust` runtime extension, `vllm-hust-stateharbor`, `vllm-hust-unified-comm`, `vllm-hust-dla`, `vllm-hust-kv-transfer-observability`, `vllm-hust-qos-scheduler`, and `vllm-hust-scheduler-policy-lab` | Fourteen bundles declare `import_only` or `legacy_unregistered` implementations and correctly fail closed. |
| Invalid distribution split | `pegaflow-hust` provider bundle | The provider wheel declares `vllm.general_plugins:pegaflow`, but that entry point is owned by the separate `pegaflow-llm-npu` wheel. Static discovery rejects the claim instead of trusting a different distribution. Inventory reports this Bundle as invalid without hiding healthy Bundles; selected operations remain strict. |
| Repaired during the audit | `vllm-hust-clm-lifecycle` PR #1 / main `e6c01ffd`, followed by PR #2 / main `efaae105` | Migrated the legacy descriptor to ECPA 0.3, then aligned it with host `vllm.request-lifecycle-events` 1.0 and made installation explicitly inert. Python 3.10/3.12/3.14 CI and isolated ECPA lifecycle checks passed. Live runtime evidence remains unproven. |

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

The MOD-side follow-ups are tracked in `ascend-distributed-metadata#1`,
`quality-bounded-inference-plugin#3`, `vllm-hust-request-lifecycle-profiler#29`,
and organization issue `.github#42` for Tricard (whose repository issue tracker
is disabled). Existing pluginization issues track `vllm-hust-knorm#1`,
`vllm-hust-kv-tiering#1`, `vllm-hust-prefix-router#1`, and
`vllm-hust-slicegpt#1`; the ECPA acceptance evidence was added to each.

This audit is packaging and contract evidence only. It is not native NPU,
functional-correctness, runtime-effectiveness, or performance evidence.

### Re-audit update (2026-09-30)

| Candidate | New evidence | Remaining owner gate |
| --- | --- | --- |
| KNorm PR #4 (`b9429de`) | Clean wheel and ECPA list/inspect/check/plan/render passed; 78 tests passed and one skipped. | Migrate manifest 0.2 to 0.3, declare the installed general-plugin activation entry point and resource conflicts, then resolve worker synchronization and native qualification. |
| KV Tiering PR #3 (`7ba646a`) | Wheel, list, and inspect passed. | Provider import executes a hard `vllm` import; clean tests also lack declared `torch`, `numpy`, and `vllm`. Add import isolation/dependencies/CI and a 0.3 protocol/resource contract. |
| Prefix Router PR #2 (`2594ae6`) | Clean wheel and ECPA list/inspect/check/plan/render passed; 49 tests passed. | It truthfully remains an external, user-owned, `import_only` service. Add a 0.3 service/resource contract without transferring operator lifecycle to ECPA. |
| Pegaflow main (`64ef9d0`) | Provider wheel builds, but its activation entry point targets `pegaflow.vllm_plugin`, which is absent from that wheel. | Package the implementation in the declaring distribution or move Bundle ownership; metadata duplication alone is invalid. |

ADM, Quality Bounded Inference, Tricard CLM, Request Lifecycle Profiler, and
SliceGPT still have no packaged ECPA Bundle. Their existing owner issues were
updated with the exact audited main commits. No native NPU or performance run
was performed in this re-audit.

### Full organization follow-up (2026-10-02)

The audit was expanded from the previously tracked MOD set to every one of the
71 organization repositories. All 26 ECPA distributions were installed
together: 29 registrations were found, 28 were valid, and the known Pegaflow
distribution split remained the sole invalid registration. All 28 valid
Bundles passed disabled inspect/check/plan/render against Manager `ff144b46`.
This remains packaging and contract evidence only.

| Candidate | Classification and follow-up |
| --- | --- |
| BetterScale main `852c1066` | Explicit `--worker-cls` runtime MOD, but no ECPA Bundle; tracked by BetterScale #9. |
| FreshKV main `738d24ad` | Engine-independent policy/runtime library with no vLLM carrier; FreshKV #1 requires either a real host carrier or an explicit library-only classification. |
| `llm-serving-cost-pricing-model` main `4d4fafe7` | Installed general plugin but no ECPA Bundle; tracked in organization issue `.github#43` because repository issues are disabled. |
| PyramidKV PR #4 `a40b46c2` | Wheel and ECPA commands pass, but its custom method entry point depends on the separately enabled KVCompress general plugin. Manager #25 adds fail-closed Bundle dependency semantics; the MOD still needs a 0.3 dependency/resource manifest. |
| DLA PR #3 `da1dab54` | Wheel and ECPA commands plus package CI pass; 0.3 exclusive preemption resource ownership and native evidence remain owner gates. |
| vSpec PR #2 `bf9ffac3` | Dirty against main and package CI fails `ruff format --check` on 12 files; not qualified. |

LMCache-Ascend and hardware platform plugins remain host prerequisites or
external lifecycle systems. TraceLoom remains an experiment/analysis harness,
and research-only repositories are not relabeled as ECPA-managed MODs. ECPA
does not acquire ownership of their services, devices, KV data, clusters, or
performance claims.

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
