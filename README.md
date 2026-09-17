# vLLM-HUST Extension Manager

## Research charter

The research line **Evidence-Carrying Plugin Architecture for LLM Inference
Systems / 大模型推理插件体系结构** studies whether plugin activation can remain
discoverable, composable, verifiable, and reversible under version skew,
multi-process loading, heterogeneous providers, composition conflicts, lifecycle
drift, and runtime effects that cannot be proved statically.

- [Research charter](docs/research-charter.md)
- [Falsifiable evaluation plan](docs/evaluation-plan.md)
- [Executable ECPA architecture](docs/design/ecpa-architecture.md)
- [Protocol state machine](docs/design/protocol-state-machine.md)
- [Threat model](docs/design/threat-model.md)
- [Failure semantics](docs/design/failure-semantics.md)
- [Frozen core decisions](docs/adr/0001-ecpa-frozen-core-decisions.md)
- [ECPA 0.1 candidate specification](spec/0.1/README.md)

`vllm-hust-ext` is a provider-neutral control point for discovering, validating,
configuring, enabling, planning, rendering, and checking vLLM-HUST extensions.
It is not a vLLM distribution, deployment system, or control plane.

The core owns static manifests, compatibility, persistent intent, lifecycle
state, conflict checks, and delegation. Host Providers retain runtime
authority:

- the vLLM Provider renders launch configuration for in-process extensions;
- the Mooncake Provider reuses official vLLM connectors and checks externally
  operated Mooncake services;
- the Production Stack Provider renders Helm/Kubernetes inputs and dry-run
  plans without applying them.

A plugin, KV connector, external KV system, and control-plane policy remain
different kinds. Installing or enabling an adapter never gives this manager
authority to start shared services, change drivers, delete KV data, or mutate a
production cluster.

Production Stack health evidence is not accepted as a bare boolean:
`cluster_reachable=true` requires `cluster_evidence`, and
`rollout_healthy=true` requires both a reachable cluster and
`rollout_evidence` plus structured `component_evidence` for controller
reconciliation, Router traffic, and an autoscaler decision. It also requires a
configured Kubernetes context, a vLLM OpenAI backend endpoint, and structured
`router_data_plane_evidence`: mock traffic cannot claim health, and the
evidence must show a real model plus backend 5xx and recovered 2xx results. A reported
`ownership_conflicts` entry projects `incompatible + degraded`; in particular,
an HPA and a `VLLMRouter` controller may not both own
`Deployment.spec.replicas`. Rendered operator plans keep install, upgrade,
rollback, and uninstall as explicit operator-owned `null` actions.

The official Production Stack controller at commit `1b87c11a` has now
reconciled a `VLLMRouter` into owned RBAC, Service, and Deployment resources in
an isolated Kubernetes 1.34.11 cluster. The official Router forwarded an
OpenAI-compatible completion request to an external test backend, and a real
metrics-server CPU signal scaled a separately owned Router Deployment from one
to three replicas. The separation is intentional: a negative test proved that
placing an HPA on the operator-owned Deployment creates a two-writer conflict.
On the arm64 host `180-ascend-bench`, a Router built from the same upstream
commit returned HTTP 500 for an absent backend, then HTTP 200 and `ROUTER_OK`
from the existing `zai-org/GLM-4-32B-0414` service after only the isolated
Router was reconfigured. The product does not require amd64. The
`vLLM-HUST/production-stack-hust` thin fork now passes a GitHub-hosted arm64
image build and Router entrypoint smoke test on `main`; publication and clean
host reproduction remain gated. No self-hosted Actions runner is required.

Mooncake runtime detection covers the mutually exclusive official CUDA,
CUDA 13, non-CUDA, NPU, MUSA, and EFA wheel variants. Installing more than one
variant is reported as an incompatible/degraded environment instead of picking
one arbitrarily. The experimental Mooncake profile currently declares
`>=0.3.11.post1,<0.4`. Its Store REST and vLLM KV configuration surfaces are
marked explicitly unversioned because upstream does not publish independent
protocol semantic versions; the Manager does not invent `1.0` contracts for
them.

The official 0.3.12.post1 non-CUDA wheel has completed both a two-process 1 MiB
TransferEngine TCP write and an isolated Store put/exist/get/remove round trip
on `a100-dev`. A separate Ascend NPU 4 run completed a real
MooncakeStoreConnector save/load hit: nine keys and 133,191,072 bytes each way,
with local prefix caching disabled. Master outage produced partial save
failures while inference remained available, and recovery restored save/load
without restarting vLLM. Alpha remains frozen for the remaining online
restart/rollback and support-matrix gates.

> **Compatibility freeze:** Manifest `0.2-experimental` and the former Bundle
> v1 prototype are not stable APIs. No alpha package will be published until
> the vLLM, KV-system, and control-plane end-to-end gates pass.

The pinned pass/fail combinations and lifecycle rollback owners are summarized
in [`docs/support-matrix.md`](docs/support-matrix.md). A passing point does not
implicitly validate the rest of an experimental version range.

```bash
pip install vllm-hust-ext
pip install bidkv

vllm-hust-ext extension list
vllm-hust-ext extension status org.vllm-hust.bidkv
vllm-hust-ext extension check org.vllm-hust.bidkv
```

BidKV 0.2 targets vLLM-HUST `0.28.1rc1.dev319` through the typed
`vllm.preemption-policy` API v1. The main BidKV distribution does not register
the removed private `vllm.victim_selector` entry point and does not monkey
patch the scheduler. Manager resolves the static bundle component into the
host-native `--preemption-policy` option and refuses incompatible official-vLLM
hosts. Source compatibility is currently unverified on the Sage Mate TP4 graph
target; the older vLLM-HUST 0.23 serving record is retained only as historical
evidence and is not inherited by this baseline.

```bash
vllm-hust-ext extension enable org.vllm-hust.bidkv
vllm-hust-ext run -- vllm serve MODEL
```

Only one enabled extension may claim vLLM's `--kv-transfer-config` in a single
process. The Manager rejects conflicting connector plans instead of silently
choosing one. Package removal remains separate from runtime intent: `forget`
only removes Manager-owned configuration and enabled intent and never stops a
shared service, clears KV data, or deletes Kubernetes resources.

Installing an extension distribution only makes it discoverable. Enabling is
explicit and stored in the user configuration. Discovery reads installed
distribution metadata and the static bundle manifest without importing its
implementation modules.

Lifecycle states are independent: `installed`, `configured`, and `enabled`
describe artifacts and saved launch intent. `runtime_effective` requires a
process-owned observer to prove that the selected implementation was invoked
by the running engine. This Manager does not infer runtime effectiveness from
static discovery or an environment variable, so ordinary status output omits
that state until an external runtime observer supplies evidence.

Descriptors whose only Python implementation is marked `import_only` or
`legacy_unregistered` remain inspectable but cannot be enabled. Inspection
reports `activation_ready=false` and the blocker instead of pretending that an
inert research package is runnable. Likewise, saved enabled intent survives an
external-service outage, but `run` refuses a new launch until every non-optional
`requires_services` dependency reports healthy.

Third-party host providers register factories only under the project-owned
entry-point group `vllm_hust_ext.providers`. Extension distributions register
static manifests under `vllm_hust.extension_bundles`. Neither namespace claims
an unofficial `vllm.*` entry-point group.

## Organization catalog feed

The Manager validates the organization-wide, immutable extension catalog used
by Workstation Mod Center. The feed is metadata only: listing an entry never
installs or enables it. `qualified` requires passed functional and recovery
evidence plus an immutable install target. An extension with correct behavior
but a negative matched performance result remains available and records
`not-recommended-for-tested-cell`; unverified function or recovery remains a
non-enableable `preview`.

```bash
vllm-hust-ext catalog validate extension-catalog-v1.json
vllm-hust-ext catalog list extension-catalog-v1.json --include-preview
vllm-hust-ext catalog inspect extension-catalog-v1.json org.vllm-hust.bidkv
```

Catalog availability is not runtime state. Workstation and API consumers must
continue to distinguish `installed`, `configured`, `enabled`, and
`runtime_effective`; only a process-owned observer may prove the last state.
