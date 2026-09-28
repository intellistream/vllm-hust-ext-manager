# Extension Manifest 0.3 — experimental

Manifest 0.3 is the first composition-oriented ECPA schema. It retains every
0.2 field and adds `resource_claims` so conflicts are rejected before a host
process starts.

```json
{
  "schema_version": "0.3-experimental",
  "resource_claims": [
    {
      "resource": "vllm.scheduler.preemption-policy",
      "scope": "vllm-process",
      "mode": "exclusive"
    },
    {
      "resource": "vllm.runtime.observer",
      "scope": "vllm-process",
      "mode": "shared"
    }
  ]
}
```

`resource` and `scope` are extensible lowercase identifiers. ECPA does not
maintain a closed list of MOD names. Providers and host contracts define the
meaning of a resource. `mode` is one of:

- `exclusive`: another claim for the same `(scope, resource)` is rejected,
  including an otherwise identical exclusive claim;
- `shared`: multiple shared claims may coexist, but they conflict with an
  exclusive claim for the same resource.

Typical exclusive resources include scheduler policies, KV connectors,
process carriers, network ports, and device partitions. Observer and telemetry
fan-out are typical shared resources. Resource claims do not grant lifecycle
ownership, device access, or permission to mutate an external service.

## Host capability discovery

Current vLLM-HUST hosts export a side-effect-free snapshot from
`vllm.plugins.extension_capabilities.get_extension_capabilities()`:

```json
{
  "schema_version": "vllm.extension-capabilities/v1",
  "host_api_version": "1.0",
  "protocols": {
    "vllm.preemption-policy": "1.0"
  }
}
```

ECPA consumes that registry instead of importing one implementation module per
MOD. An unknown schema, malformed version, invalid protocol entry, or failing
registry is rejected without falling back to optimistic compatibility.
Legacy module probes are used only when the registry module is absent.

## Migration from 0.2

0.2 manifests remain readable and receive an empty resource-claim set. They
must not add `resource_claims` without changing `schema_version` to
`0.3-experimental`. Migrating a MOD requires identifying every resource it
owns; absence of a claim is not evidence that a combination is safe.

This schema remains under compatibility freeze. It is not a stable v1 promise.
