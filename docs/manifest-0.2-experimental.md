# Extension Manifest 0.2 — experimental

This schema replaces the single-Python-Bundle assumption during architecture
validation. It is deliberately marked `0.2-experimental`; it is not a stable
compatibility contract.

Every manifest declares:

- `kind`: the domain role, such as `scheduler_policy`, `kv_service_adapter`, or
  `control_plane_extension`;
- `host`: Provider identity plus host and host-API compatibility ranges;
- `runtime`: Python, external service, OCI, Kubernetes, or composite runtime,
  with process scope and isolation;
- `lifecycle_owner`: the system or operator that is authorized to change the
  runtime lifecycle;
- `protocols`: explicit protocol compatibility ranges;
- `implementation`: one or more carriers, including registered Python entry
  points and unregistered/import-only Python modules,
  host-builtins, external services, OCI images, Helm values, Kubernetes
  manifests, CRDs, and controllers;
- `requires_services`: service identity, protocol range, configuration key for
  its endpoint, and whether it is optional; and
- optional typed components and activation declarations.

`activation.entry_points` contains exact `{group, name}` pairs. For installed
Python bundles, every declared pair must be present in the same distribution's
metadata. The Manager projects only `vllm.general_plugins` and
`vllm.platform_plugins` into vLLM's allowlist; other registered groups remain
inspectable but are not activated by this mechanism. Two enabled bundles may
not own the same projected name.

The old Bundle v1 shape remains readable only as an experimental migration
input. It must not be advertised as stable and receives no forward
compatibility promise.

Saved Manager configuration currently uses schema 2. Schema 1's `enabled`
array is read as an input migration and is rewritten as schema 2 on the next
state change. Unknown configuration and manifest schema versions fail closed;
there is no automatic downgrade migration.

An external-service carrier describes the official implementation surface; it
does not transfer lifecycle ownership to the Manager. For example, an external
service profile may record both its operator-owned console command and
its backing Python module, while `lifecycle_owner=external_operator` prevents
Core from turning that description into implicit start, stop, clear, or delete
operations.
