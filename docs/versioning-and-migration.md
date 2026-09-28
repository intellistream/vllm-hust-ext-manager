# Versioning and migration

The package remains `0.2.0.dev0`; compatibility is frozen and no alpha release
is authorized. Passing unit or host-contract tests does not by itself stabilize
the manifest, Provider, host-hook, or catalog contracts.

## Persisted configuration

- Schema 2 stores each extension's `enabled` intent separately from its
  provider configuration.
- Schema 1's `enabled` list is accepted as a one-way migration input. The next
  saved state writes schema 2.
- Unknown schemas and malformed fields are rejected. Operators should retain a
  copy of the previous configuration before migration; rollback is restoring
  that copy while no Manager command is writing it.

## Runtime rollback

For an in-process vLLM plugin, disable the extension and restart the
Manager-owned host process. Then verify the plugin observer no longer reports
invocations before forgetting state or uninstalling the distribution. A
successful import, an environment variable, or saved enabled intent is never
`runtime_effective` evidence.

External KV services and Kubernetes workloads keep their existing operator
lifecycle. Manager disable, forget, and package uninstall do not stop, roll
back, or delete those resources.

## Release gate

The freeze remains until the latest vLLM-HUST contract and at least one real
plugin pass clean-wheel activation, incompatible-version rejection,
process-owned runtime observation, failure degradation, stop, disable,
rollback, forget, and uninstall. Support-matrix entries must cite the exact
host/plugin commits and must distinguish historical compatibility adapters from
native-host NPU validation.
