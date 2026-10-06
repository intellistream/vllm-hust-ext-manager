The Mooncake provider can render the host's `AscendStoreConnector` through
`configuration.ascend-store.example.json`. This path requires `vllm-ascend`,
the Ascend transport, and an explicit `backend: mooncake`. It preserves the
caller's serving configuration and does not start the external master.

Set the external Mooncake configuration and health endpoint for your deployment
before enabling the bundle. A reachable health endpoint only checks the service;
it does not prove successful cache restores or hybrid-model correctness. Record
real transfer and correctness evidence separately before claiming performance.
