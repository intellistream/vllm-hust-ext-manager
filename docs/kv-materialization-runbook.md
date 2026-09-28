# KV materialization ECPA runbook

This runbook covers the pinned native-contract lane only:

- Extension Manager `a78dc3b66a908c588a7ee562edb6a250fa86c9ba` or later main;
- vLLM-HUST `6baa026f602fd221dc7db64362730305048a8b87`; and
- arrival-control plugin `6d31843458bf7c75322f60c5715ae598c6ed4cde`.

Install Manager and plugin wheels into an isolated environment, then run:

```bash
vllm-hust-ext extension list
vllm-hust-ext extension inspect \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension check \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension enable \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension plan \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension render \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext run --dry-run -- vllm serve MODEL
vllm-hust-ext run -- vllm serve MODEL
vllm-hust-ext extension status \
  org.vllm-hust.kv-materialization-arrival-control
```

Before describing the plugin as runtime-effective, require an observer receipt
emitted by the running host after an actual KV lookup or commit outcome. Saved
enable intent, `VLLM_PLUGINS`, entry-point resolution, import success, and a
controller decision are insufficient. Performance qualification is a separate
benchmark-harness result and is never inferred by `check`, `status`, or `plan`.

Stop the `vllm-hust-ext run` process and verify its API/worker descendants,
ports, and assigned device processes have exited. Do not stop external
operator-owned KV services. Roll back the in-process plugin on the next host
start:

```bash
vllm-hust-ext extension disable \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext run --dry-run -- vllm serve MODEL
vllm-hust-ext extension forget \
  org.vllm-hust.kv-materialization-arrival-control
python -m pip uninstall vllm-kv-materialization
```

The disabled dry-run must omit `kv_materialization` and the bundle ID. After
uninstall, `extension list` must not discover the bundle. The historical
vLLM 0.23 Ascend record validates only the version-scoped compatibility
adapter; it does not qualify this native host on NPU.
