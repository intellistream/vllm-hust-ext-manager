# ECPA 0.3 findings

- The public ecosystem catalog currently contains 47 components; it is not a
  list of 47 deployable MODs. At least 21 entries besides the Manager use a
  Python distribution or extension/bridge-shaped delivery path.
- The 0.2 vLLM Provider imports individual implementation modules to discover
  four protocol versions. That approach grows linearly with host contracts and
  couples Manager discovery to vLLM internals.
- Existing generated-config conflict checks catch unequal rendered keys but do
  not express exclusive ownership when two MODs render equal values or use
  different keys for the same scheduler, connector, process, port, or device.
- Website catalog maturity and Manager activation qualification remain separate
  evidence domains; this iteration does not convert catalog presence into
  activation eligibility.
- Loader discovery, import, resolution, and callable registration cannot prove
  runtime effectiveness. The accepted evidence is a bound host KV observer
  receipt from an exact PID/start identity that is still alive; retained audit
  events stop projecting `runtime_effective` after process exit.
- The final clean-wheel path required no NPU. It proves packaging, host
  contracts, observer delivery, supervision, and rollback behavior only.
