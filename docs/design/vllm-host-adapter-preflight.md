# vLLM-HUST host-adapter preflight

Status: executable integration preflight; not a formal-real result.

`experiments/false_effective/vllm_host_adapter_preflight.py` checks one exact,
clean `vLLM-HUST/vllm-hust` commit and tree before loading producer code. It
binds the four producer source blobs, verifies native EngineCore and worker rank
bindings in the checked source, copies the exact Git object bytes into a private
read-only snapshot while rejecting worktree drift, and executes that tree's real
`PreemptionPolicyController` selection path. The producer writes resolution and
dispatch events through ECPA's deployment-owned journal sink. ECPA then reads
the exact journal bytes and translates the dispatch into a Plan-bound
invocation statement.

The check therefore detects wire drift, missing native rank binding, a loader
or scheduler path that does not emit, non-host-assigned identity, Plan/launch
drift, and a translator that fails to bind the exact producer bytes. It does
not start an inference engine, serve a model, establish complete worker
coverage, or exercise a real fault. Its output schema fixes
`formal_real_result` to `false`.

Run it only against an explicitly reviewed checkout:

```bash
PYTHONPATH=src .venv/bin/python \
  experiments/false_effective/vllm_host_adapter_preflight.py \
  --vllm-checkout /absolute/path/to/vllm-hust \
  --expected-commit COMMIT \
  --expected-tree TREE
```

Producer admission remains separate. The exact producer must be merged and
must carry the repository-required human line review before its commands can
enter `verified-adapters.json`. A passing preflight must never be used to fill a
formal result row.
