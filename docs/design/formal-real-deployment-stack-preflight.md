# Formal-real deployment stack preflight

Status: deployment-candidate audit; not registration authority and not a
formal-real result.

The first real cell must bind a mutually supported vLLM-HUST, accelerator
plugin, CANN, container image, hardware topology, and complete model snapshot.
The deployment registration cannot infer these values from a developer host or
accept a stack merely because each component exists independently.

`experiments/false_effective/deployment_stack_preflight.py` compares an
immutable candidate with a point-in-time observation. It fails closed on:

- missing or different vLLM-HUST and accelerator-plugin identities;
- an accelerator plugin verified against a different upstream vLLM commit;
- a CANN version outside the candidate's exact requirement;
- an incompatible accelerator family or insufficient devices;
- an inaccessible container server, unpinned image, or different image;
- container binaries built from different source commits than the mounted
  runtime/plugin trees, or a different effective runtime mode;
- an incomplete or differently versioned model snapshot.

The refreshed 112 candidate binds exact read-only source trees, CANN 9.1, an
accessible Docker server, eight visible Ascend 910B2 devices, a content-addressed
local image, and every required Qwen2.5-0.5B file and digest. A one-device
eager/native smoke completed model load, KV-cache initialization, warmup, one
request, and shutdown. The checked smoke is separately typed as non-formal and
non-authoritative. It mounted newer source trees over an image built from older
runtime/plugin commits and set `VLLM_BATCH_INVARIANT=1`, disabling custom ops.
The plugin's checked upstream vLLM commit also still differs from the
vLLM-HUST sync commit. The preflight therefore remains blocked on binary/source
identity, runtime mode, and verified runtime compatibility. These are
deployment blockers, not ECPA correctness failures.

A zero-blocker result has status `ready-for-registration-review`. It still has
`formal_real_result=false` and `registration_authority=false`: it cannot enter
`verified-adapters.json`, fill deployment-registration fields, or support a
paper result. The exact commands and independent sources still require review,
and the resulting stack must complete a real service launch and workload.

`deployment-candidates/ascend-910b2-112.smoke.json` records the successful
pre-admission smoke without promoting its SUT-owned diagnostic stream to
observer truth. Its schema fixes `formal_real_result=false`,
`registration_authority=false`, the source-override mode, batch-invariant mode,
and disabled custom operators. It cannot populate the adapter registry or a
paper aggregate.

Recompute a candidate:

```bash
PYTHONPATH=src .venv/bin/python \
  experiments/false_effective/deployment_stack_preflight.py \
  --requirements experiments/false_effective/deployment-candidates/ascend-910b2-112.requirements.json \
  --observation experiments/false_effective/deployment-candidates/ascend-910b2-112.observation.json
```
