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
- an incomplete or differently versioned model snapshot.

The checked 112 candidate demonstrates why the current host cannot yet produce
the first formal-real cell. Eight Ascend 910B2 devices are visible, but the
candidate vLLM-Ascend `main` requires CANN 9.1.0 while the host exposes 9.0.0;
the plugin's checked upstream vLLM commit differs from the vLLM-HUST sync
commit; Docker's client is present but its server is inaccessible; no container
digest is frozen; and the Qwen3-0.6B cache contains only `config.json`, not the
tokenizer and weights. Neither runtime checkout is installed in the execution
environment. These are deployment blockers, not ECPA correctness failures.

A zero-blocker result has status `ready-for-registration-review`. It still has
`formal_real_result=false` and `registration_authority=false`: it cannot enter
`verified-adapters.json`, fill deployment-registration fields, or support a
paper result. The exact commands and independent sources still require review,
and the resulting stack must complete a real service launch and workload.

Recompute a candidate:

```bash
PYTHONPATH=src .venv/bin/python \
  experiments/false_effective/deployment_stack_preflight.py \
  --requirements experiments/false_effective/deployment-candidates/ascend-910b2-112.requirements.json \
  --observation experiments/false_effective/deployment-candidates/ascend-910b2-112.observation.json
```
