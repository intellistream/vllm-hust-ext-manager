# ECPA 0.3 progress

- Created Manager branch `codex/ecpa-capability-registry` from
  `origin/main` `9668255f0b36939155681916993462082282ea35`.
- Created host branch `codex/ecpa-host-capability-registry` from
  `origin/main` `6baa026f602fd221dc7db64362730305048a8b87`.
- Implemented host capability snapshot schema
  `vllm.extension-capabilities/v1`.
- Implemented Manager registry validation, fail-closed handling, and
  absent-registry legacy probes.
- Implemented manifest `0.3-experimental` resource claims and pre-launch
  exclusive/shared conflict checks.
- Manager validation so far: 113 tests, Ruff, Ruff format, strict mypy, and
  sdist/wheel build pass.
- Paired source-tree probe loaded all four protocols from the new host registry.
- Host registry is under review in vLLM-HUST PR #44 at commit `78c270e76`;
  its two new tests and 40 adjacent request/KV/preemption tests pass.
- Clean wheels built and installed together as Manager `0.2.0.dev0` and host
  `0.29.1.post1.dev86+g78c270e76.empty`; the installed Manager loaded all four
  registry protocols and rejected a two-owner scheduler claim before launch.
