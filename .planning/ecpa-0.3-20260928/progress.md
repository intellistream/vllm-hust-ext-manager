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
- Manager capability/resource work merged through PR #18 as
  `2694cb11400b324e3a926a5e76b54a6a8710d0a3`; live-only runtime evidence
  projection then merged through PR #19 as
  `2dffcf7fdea3cad36bc24c0c4174394bcc06d796`.
- Host capability registry PR #44 merged as
  `e7dbd66251812282e5834a8532be9f830c991e0e`; host-owned KV observer evidence
  PR #45 merged as `e521b42ed004692eea5ee2f1f8ff2f4d0245b7b1`.
- The real arrival-control plugin migrated to Manifest 0.3 in PR #27, pinned
  both exact merge commits, passed Python 3.10/3.12 CI, and merged as
  `15172b7c8630cf5fa8f33ae0d2c275df5ced7272`.
- Final validation: Manager 117 tests plus Ruff/format/strict mypy; host 43
  adjacent request/KV/preemption/capability tests plus full remote pre-commit;
  plugin 104 tests plus Ruff/format and sdist/wheel builds.
- Exact clean-wheel validation used host
  `0.29.1.post1.dev5+ge521b42.empty`. Discover/check/enable/plan/render passed;
  a supervised live KV observer receipt projected `runtime_effective`, SIGINT
  returned 130 and reaped the reporting process, the state then disappeared,
  and disable/forget/uninstall left empty Manager state.
- Compatibility freeze remains: no native-current NPU or performance
  qualification was claimed by this CPU/empty-device contract exercise.
