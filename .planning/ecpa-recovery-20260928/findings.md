# ECPA recovery findings

## Initial audit

- The requested `/root/extension-manager` checkout did not exist on this container. Therefore the historical local `main=701aa95` claim was not current local state.
- Created a fresh authoritative clone at `/root/extension-manager` and isolated worktree at `/root/extension-manager-worktrees/ecpa-recovery`.
- Work branch: `codex/ecpa-general-plugin-contract-recovery`.
- Extension Manager `origin/main`: `53eb555b35a29476fbf9057c4070a27c670a1f7b`.
- Extension Manager PR #5 head: `782e7a03a30eab6b04bbdbb2c3fc86fdf6e32ee6`.
- vLLM-HUST `origin/main`: `55d6c601da6ae2ed61ce9b7b3d5e3607a6402023`.
- vLLM-HUST PR #20 head: `19d4db1b70461b6d9c87100f187ae00084ab8c67` (different from older background state; audit required).
- KV plugin `origin/main`: `be6fc7819269e8897e610f44040a7c83236ee174`.
- KV plugin PR #23 head: `ea59bd3d1218d871fe7406dc1c480d04d13e9d63`.
- Extension Manager PR #5 changes only README, CLI activation environment, vLLM protocol detection, and focused tests. It predates merged lifecycle/provider work and must not be merged blind.

## Initial pending evidence

- PR #5 is open, mergeable, and had no CI. Its five-file diff did not implement
  process supervision, duplicate-install handling, StateAxis, or exclusive
  carriers, but its CLI launch path overlaps the evolved lifecycle and required
  a fresh integration rather than direct merge.
- PR #20 is open and conflicting with current vLLM-HUST main; its existing
  pre-commit check passed on the old head, while format checks were skipped.
- PR #23 is open and conflicting with current plugin main; its old wheel jobs
  passed, but current main now includes merged PR #25 and must be reconciled.
- Manager isolated baseline after editable installation: 94 tests passed. Main
  initially failed Ruff on newly merged StateAxis formatting; mechanical fixes
  were required before adding CI. Strict mypy then exposed existing annotations
  in supervision/discovery/providers; these were corrected without behavior
  changes.
- Modernized Manager result: 101 tests pass, Ruff passes, strict mypy passes,
  sdist/wheel build passes, clean-wheel CLI install and uninstall pass.
- Clean-wheel audit exposed stale `vllm_hust_ext.__version__=0.1.0` while package
  metadata is `0.2.0.dev0`; corrected to keep version reporting truthful.
- No NPU tests were run; Manager contract work did not require device access.
- Host and plugin dependency-chain validation was pending at initial audit.

## Final convergence evidence

- Extension Manager PR #15 replaced old PR #5; PR #5 was closed with a link to
  the replacement. PR #15 passed Python 3.10/3.12 CI, Ruff, strict mypy, wheel,
  101 tests, and clean-wheel CLI validation. It merged as
  `a78dc3b66a908c588a7ee562edb6a250fa86c9ba`. Later Manager main
  `9c487b02d088f2cbe95cd8f0ce1024c93d9dcc64` also includes PR #16's declared
  activation-environment conflict checks.
- vLLM-HUST PR #20 preserved main's request-scoped KV hints, Qwen3.5 path,
  prefix replay, and scheduler behavior while adding typed request-processing
  and KV-materialization API v1.0 contracts. Focused results: 6 request-hook
  tests and 10 KV-runtime tests passed; Ruff, format, SPDX, Python 3.12 mypy,
  Buildkite tethering, and remote pre-commit passed. PR #20 merged as
  `6baa026f602fd221dc7db64362730305048a8b87`.
- Arrival-control PR #23 preserved merged PR #25's correlation/session behavior,
  replaced its temporary current-layout monkey patch with the native v1.0 host
  contracts, updated the Manager pin to `a78dc3b...` and host submodule to
  `6baa026f...`, and merged as
  `6d31843458bf7c75322f60c5715ae598c6ed4cde`.
- Plugin validation: 105 repository tests passed; 37 focused tests passed before
  final CI hardening; targeted Ruff and format passed; sdist/wheel built; remote
  Python 3.10 and 3.12 wheel jobs passed.
- Clean-wheel validation used Manager and plugin wheels plus the pinned host's
  dependency-free carrier build. Manager discovered and checked host version
  `0.29.1.post1.dev1+g75aaa9b4b.empty` and both protocol APIs at `1.0`.
  User `VLLM_PLUGINS=user_plugin,ascend,user_plugin` rendered deterministically
  as `user_plugin,ascend,kv_materialization`.
- A Manager-supervised clean-wheel process resolved the installed plugin entry
  point, applied the pinned host request processor, and received a host-process
  observer receipt. Host core tests separately verify that lookup/commit
  receipts are emitted after actual cache outcomes. Disable removed activation
  from the next launch; forget and wheel uninstall removed Manager/package
  state. No port, NPU, or child process was left behind.
- No new NPU test was run. The historical 2026-09-10 Ascend result qualifies
  only the vLLM 0.23 compatibility adapter, not the merged native API v1.0 host.
  Compatibility freeze remains in force.

## ECPA 0.3 follow-through

- Manager PRs #18 and #19 merged as `2694cb11400b324e3a926a5e76b54a6a8710d0a3`
  and `2dffcf7fdea3cad36bc24c0c4174394bcc06d796`.
- Host PRs #44 and #45 merged as `e7dbd66251812282e5834a8532be9f830c991e0e`
  and `e521b42ed004692eea5ee2f1f8ff2f4d0245b7b1`.
- Arrival-control PR #27 merged as
  `15172b7c8630cf5fa8f33ae0d2c275df5ced7272` with Manager/host pins, Manifest
  0.3 resource claims, and isolated host-contract tests.
- The exact clean-wheel lifecycle included a live host-owned runtime observer
  receipt. `runtime_effective` was visible only while its PID/start identity
  remained alive, disappeared after supervised SIGINT cleanup, and was followed
  by successful disable, forget, and uninstall. This is not NPU or performance
  qualification.

# Follow-up discovery-isolation finding (2026-09-29)

- A malformed installed Bundle registration was able to make `extension list`
  fail before it showed any healthy Bundle. This was an ECPA inventory defect:
  disabled third-party metadata must not deny visibility into unrelated MODs.
- Strict resolution remains correct for inspect/check/enable/plan/render/run;
  the repair is intentionally limited to list inventory and preserves fail-closed
  activation.
- A clean-wheel mixed installation of CLM and Pegaflow reproduced the boundary:
  CLM remained visible while Pegaflow was reported with its cross-distribution
  activation-entry-point error.

# Provider-isolation re-audit finding (2026-09-30)

- KV Tiering PR #3 publishes a third-party Provider whose factory import requires
  `vllm`. In a clean Manager environment, eager loading of every Provider made
  that missing optional host dependency crash checks for unrelated Bundles.
- Provider lookup now loads only the selected external factory. A mixed
  clean-wheel install proved Prefix Router check still works while KV Tiering is
  reported incompatible with a precise `ModuleNotFoundError` diagnostic.
- The Mod still owns its import boundary, ECPA 0.3 manifest migration, protocol
  and resource declarations, and native-host validation.
- Pegaflow main moved its activation entry-point record into the Provider wheel,
  but the target `pegaflow.vllm_plugin` module is still absent from that wheel.
  Static target ownership validation now rejects this dangling record without
  importing or executing plugin code.
