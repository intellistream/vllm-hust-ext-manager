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

## Pending evidence

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
- Host and plugin dependency-chain validation.
