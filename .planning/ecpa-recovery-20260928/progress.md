# ECPA recovery progress

- [x] Verified requested local checkout was absent.
- [x] Verified authoritative remote heads for all three repositories and target PRs.
- [x] Created clean clone, isolated worktree, and requested branch from latest Manager main.
- [x] Captured PR #5 diff for overlap review.
- [x] Modernize and validate Manager plugin activation contract.
- [x] Add CI for Python 3.10/3.12 tests, Ruff, strict mypy, build, and clean-wheel CLI.
- [x] Replaced PR #5 with PR #15, passed CI, merged, and verified remote main.
- [x] Reconciled host PR #20 with latest main, passed pre-commit/contract tests,
  merged, and verified remote main at `6baa026f602fd221dc7db64362730305048a8b87`.
- [x] Reconciled KV plugin PR #23 with PR #25, passed dual-Python CI, merged,
  and verified remote main at `6d31843458bf7c75322f60c5715ae598c6ed4cde`.
- [x] Passed clean-wheel discover/check/enable/plan/render/run-observer/
  disable/rollback/forget/uninstall validation without NPU use or residual
  Manager-owned processes.
- [x] Updated support claims and kept compatibility freeze for remaining
  native-NPU, failure-degradation, and broader support-matrix gates.
- [x] Merged ECPA 0.3 capability/resource contracts (Manager #18, host #44),
  live-only observer evidence (Manager #19, host #45), and the real plugin
  migration (#27); verified exact remote main commits and dual-Python CI.
