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
- [x] Isolated invalid Bundle registrations in `extension list` while preserving
  strict selected operations, with unit and mixed clean-wheel regression tests.
- [x] Routed confirmed MOD packaging gaps to repository issues, reusing existing
  pluginization issues and using the organization tracker where Tricard disables
  repository issues.
- [x] Re-audited the tracked MOD repositories and isolated selected external
  Provider loading so one broken Provider cannot deny unrelated ECPA operations;
  also reject activation entry points whose target module is absent from the
  declaring wheel/editable distribution.

## Organization-wide follow-up (2026-10-02)

- [x] Enumerated and classified all 71 organization repositories.
- [x] Built and co-installed all 26 ECPA distributions.
- [x] Routed newly found Mod-owned gaps to owner repositories.
- [x] Implemented and unit-tested ECPA Bundle dependency admission.
- [x] Rebuild and rerun final clean-wheel validation.
- [x] Open, merge, and remotely verify Manager PR #26 at
  `031cbb13ae1dc9deebb09d55dc85a1918cd33dc0`.
- [x] Remove temporary organization-audit artifacts and worktree.

## Request-lifecycle follow-up (2026-10-02)

- [x] Modernize host PR #6 on current main, publish the versioned
  `vllm.request-lifecycle-events` capability, pass pre-commit and focused
  scheduler tests, merge, and verify main at
  `7620b23ab6d91230ff1c3f65f2dc4727fdec90c9`.
- [x] Repair canonical CLM package protocol naming and default-off activation,
  pass Python 3.10/3.12/3.14 CI plus clean-wheel lifecycle checks, merge PR #2,
  and verify main at `efaae1052a672ba4df7f6139ad2d1eabda80abea`.
- [x] Keep compatibility freeze: no current-head NPU, live observer receipt, or
  performance evidence was produced by this follow-up.
