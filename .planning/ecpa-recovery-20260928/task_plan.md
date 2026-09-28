# ECPA recovery task plan

Date: 2026-09-28 (UTC)

1. Audit local state, authoritative remotes, open PR heads, CI, and overlap with merged PRs #8-#14.
2. Re-implement the still-required PR #5 contract on `origin/main`, with deterministic activation, fail-closed compatibility, and consistent CLI surfaces.
3. Run unit, lint, type, build, and clean-wheel checks; publish a narrow replacement or update PR #5, merge only with passing evidence, and verify `origin/main`.
4. Rebase and validate vLLM-HUST PR #20 against its latest main.
5. Rebase and validate KV materialization PR #23 against its latest main (including merged PR #25), update dependency pins, and execute clean-wheel end-to-end lifecycle checks.
6. Update documentation/support claims to match evidence; preserve compatibility freeze unless every release gate is proven.

Safety constraints: no unknown service/process mutation; no NPU use unless CPU/fixture/contract checks require escalation and assigned devices/processes are audited first; no modification of unrelated dirty workspaces.
