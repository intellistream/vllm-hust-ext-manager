# ADR 0002: Manager-controller boundary for formal-real activation

Status: accepted for staged implementation on 2026-09-20.

## Decision

The ECPA arm uses the extension manager as the service controller. The manager
validates a canonical, content-addressed ECPA execution-plan artifact, owns the
propagation of launch identity and host-evidence configuration, and only then starts
vLLM-HUST. vLLM-HUST remains the authority for process identity, loader and
effect-path events. An independent observer consumes that host-owned evidence.

The controller process and every EngineCore/worker process remain distinct
identities. Controller progress never satisfies a worker evidence obligation.

## Why

Appending experiment-only flags to `vllm serve` would prove parser admission,
not manager-controlled activation. Moving planner or transaction policy into
vLLM-HUST would also expand the host seam beyond the evidence and enforcement
mechanisms that only the host can own. A manager controller preserves ECPA's
contract/runtime boundary while reusing the existing vLLM-HUST plugin paths.

## First implementation slice

`vllm-hust-ext formal-run` now fails closed before target launch unless it can:

- read an owned, canonical, non-symlink execution-plan artifact;
- recompute and match its content-addressed Plan ID;
- bind supplied fresh launch and controller identities without accepting
  conflicting inherited values;
- bind an existing private, owned, canonical host-event directory; and
- install strict, manager-owned vLLM-HUST evidence environment values.

The controller also freezes the event directory's device and inode. The sink
and reader reopen it with `O_DIRECTORY|O_NOFOLLOW`, recheck ownership and mode
on the directory descriptor, compare the frozen identity, and use that same
descriptor for journal I/O. A permissions drift or path replacement therefore
fails before evidence is appended or consumed.

The false-effective runner now has a fail-closed managed-launch constructor for
this exact entry point. It reads and recomputes the canonical Plan artifact,
copies those validated bytes into a runner-created private read-only snapshot,
rejects caller-supplied host-owned identity variables or injectable manager
prefix arguments, and constructs
`formal-run --plan ... --launch-id ... --controller-instance ...
--host-event-dir ... -- <target>` without the fixture-only
`--enable-ecpa-manager`/`--disable-entrypoints` flags. A dry-run regression test
executes the real manager CLI and verifies the resulting Plan and target
binding.

The snapshot is an accidental-mutation and validation-to-use safeguard within
a trusted same-UID runner boundary, not a security boundary against a malicious
launcher with the same operating-system identity. It is published only after a
canonical re-read by atomically renaming a `.partial` generation. Formal truth
is reconciled against the Plan ID in manager/host-owned evidence. The runner
also seals the snapshot digest in the command binding, and offline validation
re-reads the Plan artifact, recomputes its Plan ID and digest, and binds both to
the executed launch/controller identities.

Its activation probe exercises the real manager `formal-run` parser without
launching the target. ECPA formal-real admission independently fingerprints the
manager, target, and observer; the executed argv must match the manager-owned
launch envelope and the separately pinned target argv. The generic adapter
verifier rejects ECPA, so there is no fallback path based on appending synthetic
activation flags to the target. The registry remains empty, so this mechanism
cannot yet produce a formal-real result.

For Python console entry points, the runner derives and pins the direct
interpreter-plus-script argv that Linux exposes instead of assuming the wrapper
path remains `argv[0]`. Existing file-backed relative target and observer
arguments are made absolute during fingerprinting, and those normalized argv
values are the ones actually launched. The runner-to-manager environment omits
the target-only activation contract by design; offline validation instead binds
that contract through the manager-owned launch record and rejects a caller that
tries to preseed it.

Executable fingerprints seal the resolved device, inode, and digest. The runner
opens and verifies the manager and observer images before `exec`, then executes
the inherited descriptor through `/proc/self/fd` while retaining the reviewed
`argv[0]`. It also passes the target fingerprint to the manager; the manager
opens and verifies the target itself and uses the same descriptor-exec pattern.
The runner additionally reads the actual manager/observer image through
`/proc/<pid>/exe`, stores that identity separately from PID/start-ticks/argv,
and rechecks it offline. Retargeting an executable symlink after registry
verification therefore cannot substitute the manager, target, observer, or
activation probe, even if the link is later restored. This is a provenance
fail-closed check, not a sandbox against code that already runs with the
experiment user's privileges.

The manager runs the target in its own process group and converts manager
termination into bounded group termination followed by forced cleanup when
needed. The runner likewise keeps a start-scoped registry of every child and
pipe descriptor, so exceptions after identity validation still reap both
processes and close all descriptors before the start fails.

## Remaining gate

The formal adapter registry uses schema v2. Every future entry must contain a
producer-admission receipt binding the exact host repository identity, PR,
reviewed head/tree/base, merge commit, and the completed human line, command,
activation-path, and observer-independence reviews. Runtime admission checks
this receipt before it fingerprints or probes commands, and offline validation
rechecks the same receipt. This receipt is a code-review trust boundary, not a
live GitHub oracle or proof that a runtime effect occurred. The registry stays
empty while the producer is open.

The remaining gate is to independently associate host-assigned
EngineCore/worker identities with this same Plan/launch/controller tuple under
a real workload and fault driver, without treating controller ACKs as effect
evidence. Registration is forbidden until vLLM-HUST PR #27 is human-reviewed
and merged and the first real cell is independently reproduced.

BidKV remains an unchanged case-study candidate; this decision neither changes
its algorithm nor adds a second inference engine.
