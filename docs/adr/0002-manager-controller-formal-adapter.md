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

Its activation probe does not launch the target. The command is not yet in the
verified adapter registry and therefore cannot produce a formal-real result.

## Remaining gate

The formal runner must bind the controller to the same Plan artifact, pass its
fresh launch identity before process creation, and independently associate
host-assigned EngineCore/worker identities with that launch. A causal phase
controller and real workload/fault driver must be added without treating its
ACKs as effect evidence. Registration is forbidden until vLLM-HUST PR #27 is
human-reviewed and merged and the first real cell is independently reproduced.

BidKV remains an unchanged case-study candidate; this decision neither changes
its algorithm nor adds a second inference engine.
