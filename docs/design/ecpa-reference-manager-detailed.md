# ECPA Reference Manager — detailed component diagram

This is the fine-grained companion to [`ecpa-architecture.md`](./ecpa-architecture.md)
(the terse Authority graph) and to `fig:architecture` in `paper/main.tex`
(the two-row simplified pipeline the paper actually prints). This diagram is
deliberately more detailed than anything that belongs in the paper: it exists
to think clearly about which module owns which fact, and the paper figure
should stay derivable from it by collapsing each dashed group below into one
box. Do not promote a box's presence here into an implementation or
evaluation status claim — that is what `evaluation.md`/`main.tex` Section 7
already tracks explicitly.

Every node below is labeled with the source module it maps to. Nodes with no
`src/` label are protocol-level concepts (the PLAN→PREPARE→LAUNCH→OBSERVE→COMMIT
workflow, the five evidence facts D/P/I/F/X) that do not live in one file.

```mermaid
flowchart TB
    subgraph MGMT["Management inputs"]
        direction LR
        M1["Extension bundle"]
        M2["Saved intent"]
        M3["Lifecycle request"]
        M4["CLI / management API"]
    end

    subgraph MANAGER["ECPA Reference Manager — host-neutral boundary"]
        direction LR

        subgraph STATIC["Static planning — pure, no external side effects"]
            direction TB
            S1["Bundle Discovery<br/><i>metadata only, never imports<br/>plugin implementation code</i><br/>discovery.py"]
            S2["Manifest Parser<br/>manifest.py"]
            S3["Contract Compiler<br/><i>resolves PEP-440 requirements to<br/>exactly one provider per capability</i><br/>contract_compiler.py"]
            S4["Conflict Graph / Authority Check<br/><i>resource ownership: exclusive /<br/>shared-read / mediated</i><br/>contract_compiler.py"]
            S5["Immutable Execution Plan<br/><i>plan_id = content_id(canonical_bytes)</i><br/>ecpa_model.py"]
            S1 --> S2 --> S3 --> S4 --> S5
        end

        subgraph TXN["Durable activation transaction"]
            direction TB
            T0["PLAN → PREPARE → LAUNCH → OBSERVE → COMMIT<br/><i>public lifecycle; failure branches to<br/>Reconcile / Rollback / FailedSafe</i>"]
            T1["Activation Coordinator<br/><i>plan() → prepare() → launch() →<br/>observe() → commit()</i><br/>durable_coordinator.py: ActivationCoordinator"]
            T2["Generation & Fence<br/><i>manager_epoch CAS invalidates stale<br/>evidence; route fence = predecessor.generation+1</i><br/>durable_coordinator.py"]
            T3["Append-only WAL + Receipts<br/><i>crash recovery resumes observation,<br/>never infers success from last step</i>"]
            T4a["Process Inventory — declared<br/><i>target set frozen in the Plan digest</i><br/>ecpa_model.py: Plan.targets"]
            T4b["Process Inventory — observed<br/><i>live PID/start-tick identity, independent<br/>of any SUT self-report</i><br/>host_observer.py"]
            T0 --> T1
            T1 --> T2
            T1 --> T3
            T4a -. "must agree before Effective (I3: authority locality)" .- T4b
            T1 --> T4a
            T1 --> T4b
        end

        subgraph EVID["Evidence & exposure"]
            direction TB
            E1["Host Event Sink<br/><i>append-only custody, not a fact issuer</i><br/>host_event_sink.py"]
            E2["Host Observer<br/><i>independent snapshot; does not turn runner<br/>phase acks into runtime facts</i><br/>host_observer.py"]
            E3["Attestation Verifier<br/><i>identity + epoch + coverage checks;<br/>raw events are audit input, never<br/>coordinator attestations by themselves</i><br/>host_evidence.py"]
            E4["Exposure Gate<br/><i>stage → close → open → drain → restore</i><br/>exposure_gate.py: GateState"]
            E4a["Candidate Open"]
            E4b["Restore / Fail-close<br/><i>unobservable close → SafetyUnknown,<br/>never manufactured success</i>"]
            E1 --> E2 --> E3 --> E4
            E4 --> E4a
            E4 --> E4b
        end

        S5 --> T1
        T2 -.-> E4
        T4b --> E2
        E3 --> T1
    end

    subgraph ADAPT["Authority-bounded adapter interfaces — host-specific boundary"]
        direction LR
        A1["Provider protocol: plan / render / check<br/><i>cannot silently apply, delete, or<br/>restart infrastructure</i>"]
        A2["HostAdapter<br/><i>fail-closed manager-owned launch seam</i><br/>manager_controller.py"]
        A3["TrafficGate"]
        A4["ExternalServiceAdapter"]
    end

    subgraph RUNTIME["Authority-owned runtime domains"]
        direction LR

        subgraph VLLM["vLLM Host Authority"]
            direction TB
            V1["API Server"]
            V2["Engine / Scheduler"]
            V3["Workers"]
        end

        subgraph MOON["Mooncake Service Authority<br/><i>real HTTP lease/health checks —<br/>can independently observe effect</i>"]
            direction TB
            K1["connector"]
            K2["transfer engine"]
            K3["store"]
            K4["lease / health / operation facts"]
        end

        subgraph PSTACK["Production Stack Authority<br/><i>⚠ render-only today — cannot yet<br/>independently observe runtime effect,<br/>despite equal visual weight elsewhere</i>"]
            direction TB
            P1["Controller"]
            P2["Router"]
            P3["Cluster Evidence"]
        end

        TRAFFIC["Traffic / Admission"]
    end

    MGMT --> S1
    E4a --> TRAFFIC
    A2 -->|"vllm.py provider"| VLLM
    A4 -->|"mooncake.py provider"| MOON
    A1 -->|"production_stack.py provider<br/>(render only, see ⚠ above)"| PSTACK
    A3 --> TRAFFIC
    MANAGER --> ADAPT
    ADAPT --> RUNTIME

    classDef pure fill:#e8f0ff,stroke:#4472c4
    classDef txn fill:#fff2cc,stroke:#d6b656
    classDef evid fill:#d5e8d4,stroke:#82b366
    classDef adapt fill:#f5f5f5,stroke:#666666,stroke-dasharray: 4 3
    classDef partial fill:#fbe5d5,stroke:#c0504d,stroke-dasharray: 4 3
    classDef full fill:#d5e8d4,stroke:#82b366

    class S1,S2,S3,S4,S5 pure
    class T0,T1,T2,T3,T4a,T4b txn
    class E1,E2,E3,E4,E4a,E4b evid
    class A1,A2,A3,A4 adapt
    class PSTACK partial
    class MOON full
```

## Deliberate corrections against the source-drawn (draw.io) version

These three points are the "fine → coarse" corrections found by cross-checking
every node above against the real module (docstrings, enums, call sites), not
against the diagram alone:

1. **Process Inventory is drawn as two nodes, not one.** The safety argument
   (`main.tex` §3.4, invariant I3) depends on a *declared* target set (frozen
   into the Plan digest at compile time, `ecpa_model.py: Plan.targets`) being
   checked against an *observed* target set that `host_observer.py` builds
   independently, explicitly *without* trusting SUT self-report
   (`host_observer.py` docstring: "does not turn runner phase acknowledgements
   into runtime facts"). Collapsing this into one "Process Inventory" box would
   hide the exact mechanism the paper's false-effective argument relies on.
   This distinction must survive any further simplification.

2. **Mooncake and Production Stack adapters are not at the same implementation
   depth**, even though the original diagram gives them equal visual weight.
   `providers/mooncake.py` does real network-based lease/health checks
   (`urlopen`/`Request` against the live service) — it can independently
   observe an effect. `providers/production_stack.py` is explicitly
   docstring-labeled **render-only**: it can generate config for the
   Kubernetes/Production-Stack resources but cannot yet observe whether that
   config produced a runtime effect. This asymmetry is worth keeping visible
   (marked ⚠ above) rather than smoothing over — it is a real gap in L3
   coverage for that authority, not a drawing inconsistency.

3. **`quarantine_transaction.py` is intentionally absent** from this diagram.
   It backs `experiments/false_effective/runner.py` and
   `formal_lifecycle_source.py` — i.e. it is evaluation-harness / fault-injection
   tooling, not a component of the reference manager itself. Its correct home
   is a separate evaluation-architecture diagram, not this one; re-adding it
   here would blur the manager/harness boundary the paper itself insists on
   (§3.2: harness sources are trusted evidence components, not part of the SUT).

## How this collapses into `fig:architecture`

The paper's printed figure is this diagram with each dashed group merged into
one box: `STATIC` → *Contract compiler (conflicts, order, coverage)*; `TXN` +
`EVID` → *Transactional runtime (prepare→activate→observe)* plus *Evidence
verifier* plus *ExposureGate*; `ADAPT` → *Typed host adapter*; `RUNTIME` →
*Host execution paths*. Point 1 and 2 above are exactly the kind of detail
that a reader of the paper figure does not need and should not see — but they
are exactly what this working diagram exists to keep straight while the
implementation is still being built out.
