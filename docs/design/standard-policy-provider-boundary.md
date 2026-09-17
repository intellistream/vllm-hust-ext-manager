# Contract, policy, provider, and host boundary

The standardizable ECPA Contract defines schemas, canonical IDs, lifecycle and
errors, evidence/fencing semantics, compatibility negotiation, and conformance.
ECPA policy chooses timeout, fallback, quorum where permitted, risk posture,
and operator intervention. Provider/host code enumerates processes, applies
host mappings, controls traffic gates, and obtains host-backed observations.

The reference implementation may implement all three adapters, but conformance
tests keep their authorities separate. No provider declaration can enlarge the
contract authority assigned to it.
