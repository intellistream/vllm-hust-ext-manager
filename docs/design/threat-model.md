# Threat model and trust boundary

Covered faults: malformed/ambiguous identity, version skew, resource aliasing,
partial worker launch, stale epoch, nonce replay, manager crash/retry,
split-brain generation commit, provider overreach, plugin self-assertion,
external lease loss, and interrupted rollback.

Trusted roots are operator intent signatures and host runtime identity/process
inventory. Authorities may be buggy but cannot amplify facts outside their
role. The evidence store preserves ordering but cannot mint truth. ECPA does
not sandbox malicious Python, tolerate a compromised host root, guarantee
network availability, or recover external data/service state it does not own.

In particular, a general Python plugin is a trusted in-process extension. It
can import or mutate observer internals, so Phase A loader events establish
control flow only for non-adversarial plugins. They do not solve malicious
plugin self-assertion. Security use requires a deployment-controlled sink,
authenticated transport, and trusted signing boundary; those mechanisms are
not supplied by Phase A.
