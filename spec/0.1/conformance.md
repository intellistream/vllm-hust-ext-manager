# Conformance test plan

Run `python3 scripts/check_spec_conformance.py`. The current skeleton verifies
the 0.1 schema, the minimal L1 example, both invalid examples, and the corpus
registry. L0 additionally requires an installed-distribution probe resolving
exactly one static manifest. L2 fixtures combine manifests and compare planner
decisions with an independent resource oracle. L3 injects missing/inert/mixed
workers and rejects false-effective state. L4 interrupts prepare, launch,
observe, and commit, then verifies the predecessor plan and authority boundary.

The CLI reports only the highest demonstrated level for a pinned cell. It must
not infer L3 from an L1 manifest or infer L4 from a successful disable command.
