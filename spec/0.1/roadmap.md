# Standardization roadmap

Roadmap owner: `ShuhaoZhangTony` (张书豪). Execution is PI-led/self-driven and
does not depend on a student owner or student delivery milestone.

The current research and paper validate the proposed contract through a deep
vLLM-HUST system study. Cross-runtime validation is deferred future work and is
not a current milestone or submission gate. The roadmap below describes a
possible longer-term standardization path, not commitments for the current
paper.

1. **Internal contract:** stabilize names, schema, negative fixtures, and M0
   oracle in this repository.
2. **Multi-plugin validation:** migrate diverse policy, connector, provider,
   cache, and observer cases; measure L0--L4 per pinned cell.
3. **Two-organization adoption:** obtain independent maintained integrations in
   both vLLM-HUST and intellistream, not merely forks owned by one author.
4. **Upstream RFC and community feedback:** propose the smallest useful contract
   to vLLM and related communities; record rejected and revised semantics.
5. **Future independent interoperability:** after the current paper, demonstrate
   independent implementations exchanging manifests/plans/evidence without
   shared code; a future cross-runtime study may be one source of evidence.
6. **Governance and evolution:** publish compatibility policy, test authority,
   release cadence, deprecation window, security process, and neutral change
   review.

External adoption evidence required before any de-facto-standard claim: at
least two independent implementations, multiple production/research users,
public conformance results, an upstream or cross-project RFC review, versioned
compatibility history, and governance not controlled by a single repository.
Today this is a research prototype and specification draft only.
