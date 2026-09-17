# Paper build and evidence contract

This is a venue-neutral, two-column systems-paper draft. It intentionally does
not claim compliance with an unconfirmed OSDI, SOSP, EuroSys, ACM, or USENIX
submission year. Adapt the class and anonymity requirements only after the
venue is fixed.

Build:

```bash
cd paper
make
make validate-results
```

The expected tool is `latexmk` with `pdflatex` and BibTeX. `main.pdf` is a build
artifact and is ignored by Git. The checked-in source uses only common TeX Live
packages.

Evidence rules:

- Observed values must point to a raw artifact and exact code/runtime identity.
- Planned cells use JSON `null` and `status: "planned"`; they are never encoded
  as zero.
- Failed runs remain records with failure class and phase.
- Formal cells use at least three independent service starts and record arm
  order, process topology, warm/cold state, model/workload, hardware, and every
  model/API call.
- Aggregates may not hide a failed provider, process topology, or version tuple.
- A figure/table generator must reject mixed identities and missing required
  provenance before producing a paper result.

Alignment:

| Governance item | Paper location |
|---|---|
| Research charter | Sections 1--3 |
| Issue #2 / M0 taxonomy and failure model | Sections 2, 3, 6 |
| Issue #4 / M1 capability and conflict planner | Sections 3.2--3.3, H2 |
| Issue #3 / M2 lifecycle, runtime evidence, rollback | Sections 3.4--3.7, H1/H3 |
| Issue #5 / program, two-week gate, stop-loss | Sections 1, 6, 8 |
| M3 cost gate | H4 and Section 6 |

`artifacts/results.schema.json` is the machine contract. The example is planned,
not a measured result. Run `make validate-results` before admitting artifacts.
