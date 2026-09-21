# Paper build and evidence contract

Paper lead and accountable owner: `ShuhaoZhangTony` (张书豪). Research,
artifact, and submission decisions are PI-led/self-driven; student
contributions are optional and non-blocking.

This is a venue-neutral, two-column systems-paper draft. It intentionally does
not claim compliance with an unconfirmed OSDI, SOSP, EuroSys, ACM, or USENIX
submission year. Adapt the class and anonymity requirements only after the
venue is fixed.

Build:

```bash
cd paper
make
make validate-results
make check-evidence-summary
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
- Artifact-backed counts and modeled metrics in `main.tex` come from the
  checked-in `generated/evidence-summary.tex`. Regenerate it with `make
  evidence-summary`; `make check-evidence-summary` fails if it is stale or if
  the corpus, planner, formal-status, and adapter-registry inputs disagree.

Alignment:

| Governance item | Paper location |
|---|---|
| Research charter | Sections 1--3 |
| Issue #2 / M0 taxonomy and failure model | Sections 2, 3, 7 |
| Issue #4 / M1 capability and conflict planner | Sections 4.2--4.4, H2 |
| Issue #3 / M2 lifecycle, runtime evidence, rollback | Sections 4.5--4.8, H1/H3 |
| Issue #5 / program, two-week gate, stop-loss | Sections 1, 7, 9 |
| M3 cost gate | H4 and Section 7 |

`artifacts/results.schema.json` is the machine contract. The example is planned,
not a measured result. Run `make validate-results` before admitting artifacts.
The ECPA interoperability contract is versioned under `../spec/`; the Manager
is a reference implementation rather than the standard itself.
