LATEXMK ?= latexmk
TECTONIC ?= tectonic
EVIDENCE_SUMMARY := generated/evidence-summary.tex
EVIDENCE_INPUTS := \
	../docs/corpus/plugin-workshop-metadata.snapshot.json \
	../docs/corpus/workshop-mods.json \
	../docs/corpus/workshop-mods.schema.json \
	../docs/corpus/plugins.json \
	../docs/corpus/plugins.schema.json \
	../docs/corpus/source-snapshots.json \
	../docs/corpus/source-snapshots.schema.json \
	../docs/research/claims-to-experiment-matrix.json \
	../docs/research/claims-to-experiment-matrix.schema.json \
	../experiments/contract_planner/cases.json \
	../experiments/contract_planner/cases.schema.json \
	../experiments/contract_planner/decision.schema.json \
	../experiments/contract_planner/oracle.json \
	../experiments/contract_planner/oracle.schema.json \
	../experiments/contract_planner/evaluate.py \
	../experiments/contract_planner/metrics.schema.json \
	../experiments/contract_planner/results/decisions.jsonl \
	../experiments/contract_planner/results/metrics.json \
	../experiments/false_effective/artifacts/formal-aggregate-summary.json \
	../experiments/false_effective/artifacts/reference-summary.json \
	../experiments/false_effective/first-formal-real-study.json \
	../experiments/false_effective/first-formal-real-study.schema.json \
	../experiments/false_effective/first-formal-real-deployment.json \
	../experiments/false_effective/first-formal-real-deployment.schema.json \
	../experiments/false_effective/harness.py \
	../experiments/false_effective/scenarios.json \
	../experiments/false_effective/protocol.json \
	../experiments/false_effective/verified-adapters.json \
	../experiments/transaction_model/explore.py \
	../experiments/transaction_model/artifacts/result-summary.json \
	../experiments/transaction_model/result-summary.schema.json \
	../spec/0.1/contract-taxonomy.json \
	../spec/0.1/contract-taxonomy.schema.json \
	../src/vllm_hust_ext/contract_compiler.py \
	../src/vllm_hust_ext/formal_lifecycle_source.py

.PHONY: all clean evidence-summary check-evidence-summary check-research-matrix tectonic validate-results
all: main.pdf

$(EVIDENCE_SUMMARY): scripts/generate_evidence_summary.py $(EVIDENCE_INPUTS)
	python3 scripts/generate_evidence_summary.py

evidence-summary: $(EVIDENCE_SUMMARY)

check-evidence-summary:
	python3 scripts/generate_evidence_summary.py --check

check-research-matrix:
	python3 ../scripts/validate_research_matrix.py

main.pdf: main.tex references.bib $(EVIDENCE_SUMMARY) check-research-matrix
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error main.tex

tectonic: main.tex references.bib $(EVIDENCE_SUMMARY) check-research-matrix
	$(TECTONIC) --keep-logs main.tex

validate-results: check-evidence-summary check-research-matrix
	python3 scripts/validate_results.py artifacts/results.example.json

clean:
	$(LATEXMK) -C main.tex
