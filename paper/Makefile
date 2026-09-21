LATEXMK ?= latexmk
EVIDENCE_SUMMARY := generated/evidence-summary.tex
EVIDENCE_INPUTS := \
	../docs/corpus/plugins.json \
	../docs/corpus/plugins.schema.json \
	../docs/corpus/source-snapshots.json \
	../docs/corpus/source-snapshots.schema.json \
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
	../experiments/false_effective/scenarios.json \
	../experiments/false_effective/protocol.json \
	../experiments/false_effective/verified-adapters.json \
	../spec/0.1/contract-taxonomy.json \
	../spec/0.1/contract-taxonomy.schema.json \
	../src/vllm_hust_ext/contract_compiler.py

.PHONY: all clean evidence-summary check-evidence-summary validate-results
all: main.pdf

$(EVIDENCE_SUMMARY): scripts/generate_evidence_summary.py $(EVIDENCE_INPUTS)
	python3 scripts/generate_evidence_summary.py

evidence-summary: $(EVIDENCE_SUMMARY)

check-evidence-summary:
	python3 scripts/generate_evidence_summary.py --check

main.pdf: main.tex references.bib $(EVIDENCE_SUMMARY)
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error main.tex

validate-results: check-evidence-summary
	python3 scripts/validate_results.py artifacts/results.example.json

clean:
	$(LATEXMK) -C main.tex
