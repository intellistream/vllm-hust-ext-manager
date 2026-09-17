LATEXMK ?= latexmk

.PHONY: all clean validate-results
all: main.pdf

main.pdf: main.tex references.bib
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error main.tex

validate-results:
	python3 scripts/validate_results.py artifacts/results.example.json

clean:
	$(LATEXMK) -C main.tex
