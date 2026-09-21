from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_vendored_style_has_explicit_pdftex_and_xetex_paths() -> None:
    style = (ROOT / "paper/usenix2019_v3.sty").read_text()

    assert "\\usepackage{iftex}" in style
    assert "\\usepackage[utf8]{inputenc}" in style
    assert "\\usepackage[kerning,spacing]{microtype}" in style
    assert "\\usepackage{microtype}" in style
    assert "\\usepackage{breakurl}" in style
    assert style.count("\\ifPDFTeX") == 3


def test_makefile_exposes_same_source_tectonic_build() -> None:
    makefile = (ROOT / "paper/Makefile").read_text()

    assert "TECTONIC ?= tectonic" in makefile
    assert "tectonic: main.tex references.bib" in makefile
    assert "$(TECTONIC) --keep-logs main.tex" in makefile
