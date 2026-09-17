from scripts.check_spec_conformance import main


def test_spec_and_corpus_conformance() -> None:
    assert main() == 0
