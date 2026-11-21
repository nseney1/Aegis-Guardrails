"""README overclaim guard (ADR 0005 D23): retracted claims must not return.

Each phrase was once in the README and was removed because the code did not
earn it (the retired CLAIM_REGISTRY's `removed` claims, plus the nonexistent
npm package). Matching is case-insensitive: "Ungameable" is the same claim.
"""
from pathlib import Path

import pytest

README = Path(__file__).resolve().parents[3] / "README.md"

RETRACTED = (
    "Structured field-level rule merging",
    "structurally unprofitable",
    "Beta-Binomial posterior",
    "evolutionary computation",
    "deterministic verification",
    "ungameable",
    "deterministic set-algebra arbiter",
    "< 1.0% waste rate",
    "require('aegis-governance')",
    'require("aegis-governance")',
)


def retracted_phrases_in(text: str) -> list:
    lowered = text.lower()
    return [phrase for phrase in RETRACTED if phrase.lower() in lowered]


def test_readme_contains_no_retracted_claim():
    assert retracted_phrases_in(README.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("text", ["Aegis is UNGAMEABLE.", "uses Evolutionary Computation", "x < 1.0% WASTE RATE"])
def test_guard_catches_case_variants(text):
    assert retracted_phrases_in(text)
