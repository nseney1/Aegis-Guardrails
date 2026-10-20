"""The governance file set (v4.3 spec §2.3): which changed paths need a human approval."""
from __future__ import annotations

import pytest

from aegis_core import governance


@pytest.mark.parametrize("path,category", [
    (".aegis/rules/traps/trap-x.md", "rules"),
    (".aegis/rules/README.md", "rules"),
    (".aegis/config.json", "aegis-state"),
    (".aegis/team.json", "aegis-state"),
    (".aegis/baseline.json", "aegis-state"),
    ("allowed_signers", "signers"),
    ("CODEOWNERS", "signers"),
    (".github/CODEOWNERS", "signers"),
    ("docs/CODEOWNERS", "signers"),
    (".github/workflows/validate.yml", "workflows"),
    ("conftest.py", "test-infra"),
    ("tests/unit/conftest.py", "test-infra"),
    ("pytest.ini", "test-infra"),
    ("tox.ini", "test-infra"),
    ("setup.cfg", "test-infra"),
    ("pyproject.toml", "test-infra"),
    ("sitecustomize.py", "test-infra"),
    ("evil.pth", "test-infra"),
    ("lib/site/evil.pth", "test-infra"),
    ("Makefile", "test-infra"),
])
def test_each_member_of_the_set_has_its_category(path, category):
    assert governance.touches_governance([path]) == [category]
    assert governance.category_of(path) == category


@pytest.mark.parametrize("path", [
    "README.md",
    "src/app.py",
    "tests/test_app.py",
    ".aegis/state/ledger.jsonl",
    ".aegis/rulesx/a.md",
    ".aegisx/config.json",
    ".aegis/proposals/p.md",
    "docs/guide.md",
    "src/conftest_helper.py",
    "allowed_signers_notes.txt",
    ".github/dependabot.yml",
    ".github/workflows",
    "",
])
def test_everything_else_is_outside_the_set(path):
    assert governance.touches_governance([path]) == []
    assert governance.category_of(path) is None


def test_matching_is_case_folded_and_separator_agnostic():
    assert governance.touches_governance([".AEGIS/Rules/trap/X.md"]) == ["rules"]
    assert governance.touches_governance([".aegis\\config.json"]) == ["aegis-state"]
    assert governance.touches_governance(["./.github/Workflows/ci.yml"]) == ["workflows"]
    assert governance.touches_governance(["CONFTEST.PY"]) == ["test-infra"]


def test_a_present_test_file_is_not_governance_but_a_deleted_one_is():
    assert governance.touches_governance(["tests/test_app.py"]) == []
    assert governance.touches_governance(["tests/test_app.py"], deleted=["tests/test_app.py"]) == ["tests-deleted"]
    assert governance.category_of("tests/test_app.py", deleted=True) == governance.DELETED_TESTS


def test_a_deleted_path_counts_even_when_the_caller_lists_it_only_as_deleted():
    assert governance.touches_governance([], deleted=["pkg/test_x.py"]) == ["tests-deleted"]


def test_a_deleted_governance_file_keeps_its_own_category():
    assert governance.touches_governance(["conftest.py"], deleted=["conftest.py"]) == ["test-infra"]


def test_categories_come_back_once_each_in_table_order():
    paths = ["Makefile", ".github/workflows/a.yml", ".aegis/rules/x.md", "setup.cfg", ".aegis/rules/y.md"]
    assert governance.touches_governance(paths) == ["rules", "workflows", "test-infra"]


def test_an_empty_change_touches_nothing_and_non_string_entries_are_ignored():
    assert governance.touches_governance([]) == []
    assert governance.touches_governance([None, 3, b"conftest.py"]) == []  # type: ignore[list-item]
    assert governance.category_of(None) is None  # type: ignore[arg-type]


def test_a_path_with_dot_segments_does_not_escape_the_table():
    # normalize_path strips ./ ; a traversal stays a different path and is not governance.
    assert governance.touches_governance(["src/../README.md"]) == []


@pytest.mark.parametrize("path,category", [
    ("pkg/.aegis/rules/invariants/x.md", "rules"),
    ("a/b/.aegis/baseline.json", "aegis-state"),
    ("pkg/.aegis/config.json", "aegis-state"),
    ("pkg/.aegis/team.json", "aegis-state"),
    (".AEGIS/Rules/X.md", "rules"),
], ids=["rules", "baseline", "config", "team", "folded"])
def test_a_nested_workspace_aegis_directory_is_governance_wherever_it_sits(path, category):
    assert governance.category_of(path) == category


@pytest.mark.parametrize("path", [
    "docs/aegis-notes.md", "src/aegis/config.json", "x.aegis/config.json", "pkg/.aegis/state/ledger.jsonl",
    "pkg/.aegis/proposals/p.md",
], ids=["notes", "srcdir", "suffix", "state", "proposals"])
def test_names_that_only_resemble_an_aegis_directory_stay_outside(path):
    assert governance.category_of(path) is None


def test_a_leading_double_star_also_matches_at_the_top_level():
    from aegis_core import match

    assert match.matches("**/.aegis/rules/**", ".aegis/rules/x.md")
