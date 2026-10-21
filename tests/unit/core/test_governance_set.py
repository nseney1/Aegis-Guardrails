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
    (".aegis/adjudications/trap-x.jsonl", "aegis-state"),  # labels count only once merged (R-evidence-3)
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
    ".aegis/adjudicationsx/x.jsonl",
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
    ("pkg/.aegis/adjudications/x.jsonl", "aegis-state"),
    (".AEGIS/Rules/X.md", "rules"),
], ids=["rules", "baseline", "config", "team", "labels", "folded"])
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


# Given a root module that `python -m pytest` would import instead of the runner (the snapshot root
# is first on sys.path), When its path is classified, Then it is test infrastructure.
@pytest.mark.parametrize("path", [
    "pytest.py", "_pytest.py", "pluggy.py", "py.py", "iniconfig.py", "pytest.pyc", "pytest.so",
    "pytest.cpython-312-x86_64-linux-gnu.so", "pytest.cp312-win_amd64.pyd", "PYTEST.PY", "pytest/__init__.py",
    "_pytest/__init__.py", "pluggy/__init__.py", "py/__init__.py", "iniconfig/__init__.py",
], ids=lambda p: p.replace("/__init__.py", "-pkg").replace("cpython-312-x86_64-linux-gnu", "abi")[:20])
def test_a_module_that_shadows_the_runner_is_test_infra(path):
    assert governance.touches_governance([path]) == ["test-infra"]


# Given a root package of a runner module in any form Python imports as a regular package (a sourceless
# or compiled __init__), or its __main__ (what ``python -m pytest`` runs), When classified, Then it is
# test infrastructure; a .pyw module is source on Windows.
@pytest.mark.parametrize("path", [
    "pytest/__init__.pyc", "pytest/__init__.so", "pytest/__init__.cpython-312-x86_64-linux-gnu.so",
    "pytest/__init__.abi3.so", "pytest/__init__.pyd", "pytest/__init__.cp312-win_amd64.pyd", "pytest/__init__.pyw",
    "pytest/__main__.py", "pytest/__main__.pyc", "_pytest/__init__.pyc", "_pytest/__main__.py", "pluggy/__init__.so",
    "py/__init__.pyc", "py/__main__.py", "iniconfig/__init__.pyd", "PYTEST/__INIT__.PYC", "pytest.pyw",
], ids=lambda p: p.replace("/", "-").replace("cpython-312-x86_64-linux-gnu", "abi")[:28])
def test_a_compiled_runner_package_or_its_main_is_test_infra(path):
    assert governance.touches_governance([path]) == ["test-infra"]


# Sad path: names that only resemble a runner module, or a package below the root, stay outside.
@pytest.mark.parametrize("path", [
    "pytest.md", "pytest_helpers.py", "mypytest.py", "numpy.py", "docs/pytest/usage.md", "src/pytest/__init__.py",
    "py/helpers/util.py", "tests/pytest_cases.py", "pytestx/__init__.py", "src/pytest_helpers.py",
    "tests/pytest/__init__.pyc", "tests/pytest/__main__.py", "src/pytest/__init__.so", "pytest/helpers.pyc",
    "pytest/__pycache__/x.pyc", "pytestx/__main__.py",
], ids=lambda p: p.replace("/", "-")[:24])
def test_a_name_that_only_resembles_a_runner_module_is_outside(path):
    assert governance.touches_governance([path]) == []
    assert governance.category_of(path) is None


def test_the_runner_modules_are_named():
    assert governance.RUNNER_MODULES == ("pytest", "_pytest", "pluggy", "py", "iniconfig")


@pytest.mark.skipif(not __import__("shutil").which("git"), reason="needs git")
def test_the_label_pattern_leaves_an_approval_hash_without_label_files_unchanged(tmp_path, monkeypatch):
    """U8 (R-evidence-3): ``governance_tree_hash`` hashes existing matches only, so adding
    ``.aegis/adjudications/**`` keeps every 4.3 ``Aegis-Approve`` hash of a tree without labels."""
    from aegis_core import human_gate
    from tests import helpers_humangate as hg

    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    repo = hg.make_repo(tmp_path)
    plain = repo.head()
    repo.write(".aegis/adjudications/trap-sample.jsonl", '{"example_id": "e1", "verdict": "tp"}\n')
    labelled = repo.commit("labels")

    with_pattern = (human_gate.governance_tree_hash(repo.root, plain), human_gate.governance_tree_hash(repo.root, labelled))
    old_table = tuple((name, tuple(p for p in pats if "adjudications" not in p)) for name, pats in governance._FOLDED)
    monkeypatch.setattr(governance, "_FOLDED", old_table)
    without_pattern = (human_gate.governance_tree_hash(repo.root, plain), human_gate.governance_tree_hash(repo.root, labelled))

    assert with_pattern[0] == without_pattern[0]
    assert with_pattern[1] != without_pattern[1] and without_pattern[1] == without_pattern[0]
