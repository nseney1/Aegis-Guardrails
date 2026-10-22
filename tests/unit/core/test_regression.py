"""Unit tests for ``aegis_core.regression`` (v4.3 spec §3 T5): classifiers, edges, and sad paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any, Dict

import pytest

from aegis_core import human_gate, regression
from aegis_core.regression import (
    RegressionError,
    is_config_file,
    is_doc_file,
    is_fix_commit,
    is_python_test_file,
    is_source_file,
    is_test_file,
    parse_fix_subject,
)
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path, signer_pub: str | None = None) -> hg.Repo:
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# app\n")
    repo.write("src/__init__.py", "")
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x - 1\n")
    repo.write(
        "tests/test_app.py",
        "from src.app import compute\n\ndef test_existing():\n    assert isinstance(compute(1), int)\n",
    )
    if signer_pub is not None:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


# ── Path & commit classifiers ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,expected_source,expected_test,expected_doc,expected_config",
    [
        ("src/app.py", True, False, False, False),
        ("aegis_core/regression.py", True, False, False, False),
        ("pkg/handler.go", True, False, False, False),
        ("tests/unit/test_app.py", False, True, False, False),
        ("test_app.py", False, True, False, False),
        ("src/app_test.py", False, True, False, False),
        ("conftest.py", False, True, False, True),
        ("README.md", False, False, True, False),
        ("docs/architecture.rst", False, False, True, False),
        ("CHANGELOG.md", False, False, True, False),
        ("LICENSE", False, False, True, False),
        ("CHANGES", False, False, True, False),
        ("doc/guide.md", False, False, True, False),
        ("NOTICE.txt", False, False, True, False),
        ("SECURITY.md", False, False, True, False),
        ("web/templates/index.html", False, False, True, False),
        ("src/security.py", True, False, False, False),
        ("app/history.py", True, False, False, False),
        ("pkg/changes.py", True, False, False, False),
        ("src/license.py", True, False, False, False),
        ("lib/notice.go", True, False, False, False),
        ("src/doc/parser.py", True, False, False, False),
        ("pyproject.toml", False, False, False, True),
        (".github/workflows/ci.yml", False, False, False, True),
        (".aegis/config.json", False, False, False, True),
        ("Makefile", False, False, False, True),
    ],
)
def test_file_classifiers(
    path: str,
    expected_source: bool,
    expected_test: bool,
    expected_doc: bool,
    expected_config: bool,
):
    assert is_source_file(path) is expected_source
    assert is_test_file(path) is expected_test
    assert is_doc_file(path) is expected_doc
    assert is_config_file(path) is expected_config


def test_python_test_file_excludes_conftest_and_non_python():
    assert is_python_test_file("tests/test_app.py") is True
    assert is_python_test_file("conftest.py") is False
    assert is_python_test_file("tests/conftest.py") is False
    assert is_python_test_file("src/app.test.ts") is False


@pytest.mark.parametrize(
    "subject,expected_fix,expected_scope",
    [
        ("fix: off by one", True, None),
        ("fix!: breaking bugfix", True, None),
        ("fix(auth): token expiry check", True, "auth"),
        ("fix(auth)!: token expiry check", True, "auth"),
        ("Fix(parser): handle empty input", True, "parser"),
        ("fix(ci): workflow cache", False, "ci"),
        ("fix(docs): typo", False, "docs"),
        ("fix(build): wheel", False, "build"),
        ("fix(deps): pin lib", False, "deps"),
        ("fix(release): bump", False, "release"),
        ("fix(chore): lint", False, "chore"),
        ("fix(tests): fixture", False, "tests"),
        ("feat(api): add endpoint", False, "api"),
        ("chore: update", False, None),
    ],
)
def test_parse_fix_subject(subject: str, expected_fix: bool, expected_scope: str | None):
    is_fix, scope = parse_fix_subject(subject)
    assert is_fix is expected_fix
    assert scope == expected_scope


def test_is_fix_commit_requires_both_fix_signal_and_source_file():
    assert is_fix_commit("fix: bug", [], ["src/app.py"]) is True
    assert is_fix_commit("refactor: cleanup", ["#12"], ["src/app.py"]) is True
    assert is_fix_commit("fix(ci): pipeline", ["#12"], ["src/app.py"]) is False
    assert is_fix_commit("fix: docs only", ["#12"], ["README.md", "pyproject.toml"]) is False
    assert is_fix_commit("feat: new feature", [], ["src/app.py"]) is False


@needs_git
def test_a_fix_to_a_module_named_like_a_document_is_judged(tmp_path: Path):
    """R-evidence-25: Given a fix commit touching only src/security.py, When regressions are checked,
    Then it is a fix commit failing with no_test_changes (it used to be read as documentation)."""
    repo = make_repo(tmp_path)
    repo.write("src/security.py", "def harden() -> bool:\n    return True\n")
    oid = repo.commit("fix: harden security module")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status, c.reason) for c in report.commits] == [(oid, "failed", "no_test_changes")]
    assert report.commits[0].source_files == ("src/security.py",)


# ── Fail-to-pass failure modes ───────────────────────────────────────────────


@needs_git
def test_collection_error_on_base_does_not_count_as_fail_to_pass(tmp_path: Path):
    """A test file that fails collection on base (top-level ImportError) is not a valid fail-to-pass test."""
    repo = make_repo(tmp_path)
    repo.write(
        "src/app.py",
        "def compute(x: int) -> int:\n    return x + 1\n\n"
        "def brand_new_symbol() -> int:\n    return 42\n",
    )
    # Top-level import of brand_new_symbol causes collection error on base, while the test itself asserts True!
    repo.write(
        "tests/test_app.py",
        "from src.app import brand_new_symbol\n\n"
        "def test_fake():\n"
        "    assert True\n",
    )
    repo.commit("fix: try to game fail-to-pass with top-level import error on base")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is False
    item = report.commits[0]
    assert item.status == "failed"
    assert item.reason == "collection_error_on_base"
    assert item.failed_on_base is False


@needs_git
def test_failing_test_on_head_fails_regression_check(tmp_path: Path):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x - 2\n")
    repo.write(
        "tests/test_app.py",
        "from src.app import compute\n\n"
        "def test_compute():\n"
        "    assert compute(5) == 6\n",
    )
    repo.commit("fix: broken fix where test still fails on head")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is False
    item = report.commits[0]
    assert item.status == "failed"
    assert item.reason == "failed_on_head"
    assert item.passed_on_head is False


@needs_git
def test_empty_test_file_with_no_collected_tests_fails(tmp_path: Path):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.write("tests/test_app.py", "# no tests in this file\nx = 1\n")
    repo.commit("fix: remove all test functions from test file")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is False
    item = report.commits[0]
    assert item.status == "failed"
    assert item.reason == "no_tests_collected"


@needs_git
def test_merge_commits_are_ignored_by_regression_check(tmp_path: Path):
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "-b", "side", "main")
    repo.write("docs/notes.md", "notes\n")
    repo.commit("docs: add notes")
    repo.git("checkout", "-q", "work")
    repo.write("README.md", "# updated\n")
    repo.commit("docs: update readme")
    repo.git("merge", "--no-ff", "-m", "fix: merge side branch", "side")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is True
    assert report.total_fix_commits == 0


@needs_git
def test_hermetic_runner_scrubs_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    monkeypatch.setenv("PYTEST_ADDOPTS", "--nonexistent-pytest-flag-xyz")
    monkeypatch.setenv("AEGIS_SECRET_TOKEN", "should-not-leak")
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.write(
        "tests/test_app.py",
        "import os\nfrom src.app import compute\n\n"
        "def test_compute_and_env():\n"
        "    assert 'AEGIS_SECRET_TOKEN' not in os.environ\n"
        "    assert compute(2) == 3\n",
    )
    repo.commit("fix: compute adds 1")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is True
    assert report.commits[0].status == "passed"


@needs_git
def test_user_config_sets_tier_but_repo_config_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.commit("fix: change without test")

    # Repo config trying to set tier is ignored
    repo.write(".aegis/config.json", json.dumps({"v": 1, "regression": {"tier": "gate"}}))
    r1 = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert r1.tier == "warning"

    # User-scope config outside workspace sets tier="gate"
    user_cfg = tmp_path / "home" / ".aegis"
    user_cfg.mkdir(parents=True, exist_ok=True)
    (user_cfg / "config.json").write_text(json.dumps({"v": 1, "regression": {"tier": "gate"}}), encoding="utf-8")
    r2 = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert r2.tier == "gate"
    assert r2.blocking is True


@needs_git
def test_unresolvable_base_or_head_raises_regression_error(tmp_path: Path):
    repo = make_repo(tmp_path)
    with pytest.raises(RegressionError, match="base"):
        regression.check_ci_regressions(repo.root, "no-such-base", "HEAD")
    with pytest.raises(RegressionError, match="head"):
        regression.check_ci_regressions(repo.root, "main", "no-such-head")


@needs_git
def test_unrelated_histories_raise_regression_error(tmp_path: Path):
    repo = make_repo(tmp_path)
    repo.git("checkout", "-q", "--orphan", "orphan-branch")
    repo.git("rm", "-rfq", ".")
    repo.write("src/x.py", "x = 1\n")
    repo.commit("orphan")
    with pytest.raises(RegressionError, match="share no history"):
        regression.check_ci_regressions(repo.root, "main", "HEAD")
