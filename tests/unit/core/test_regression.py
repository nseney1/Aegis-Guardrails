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


def _count_runs(monkeypatch: pytest.MonkeyPatch) -> list:
    runs: list = []
    real = regression._run_pytest_in_snapshot

    def spy(snapshot, test_files, *args, **kwargs):
        runs.append(tuple(test_files))
        return real(snapshot, test_files, *args, **kwargs)

    monkeypatch.setattr(regression, "_run_pytest_in_snapshot", spy)
    return runs


@needs_git
def test_a_fix_with_only_a_go_test_is_unverified_not_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """R-evidence-26: Given a fix changing pkg/handler.go and pkg/handler_test.go, When regressions are
    checked, Then it is unverifiable/tests_not_pytest, nothing runs, and the report still passes."""
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    repo.write("pkg/handler.go", "package pkg\n\nfunc Handle() int { return 2 }\n")
    repo.write("pkg/handler_test.go", "package pkg\n\nimport \"testing\"\n\nfunc TestHandle(t *testing.T) {}\n")
    oid = repo.commit("fix: go handler")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    (item,) = report.commits
    assert (item.commit, item.status, item.reason) == (oid, "unverifiable", "tests_not_pytest")
    assert item.passed is True and item.test_files == ("pkg/handler_test.go",)
    assert runs == []
    assert report.passed is True and report.blocking is False and report.status == "pass"
    assert [(f.code, f.path) for f in report.findings] == [("tests_not_pytest", "pkg/handler_test.go")]
    assert "tests_not_pytest" in regression.UNVERIFIED_CODES


@needs_git
@pytest.mark.parametrize("extra", [None, "tests/data.json", "tests/conftest.py"], ids=["none", "data", "conftest"])
def test_a_fix_whose_only_test_change_is_not_a_test_stays_no_test_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra
):
    """Sad: a Python fix that edits only a fixture or conftest (or nothing) is still no_test_changes."""
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    if extra:
        repo.write(extra, "{}\n" if extra.endswith(".json") else "import pytest\n")
    repo.commit("fix: compute")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason) for c in report.commits] == [("failed", "no_test_changes")]
    assert runs == [] and report.passed is False


@needs_git
def test_a_fix_with_a_go_test_and_a_python_test_takes_the_python_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.write("pkg/handler_test.go", "package pkg\n")
    repo.write("tests/test_app.py", "from src.app import compute\n\ndef test_compute():\n    assert compute(2) == 3\n")
    repo.commit("fix: compute adds one")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason) for c in report.commits] == [("passed", "ok")]
    assert runs and all(files == ("tests/test_app.py",) for files in runs)


# ── Commit metadata: two git calls, never git log (R-evidence-24) ─────────────


def _metadata_calls(monkeypatch: pytest.MonkeyPatch) -> list:
    from aegis_core import gitsafe

    calls: list = []
    real = gitsafe.run

    def spy(args, *rest, **kwargs):
        calls.append(list(args))
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return calls


@needs_git
def test_thirty_commits_cost_at_most_two_metadata_git_calls_and_no_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Given 30 non-fix commits, When regressions are checked, Then rev-list/diff-tree/log calls number at
    most 2 (one per commit each before) and none is git log; every commit is still classified."""
    repo = make_repo(tmp_path)
    for n in range(30):
        repo.write(f"src/m{n}.py", f"x = {n}\n")
        repo.commit(f"feat: module {n}")
    calls = _metadata_calls(monkeypatch)

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    metadata = [c[0] for c in calls if c and c[0] in ("log", "rev-list", "diff-tree")]
    assert len(metadata) <= 2 and "log" not in metadata, metadata
    assert [u.source_files for u in report.untested_changes] == [(f"src/m{n}.py",) for n in range(30)]


@needs_git
@posix_only
def test_a_signed_commit_runs_no_gpg_program_the_repository_configured(tmp_path: Path):
    """Given a commit with a gpgsig header, log.showSignature=true and a marker-touching gpg.program in the
    repository config, When regressions are checked, Then the marker is absent and the commit classified."""
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.commit("fix: change without test")
    headers, _, message = repo.git("cat-file", "commit", "HEAD").partition("\n\n")
    signature = "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----"
    forged = repo.git("hash-object", "-t", "commit", "-w", "--stdin", stdin=f"{headers}\n{signature}\n\n{message}\n")
    repo.git("update-ref", "HEAD", forged)
    marker = tmp_path / "gpg-ran"
    program = tmp_path / "fake-gpg"
    program.write_bytes(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n".encode("utf-8"))
    program.chmod(0o755)
    repo.git("config", "log.showSignature", "true")
    repo.git("config", "gpg.program", str(program))
    subprocess.run(["git", "log", "-1"], cwd=str(repo.root), capture_output=True, env={**os.environ, **repo.home.env})
    assert marker.exists(), "the probe must make plain git log run the program"
    marker.unlink()

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert not marker.exists()
    assert [(c.commit, c.reason) for c in report.commits] == [(forged, "no_test_changes")]


@needs_git
def test_fix_signals_in_trailers_and_in_body_lines_are_read_as_before(tmp_path: Path):
    """Fixes:, Closes: and Aegis-No-Test: count as trailers and as body lines outside a trailer block,
    and a body line that looks like rev-list's record header does not split a record."""
    repo = make_repo(tmp_path)

    def change(n: int, message: str) -> str:
        repo.write(f"src/m{n}.py", f"x = {n}\n")
        return repo.commit(message)

    trailer = change(1, "refactor: one\n\nFixes: #1")
    in_prose = change(2, "refactor: two\n\nCloses: #8 in prose\n\nA closing paragraph of prose.")
    nt_line = change(3, "fix: three\n\nWhy it changed.\nAegis-No-Test: covered by the e2e suite\nMore prose.\n")
    lookalike = change(4, "refactor: four\n\ncommit 0123456789abcdef0123456789abcdef01234567\nFixes: #4")
    plain = change(5, "refactor: five\n\nNo issue here.")
    nt_trailer = change(6, "fix: six\n\nAegis-No-Test: trailer reason")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert {c.commit: (c.fixes, c.no_test_reason) for c in report.commits} == {
        trailer: (("#1",), None),
        in_prose: (("#8 in prose",), None),
        nt_line: ((), "covered by the e2e suite"),
        lookalike: (("#4",), None),
        nt_trailer: ((), "trailer reason"),
    }
    assert [u.commit for u in report.untested_changes] == [plain]


@needs_git
def test_batched_metadata_keeps_each_commits_paths(tmp_path: Path):
    """A file named by 40 hex characters, an empty commit, a rename (D + A without -M), a deletion and a
    range starting at the root commit give each commit exactly its own changed and present paths."""
    repo = make_repo(tmp_path)
    hexname = "0123456789abcdef0123456789abcdef01234567"
    repo.write(hexname, "data\n")
    repo.write("src/x.py", "x = 1\n")
    first = repo.commit("feat: hex-named file")
    empty = repo.commit("chore: nothing", allow_empty=True)
    repo.git("mv", "src/app.py", "src/core.py")
    moved = repo.commit("refactor: move app")
    (repo.root / hexname).unlink()
    gone = repo.commit("chore: drop the hex file")

    metas = regression._commits_meta(str(repo.root), "main", "HEAD")
    assert [(m.oid, m.changed_files, m.present_files) for m in metas] == [
        (first, (hexname, "src/x.py"), (hexname, "src/x.py")),
        (empty, (), ()),
        (moved, ("src/app.py", "src/core.py"), ("src/core.py",)),
        (gone, (hexname,), ()),
    ]


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
def test_no_config_or_argument_raises_the_tier_above_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """R-evidence-29: T5 stays at warning until T4 promotes it. Neither the repository's nor the user's
    regression.tier changes the tier, and the tier= argument is gone."""
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.commit("fix: change without test")

    repo.write(".aegis/config.json", json.dumps({"v": 1, "regression": {"tier": "gate"}}))
    user_cfg = tmp_path / "home" / ".aegis"
    user_cfg.mkdir(parents=True, exist_ok=True)
    (user_cfg / "config.json").write_text(json.dumps({"v": 1, "regression": {"tier": "gate"}}), encoding="utf-8")
    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert (report.tier, report.passed, report.blocking, report.status) == ("warning", False, False, "warning")
    with pytest.raises(TypeError):
        regression.check_ci_regressions(repo.root, "main", "HEAD", tier="gate")
    assert not hasattr(regression, "VALID_TIERS")


def test_a_gate_tier_report_still_blocks_for_a_future_promotion():
    failed = regression.CommitRegression("a" * 40, "fix: x", "failed", "no_test_changes", False, False)
    assert regression.RegressionReport("b", "h", "m", tier="gate", commits=(failed,)).blocking is True
    assert regression.RegressionReport("b", "h", "m", commits=(failed,)).blocking is False


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
