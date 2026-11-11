"""Unit tests for ``aegis_core.regression`` (v4.3 spec §3 T5): classifiers, edges, and sad paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tracemalloc
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


# ── R-evidence-30: the trigger is the spec's, a fix subject or a Fixes trailer ──


@pytest.mark.parametrize("scope,is_fix", [("doc", True), ("test", True), ("docs", False), ("tests", False)])
def test_only_the_spec_scopes_exempt_a_fix_subject(scope: str, is_fix: bool):
    assert parse_fix_subject(f"fix({scope}): correct docstring") == (is_fix, scope)
    assert is_fix_commit(f"fix({scope}): correct docstring", [], ["src/x.py"]) is is_fix


@needs_git
def test_a_fixes_line_outside_the_trailer_block_or_a_closes_trailer_is_no_fix_signal(tmp_path: Path):
    """Given a refactor whose Fixes: line sits in a body paragraph that is not the trailer block, and a
    chore whose only trailer is Closes:, When regressions are checked, Then neither is a fix commit and
    both are untested changes."""
    repo = make_repo(tmp_path)
    repo.write("src/x.py", "x = 1\n")
    tidy = repo.commit("refactor: tidy\n\nFixes: #1\n\nA closing paragraph of prose.")
    repo.write("src/y.py", "y = 1\n")
    bump = repo.commit("chore: bump\n\nCloses: #2")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.total_fix_commits == 0 and report.commits == ()
    assert [u.commit for u in report.untested_changes] == [tidy, bump]


@needs_git
def test_a_fix_subject_with_a_fixes_trailer_and_its_test_is_a_passing_fix_commit(tmp_path: Path):
    repo = make_repo(tmp_path)
    fixed = _fix(repo, "fix: a\n\nFixes: #3", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status, c.reason) for c in report.commits] == [(fixed, "passed", "ok")]
    assert report.untested_changes == ()


@needs_git
def test_aegis_no_test_is_read_from_its_trailer_only(tmp_path: Path):
    """Given an Aegis-No-Test line in a prose paragraph and one in the trailer block, When regressions
    are checked, Then only the trailer is the commit's reason."""
    repo = make_repo(tmp_path)
    repo.write("src/x.py", "x = 1\n")
    prose = repo.commit("fix: one\n\nWhy it changed.\nAegis-No-Test: covered by the e2e suite\nMore prose.\n")
    repo.write("src/y.py", "y = 1\n")
    trailer = repo.commit("fix: two\n\nAegis-No-Test: trailer reason")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.no_test_reason) for c in report.commits] == [(prose, None), (trailer, "trailer reason")]


@needs_git
def test_a_fix_doc_commit_without_a_test_is_judged_and_a_fix_docs_commit_is_not(tmp_path: Path):
    repo = make_repo(tmp_path)
    repo.write("src/x.py", "x = 1\n")
    doc = repo.commit("fix(doc): correct docstring")
    repo.write("src/y.py", "y = 1\n")
    repo.commit("fix(docs): correct docstring")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status, c.reason) for c in report.commits] == [(doc, "failed", "no_test_changes")]
    assert (report.tier, report.blocking, report.status) == ("warning", False, "warning")


@needs_git
@needs_signing
def test_a_failing_fix_with_a_signed_exemption_looks_it_up_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Sad path of the lookup rule: a fix commit that failed looks up its exemption, once, and is exempted."""
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, signer_pub=human_pub)
    fix = _fix(repo, "fix: hotfix without test\n\nAegis-No-Test: verified manually", {"src/app.py": APP.format(1)})
    repo.commit(human_gate.exemption_message(fix, "verified manually"), sign_key=human, allow_empty=True)
    looked_up: list = []
    real_finder = human_gate.exemption_finder

    def finder(root, head, base_ref):
        find = real_finder(root, head, base_ref)
        return lambda oid: looked_up.append(oid) or find(oid)

    monkeypatch.setattr(human_gate, "exemption_finder", finder)

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status) for c in report.commits] == [(fix, "exempted")]
    assert looked_up == [fix]


@needs_git
@pytest.mark.parametrize("failure", ["raises", "exit"])
def test_a_git_failure_reaches_the_caller_as_a_git_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str):
    """GitError propagates; RegressionError is only an unresolvable or unrelated range."""
    from aegis_core import gitsafe

    repo = make_repo(tmp_path)
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1)})
    real = gitsafe.run

    def failing(args, *rest, **kwargs):
        if list(args[:2]) == ["rev-list", "--reverse"]:
            if failure == "raises":
                raise gitsafe.GitError("git rev-list timed out after 60s")
            return subprocess.CompletedProcess(["git", *args], 128, b"", b"fatal: bad\n   object  ")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", failing)
    with pytest.raises(gitsafe.GitError) as info:
        regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert not isinstance(info.value, RegressionError)
    assert str(info.value) == ("git rev-list timed out after 60s" if failure == "raises"
                               else "git rev-list failed: fatal: bad object")


def test_the_t5_snapshot_runner_is_testexec_s_and_regression_reaches_no_private_name():
    """testexec.run_pytest_snapshot runs T5's pytest; regression reaches no private helper of another
    aegis module, and testexec does not import regression (no cycle)."""
    import ast

    from aegis_core import testexec

    def private_reaches(module) -> list:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        attrs = [f"{n.value.id}.{n.attr}" for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                 and isinstance(n.value, ast.Name) and n.attr.startswith("_") and not n.attr.startswith("__")
                 and n.value.id in ("testexec", "config", "gitsafe", "governance", "human_gate", "match", "rule_integrity")]
        names = [f"{n.module}.{a.name}" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                 and (n.module or "").startswith("aegis_core") for a in n.names if a.name.startswith("_")]
        return attrs + names

    def imports_regression(module) -> bool:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        return any((isinstance(n, ast.ImportFrom) and (n.module == "aegis_core.regression"
                                                      or (n.module == "aegis_core" and any(a.name == "regression" for a in n.names))))
                   or (isinstance(n, ast.Import) and any(a.name == "aegis_core.regression" for a in n.names))
                   for n in ast.walk(tree))

    assert callable(testexec.run_pytest_snapshot)
    assert private_reaches(regression) == []
    assert not imports_regression(testexec)


@pytest.mark.parametrize("body,passed", [("def test_ok():\n    assert True\n", True),
                                         ("def test_ok():\n    assert False\n", False)], ids=["pass", "fail"])
def test_the_snapshot_runner_exits_zero_for_a_passing_file_and_non_zero_for_a_failing_one(
    tmp_path: Path, body: str, passed: bool
):
    from aegis_core import testexec

    snapshot, workspace = tmp_path / "snap", tmp_path / "ws"
    (snapshot / "tests").mkdir(parents=True)
    workspace.mkdir()
    (snapshot / "tests" / "test_x.py").write_bytes(body.encode("utf-8"))

    outcome = testexec.run_pytest_snapshot(snapshot, ["tests/test_x.py"], workspace, tmp_path / "run", 120.0)
    assert (outcome.exit_code == 0) is passed and outcome.timed_out is False
    assert (outcome.passed_ids if passed else outcome.failed_ids) == frozenset({"tests.test_x::test_ok"})
    assert (outcome.failed_ids if passed else outcome.passed_ids) == frozenset()


@needs_git
def test_a_fix_to_a_module_named_like_a_document_is_judged(tmp_path: Path):
    """R-evidence-25: Given a fix commit touching only src/security.py, When regressions are checked,
    Then it is a fix commit failing with no_test_changes (it used to be read as documentation)."""
    repo = make_repo(tmp_path)
    repo.write("src/security.py", "def harden() -> bool:\n    return True\n")
    oid = repo.commit("fix: harden security module")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status, c.reason) for c in report.commits] == [(oid, "failed", "no_test_changes")]
    assert [(f.code, f.path) for f in report.findings] == [("no_test_changes", "src/security.py")]


def _count_runs(monkeypatch: pytest.MonkeyPatch) -> list:
    from aegis_core import testexec

    runs: list = []
    real = testexec.run_pytest_snapshot

    def spy(snapshot, test_files, *args, **kwargs):
        runs.append(tuple(test_files))
        return real(snapshot, test_files, *args, **kwargs)

    monkeypatch.setattr(testexec, "run_pytest_snapshot", spy)
    return runs


@needs_git
def test_a_fix_with_only_a_go_test_is_unverified_not_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """R-evidence-26: Given a fix changing pkg/handler.go and pkg/handler_test.go, When regressions are
    checked, Then absent native definitions are explicit, no pytest runs, and the report still passes."""
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    repo.write("pkg/handler.go", "package pkg\n\nfunc Handle() int { return 2 }\n")
    repo.write("pkg/handler_test.go", "package pkg\n\nimport \"testing\"\n\nfunc TestHandle(t *testing.T) {}\n")
    oid = repo.commit("fix: go handler")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    (item,) = report.commits
    assert (item.commit, item.status, item.reason) == (oid, "unverifiable", "no_driver")
    assert item.passed is True
    assert runs == []
    assert report.passed is True and report.blocking is False and report.status == "pass"
    assert [(f.code, f.path) for f in report.findings] == [("no_driver", "pkg/handler_test.go")]
    assert "no_driver" in regression.UNVERIFIED_CODES


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
def test_a_python_transition_does_not_hide_an_unavailable_go_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    repo.write("src/app.py", "def compute(x: int) -> int:\n    return x + 1\n")
    repo.write("pkg/handler_test.go", "package pkg\n")
    repo.write("tests/test_app.py", "from src.app import compute\n\ndef test_compute():\n    assert compute(2) == 3\n")
    repo.commit("fix: compute adds one")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason) for c in report.commits] == [("unverifiable", "no_driver")]
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
def test_fix_signals_are_read_from_the_trailer_block_only(tmp_path: Path):
    """R-evidence-30 (rewrites the body-line reading this test pinned before): Fixes: and Aegis-No-Test:
    count only in the trailer block and Closes: never does; a body line that looks like rev-list's record
    header does not split a record."""
    repo = make_repo(tmp_path)

    def change(n: int, message: str) -> str:
        repo.write(f"src/m{n}.py", f"x = {n}\n")
        return repo.commit(message)

    trailer = change(1, "refactor: one\n\nFixes: #1")
    in_prose = change(2, "refactor: two\n\nCloses: #8 in prose\n\nA closing paragraph of prose.")
    nt_line = change(3, "fix: three\n\nWhy it changed.\nAegis-No-Test: covered by the e2e suite\nMore prose.\n")
    lookalike = change(4, "refactor: four\n\ncommit 0123456789abcdef0123456789abcdef01234567\n\nFixes: #4")
    plain = change(5, "refactor: five\n\nNo issue here.")
    nt_trailer = change(6, "fix: six\n\nAegis-No-Test: trailer reason")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert {c.commit: c.no_test_reason for c in report.commits} == {
        trailer: None,
        nt_line: None,
        lookalike: None,
        nt_trailer: "trailer reason",
    }
    assert [u.commit for u in report.untested_changes] == [in_prose, plain]


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
def test_a_module_that_fails_collection_on_base_counts_as_fail_to_pass(tmp_path: Path):
    """R-evidence-27: a test module whose top-level import of a new symbol fails on base fails there, so a
    test in it that passes at head is fail-to-pass. (The old rule rejected this but accepted the same
    test with a lazy import, so it only ever blocked honest tests.)"""
    repo = make_repo(tmp_path)
    repo.write(
        "src/app.py",
        "def compute(x: int) -> int:\n    return x + 1\n\n"
        "def brand_new_symbol() -> int:\n    return 42\n",
    )
    repo.write(
        "tests/test_app.py",
        "from src.app import brand_new_symbol\n\n"
        "def test_new_symbol():\n"
        "    assert brand_new_symbol() == 42\n",
    )
    repo.commit("fix: add the missing symbol")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert report.passed is True
    item = report.commits[0]
    assert (item.status, item.reason) == ("passed", "ok")
    assert item.fail_to_pass_tests == ("tests.test_app::test_new_symbol",)


# ── Fail-to-pass at PR level: two runs, head against merge base (R-evidence-27) ──


def _fix(repo: hg.Repo, message: str, files: Dict[str, str]) -> str:
    for path, text in files.items():
        repo.write(path, text)
    return repo.commit(message)


APP = "def compute(x: int) -> int:\n    return x + {}\n"
TEST_COMPUTE = "from src.app import compute\n\ndef test_compute():\n    assert compute(2) == 3\n"


@needs_git
def test_a_fix_whose_test_imports_a_helper_added_earlier_in_the_pr_passes_in_two_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    _fix(repo, "feat: add clamp helper", {"src/util.py": "def clamp(x: int) -> int:\n    return x\n"})
    fix = _fix(repo, "fix: clamp negative values", {
        "src/util.py": "def clamp(x: int) -> int:\n    return max(x, 0)\n",
        "tests/test_util.py": "from src.util import clamp\n\ndef test_clamp_negative():\n    assert clamp(-1) == 0\n",
    })

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.commit, c.status, c.fail_to_pass_tests) for c in report.commits] == [
        (fix, "passed", ("tests.test_util::test_clamp_negative",))]
    assert len(runs) == 2


@needs_git
def test_two_fixes_one_failing_an_assertion_one_failing_collection_on_base_both_pass_in_two_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """One module that cannot import on base must not hide the other module's base result."""
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_one.py": TEST_COMPUTE})
    _fix(repo, "fix: add the missing brand_new", {
        "src/app.py": APP.format(1) + "\ndef brand_new() -> int:\n    return 42\n",
        "tests/test_two.py": "from src.app import brand_new\n\ndef test_brand_new():\n    assert brand_new() == 42\n",
    })

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [c.status for c in report.commits] == ["passed", "passed"]
    assert runs == [("tests/test_one.py", "tests/test_two.py")] * 2


@needs_git
def test_two_tautological_fixes_cost_two_runs_and_pass_on_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    _fix(repo, "fix: one", {"src/app.py": APP.format(1), "tests/test_one.py": "def test_one():\n    assert True\n"})
    _fix(repo, "fix: two", {"src/app.py": APP.format(2), "tests/test_two.py": "def test_two():\n    assert True\n"})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason) for c in report.commits] == [("failed", "passed_on_base")] * 2
    assert len(runs) == 2


@needs_git
def test_a_scratch_path_that_resolves_elsewhere_still_attributes_the_fix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Review F1: Given a temporary directory reached through a link (as a Windows 8.3 short TEMP is a
    second spelling of its long path), When regressions are checked, Then pytest starts in the very
    directory string it gets as --rootdir and the fix commit is attributed its fail-to-pass test. Windows
    keeps a child's cwd string verbatim, so a cwd spelled unlike --rootdir leaves the JUnit classname
    empty there and every fix reads no_tests_collected."""
    import tempfile

    from aegis_core import testexec
    from conftest import symlink_or_skip

    repo = make_repo(tmp_path)
    fix = _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    real, link = tmp_path / "real-tmp", tmp_path / "linked-tmp"
    real.mkdir()
    symlink_or_skip(real, link, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(link))
    started: list = []
    real_run = testexec.run_tests

    def spy(argv, cwd, *args, **kwargs):
        started.append((str(cwd), next(a.partition("=")[2] for a in argv if str(a).startswith("--rootdir="))))
        return real_run(argv, cwd, *args, **kwargs)

    monkeypatch.setattr(testexec, "run_tests", spy)

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert len(started) == 2 and all(cwd == rootdir for cwd, rootdir in started), started
    assert [(c.commit, c.status, c.fail_to_pass_tests) for c in report.commits] == [
        (fix, "passed", ("tests.test_app::test_compute",))]


@needs_git
def test_a_fix_broken_by_a_later_commit_fails_on_head(tmp_path: Path):
    """The fix passes at its own commit, but the pull request's head is what lands."""
    repo = make_repo(tmp_path)
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    _fix(repo, "feat: compute adds two", {"src/app.py": APP.format(2)})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason, c.fail_to_pass_tests) for c in report.commits] == [("failed", "failed_on_head", ())]


@needs_git
def test_a_test_run_that_times_out_says_timeout(tmp_path: Path):
    repo = make_repo(tmp_path)
    _fix(repo, "fix: compute adds one", {
        "src/app.py": APP.format(1),
        "tests/test_slow.py": "import time\n\ndef test_slow():\n    time.sleep(60)\n",
    })

    report = regression.check_ci_regressions(repo.root, "main", "HEAD", timeout=1.5)
    assert [(c.status, c.reason) for c in report.commits] == [("failed", "timeout")]
    assert report.findings[0].code == "timeout"


@needs_git
def test_a_fix_whose_test_a_later_commit_deletes_collects_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_gone.py": TEST_COMPUTE})
    (repo.root / "tests" / "test_gone.py").unlink()
    repo.commit("test: drop the new test")

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.reason) for c in report.commits] == [("failed", "no_tests_collected")]
    assert runs == []


@needs_git
def test_a_syntax_error_in_one_fixs_test_fails_only_that_fix(tmp_path: Path):
    repo = make_repo(tmp_path)
    bad = _fix(repo, "fix: other", {"src/other.py": "y = 1\n", "tests/test_bad.py": "def test_bad(:\n    pass\n"})
    good = _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_good.py": TEST_COMPUTE})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert {c.commit: (c.status, c.reason) for c in report.commits} == {
        bad: ("failed", "failed_on_head"), good: ("passed", "ok")}


@needs_git
def test_accepted_trade_off_a_tautological_fix_sharing_a_real_fixs_test_file_shares_its_credit(tmp_path: Path):
    """Accepted at warning tier (R-evidence-27): credit is per test file, so the second commit, which only
    adds `assert True` to the same file, passes on the first commit's fail-to-pass test."""
    repo = make_repo(tmp_path)
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    _fix(repo, "fix: other", {"src/other.py": "y = 1\n",
                              "tests/test_app.py": TEST_COMPUTE + "\ndef test_trivial():\n    assert True\n"})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [(c.status, c.fail_to_pass_tests) for c in report.commits] == [
        ("passed", ("tests.test_app::test_compute",))] * 2


@needs_git
def test_no_python_test_to_judge_starts_no_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = make_repo(tmp_path)
    runs = _count_runs(monkeypatch)
    _fix(repo, "fix: go handler", {"pkg/handler.go": "package pkg\n", "pkg/handler_test.go": "package pkg\n"})
    _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1)})

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert [c.reason for c in report.commits] == ["no_driver", "no_test_changes"]
    assert runs == []


def _fake_outcomes(monkeypatch: pytest.MonkeyPatch, head: Any, base: Any) -> list:
    """Replace the pytest runner: a snapshot holding the head's src/app.py gets ``head``, else ``base``."""
    from aegis_core import testexec

    seen: list = []

    def fake(snapshot, test_files, *_args, **_kwargs):
        at_head = (snapshot / "src" / "app.py").read_text(encoding="utf-8") == APP.format(1)
        seen.append("head" if at_head else "base")
        passed, failed, errors = head if at_head else base
        return testexec.PytestOutcome(0, False, frozenset(passed), frozenset(failed), frozenset(errors))

    monkeypatch.setattr(testexec, "run_pytest_snapshot", fake)
    return seen


@needs_git
def test_failed_fixes_share_one_exemption_discovery(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    fixes = [_fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i)}) for i in range(1, 4)]
    for i in range(8):
        repo.commit(f"chore: unrelated {i}", allow_empty=True)
    calls = _metadata_calls(monkeypatch)
    batches = _commit_batch_reads(monkeypatch)

    report = regression.check_ci_regressions(repo.root, "main")

    assert [(c.commit, c.status, c.exemption_code) for c in report.commits] == [
        (oid, "failed", None) for oid in fixes]
    assert [oid for chunk in batches for oid in chunk] == repo.git("rev-list", "main..HEAD").splitlines()
    assert len(batches) == 1
    assert sum(c[:2] == ["cat-file", "--batch-check"] for c in calls) == 1
    assert sum(c[:2] == ["cat-file", "--batch"] for c in calls) == 1
    assert sum(c[0] == "rev-list" for c in calls) == 2
    assert sum(c[0] == "log" for c in calls) <= 2


@needs_git
@pytest.mark.parametrize("phase", ["preflight", "early-chunk", "later-chunk"])
@pytest.mark.parametrize("fault", ["error", "timeout"])
def test_exemption_discovery_timeout_is_not_retried_for_each_fix(tmp_path, monkeypatch, phase, fault):
    from aegis_core import approval_shape, gitsafe

    repo = make_repo(tmp_path)
    fixes = [_fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i)}) for i in range(1, 4)]
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += "\n" + "".join(f"Aegis-Exempt-Test: {fix} reviewed by hand\n" for fix in fixes)
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
    git_calls = _metadata_calls(monkeypatch)
    calls = []
    chunks = []
    preflights = []
    real_read = gitsafe.read_blobs
    real_sizes = gitsafe.blob_sizes
    real_iter = gitsafe.iter_objects
    error = "git cat-file timed out" if fault == "timeout" else "private discovery failure"

    def fail():
        calls.append(len(git_calls))
        raise gitsafe.GitError(error)

    def sizes(cwd, oids, **kw):
        if kw.get("kind") == "commit":
            preflights.append(phase)
            if phase == "preflight":
                fail()
        return real_sizes(cwd, oids, **kw)

    def read(cwd, oids, **kw):
        if kw.get("kind") == "commit":
            chunks.append(list(oids))
            if len(chunks) == (2 if phase == "later-chunk" else 1):
                fail()
        return real_read(cwd, oids, **kw)

    def one_per_chunk(cwd, oids, **kw):
        return real_iter(cwd, oids, byte_budget=1, **kw)

    monkeypatch.setattr(gitsafe, "blob_sizes", sizes)
    monkeypatch.setattr(gitsafe, "read_blobs", read)
    monkeypatch.setattr(gitsafe, "iter_objects", one_per_chunk)
    report = regression.check_ci_regressions(repo.root, "main")
    assert len(calls) == 1
    assert git_calls[calls[0]:] == [], "failed discovery must not start diagnostic subprocesses"
    assert len(preflights) == 1
    assert len(chunks) == {"preflight": 0, "early-chunk": 1, "later-chunk": 2}[phase]
    assert [(c.reason, c.exemption_code) for c in report.commits] == [("no_test_changes", None)] * 3
    assert error not in json.dumps(report.as_dict(repo.root))


@needs_git
def test_refusal_scan_failure_is_terminal_for_the_report(tmp_path, monkeypatch):
    from aegis_core import gitsafe

    repo = make_repo(tmp_path)
    for i in range(3):
        _fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i + 1)})
    calls = []
    real = gitsafe.run

    def timeout(args, *rest, **kwargs):
        if args[0] == "log" and any(arg.startswith("--grep=") for arg in args):
            calls.append(args)
            raise gitsafe.GitError("private diagnostic timeout")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", timeout)
    report = regression.check_ci_regressions(repo.root, "main")
    assert [(c.reason, c.exemption_code) for c in report.commits] == [("no_test_changes", None)] * 3
    assert len(calls) == 1
    assert "private diagnostic timeout" not in json.dumps(report.as_dict(repo.root))


@needs_git
def test_refusal_scan_has_one_shared_deadline(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import gitsafe

    repo = make_repo(tmp_path)
    for i in range(3):
        _fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i + 1)})
    now = [100.0]
    tick = regression._GIT_TIMEOUT_S / 2 + 1
    timeouts = []
    real = gitsafe.run

    def elapsed(args, *rest, **kwargs):
        if args[0] == "log":
            timeouts.append(kwargs["timeout"])
            now[0] += tick
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(regression, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(gitsafe, "run", elapsed)
    report = regression.check_ci_regressions(repo.root, "main")
    assert [c.exemption_code for c in report.commits] == [None] * 3
    assert timeouts == pytest.approx([regression._GIT_TIMEOUT_S, regression._GIT_TIMEOUT_S - tick])


@needs_git
@needs_signing
@pytest.mark.parametrize("exempt_first", [False, True])
@pytest.mark.parametrize("failure", ["grep_error", "deadline", "read_limit"])
def test_diagnostic_failure_preserves_independent_primary_exemptions(tmp_path, monkeypatch, exempt_first, failure):
    from types import SimpleNamespace
    from aegis_core import gitsafe

    key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, public)
    names = ("exempt", "plain") if exempt_first else ("plain", "exempt")
    fixes = {name: _fix(repo, f"fix: {name}", {f"src/{name}.py": "value = 1\n"}) for name in names}
    repo.commit(human_gate.exemption_message(fixes["exempt"], "reviewed manually"), sign_key=key, allow_empty=True)
    now = [100.0]
    calls = []
    real = gitsafe.run

    def fail_diagnostic(args, *rest, **kwargs):
        if args[0] == "log" and any(arg.startswith("--grep=") for arg in args):
            calls.append(args)
            if failure == "grep_error":
                raise gitsafe.GitError("private diagnostic failure")
            if failure == "deadline":
                now[0] += kwargs["timeout"] + 1
        if failure == "read_limit" and args[:2] == ["cat-file", "-s"]:
            return subprocess.CompletedProcess(args, 0, f"{1 << 30}\n".encode(), b"")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(regression, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(gitsafe, "run", fail_diagnostic)
    report = regression.check_ci_regressions(repo.root, "main")

    assert {c.commit: (c.status, c.exemption_code) for c in report.commits} == {
        fixes["plain"]: ("failed", None), fixes["exempt"]: ("exempted", None)}
    assert len(calls) == 1
    assert "private diagnostic failure" not in json.dumps(report.as_dict(repo.root))


def _refuse_exemption_at_git_boundary(monkeypatch, approval, code):
    from aegis_core import gitsafe

    real = gitsafe.run

    def refuse(args, *rest, **kwargs):
        if code == "unresolved" and args == ["rev-parse", "--verify", "--quiet", f"{approval}^{{commit}}"]:
            return subprocess.CompletedProcess(args, 1, b"", b"private resolution failure")
        if args[-1] == approval and "--format=%G?%n%GF" in args:
            status = {"unverifiable": "E", "untrusted_signature": "U", "bad_signature": "B"}.get(code)
            if status is not None:
                return subprocess.CompletedProcess(args, 0, f"{status}\n".encode(), b"")
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", refuse)


@needs_git
@needs_signing
@pytest.mark.parametrize("exempt_first", [False, True])
@pytest.mark.parametrize("code", ["unresolved", "unverifiable"])
def test_one_primary_rejection_preserves_other_fixes_exemptions(tmp_path, monkeypatch, exempt_first, code):
    key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, public)
    names = ("exempt", "refused") if exempt_first else ("refused", "exempt")
    fixes = {name: _fix(repo, f"fix: {name}", {f"src/{name}.py": "value = 1\n"}) for name in names}
    approval = repo.commit(human_gate.exemption_message(fixes["refused"], "reviewed manually"), allow_empty=True)
    repo.commit(human_gate.exemption_message(fixes["exempt"], "reviewed manually"), sign_key=key, allow_empty=True)
    _refuse_exemption_at_git_boundary(monkeypatch, approval, code)
    assert human_gate.verify_test_exemption(repo.root, approval, fixes["refused"], "main").code == code

    report = regression.check_ci_regressions(repo.root, "main")

    assert {c.commit: (c.status, c.exemption_code) for c in report.commits} == {
        fixes["refused"]: ("failed", code), fixes["exempt"]: ("exempted", None)}
    assert "private resolution failure" not in json.dumps(report.as_dict(repo.root))


@needs_git
@needs_signing
def test_primary_verification_time_does_not_expire_in_memory_diagnostics(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import approval_shape, gitsafe

    _key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, public)
    plain = _fix(repo, "fix: plain", {"src/plain.py": "value = 1\n"})
    refused = _fix(repo, "fix: refused", {"src/refused.py": "value = 1\n"})
    approval = repo.commit(human_gate.exemption_message(refused, "reviewed manually"), allow_empty=True)
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message + f"\nAegis-Exempt-Test: {refused} checked manually\n")
    now = [100.0]
    calls = []
    real = gitsafe.run

    def slow_primary(args, *rest, **kwargs):
        if args[-1] == approval and "--format=%G?%n%GF" in args:
            calls.append(args)
            now[0] += regression._GIT_TIMEOUT_S + 1
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(regression, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(gitsafe, "run", slow_primary)
    report = regression.check_ci_regressions(repo.root, "main")

    assert [(c.commit, c.exemption_code) for c in report.commits] == [(plain, None), (refused, "message_too_large")]
    assert len(calls) == 1


@needs_git
def test_refusal_index_reads_an_oversized_candidate_once_for_all_fixes(tmp_path, monkeypatch):
    from aegis_core import approval_shape

    repo = make_repo(tmp_path)
    fixes = [_fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i)}) for i in range(1, 4)]
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += "\n" + "".join(f"Aegis-Exempt-Test: {fix} reviewed by hand\n" for fix in fixes)
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
    approval = repo.head()
    calls = _metadata_calls(monkeypatch)
    batches = _commit_batch_reads(monkeypatch)

    report = regression.check_ci_regressions(repo.root, "main")

    assert [c.exemption_code for c in report.commits] == ["message_too_large"] * len(fixes)
    # One pinned discovery read plus one diagnostic read, independent of the number of named fixes.
    assert sum(approval in chunk for chunk in batches) == 1
    assert sum(c[:3] == ["cat-file", "commit", approval] for c in calls) == 1
    logs = [c for c in calls if c[0] == "log"]
    assert len(logs) == 2
    filtered, = [c for c in logs if any(arg.startswith("--grep=") for arg in c)]
    assert not any(arg.startswith("--max-count") for arg in filtered)


@needs_git
def test_discovery_failure_does_not_start_a_diagnostic_reread(tmp_path, monkeypatch):
    from aegis_core import approval_shape, gitsafe

    repo = make_repo(tmp_path)
    fixes = [_fix(repo, f"fix: constant {i}", {"src/app.py": APP.format(i)}) for i in range(1, 4)]
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += "\n" + "".join(f"Aegis-Exempt-Test: {fix} reviewed by hand\n" for fix in fixes)
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
    approval = repo.head()
    reads = []
    git_calls = _metadata_calls(monkeypatch)
    real = gitsafe.read_blobs

    def timeout(cwd, oids, **kwargs):
        requested = list(oids)
        if kwargs.get("kind") == "commit" and approval in requested:
            reads.append((requested, len(git_calls)))
            raise gitsafe.GitError("private message timeout")
        return real(cwd, requested, **kwargs)

    monkeypatch.setattr(gitsafe, "read_blobs", timeout)
    report = regression.check_ci_regressions(repo.root, "main")
    assert len(reads) == 1
    assert git_calls[reads[0][1]:] == [], "failed discovery must not start a diagnostic reread"
    assert [c.exemption_code for c in report.commits] == [None] * len(fixes)
    assert "private message timeout" not in json.dumps(report.as_dict(repo.root))


@needs_git
def test_refusal_index_checks_total_object_size_before_reading_content(tmp_path, monkeypatch):
    from aegis_core import approval_shape, gitsafe

    repo = make_repo(tmp_path)
    fix = _fix(repo, "fix: diagnostic limit", {"src/app.py": APP.format(1)})
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += f"\nAegis-Exempt-Test: {fix} reviewed by hand\n"
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
    approval = repo.head()
    reads = []
    batches = _commit_batch_reads(monkeypatch)
    real = gitsafe.run

    def oversized(args, *rest, **kwargs):
        if args[:2] == ["cat-file", "-s"]:
            return subprocess.CompletedProcess(args, 0, f"{1 << 30}\n".encode(), b"")
        if args[:3] == ["cat-file", "commit", approval]:
            reads.append(args)
        return real(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", oversized)
    report = regression.check_ci_regressions(repo.root, "main")
    assert report.commits[0].exemption_code is None
    assert sum(approval in chunk for chunk in batches) == 1
    assert reads == []  # Only batched discovery reads content; diagnostics stop at the size query.


@needs_git
@needs_signing
@pytest.mark.parametrize("newer_oversized", [True, False])
@pytest.mark.parametrize("diagnostic_code", ["message_too_large", "message_line_too_long"])
@pytest.mark.parametrize("primary_code", ["unsigned", "unresolved", "unverifiable", "no_allowed_signers",
                                         "untrusted_signature", "bad_signature", "accept_reserved",
                                         "multiple_trailers", "invalid_message_shape"])
def test_refused_exemptions_keep_newest_first_order_across_both_indexes(
        tmp_path, monkeypatch, newer_oversized, diagnostic_code, primary_code):
    from aegis_core import approval_shape

    _key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, None if primary_code == "no_allowed_signers" else public)
    fix = _fix(repo, "fix: newest refusal", {"src/app.py": APP.format(1)})
    oversized = ("prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1) if diagnostic_code == "message_too_large"
                 else "x" * (approval_shape.MAX_LINE_LENGTH + 1) + "\n")
    oversized += f"\nAegis-Exempt-Test: {fix} reviewed by hand\n"
    ordinary = human_gate.exemption_message(fix, "reviewed manually")
    if primary_code == "accept_reserved":
        ordinary += "Aegis-Accept: reserved\n"
    elif primary_code == "multiple_trailers":
        ordinary += f"Aegis-Exempt-Test: {fix} reviewed again\n"
    elif primary_code == "invalid_message_shape":
        ordinary += " continued signed value\n"
    for message in ((ordinary, oversized) if newer_oversized else (oversized, ordinary)):
        repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
        if message == ordinary:
            approval = repo.head()
    # A resolution failure for this candidate must not also hide the report's head.
    repo.commit("chore: finish refusal ordering fixture", allow_empty=True)
    _refuse_exemption_at_git_boundary(monkeypatch, approval, primary_code)
    assert human_gate.verify_test_exemption(repo.root, approval, fix, "main").code == primary_code

    item, = regression.check_ci_regressions(repo.root, "main").commits

    assert (item.status, item.exemption_code) == ("failed", diagnostic_code if newer_oversized else primary_code)


@needs_git
def test_oversized_exemption_bounds_precede_a_missing_reason(tmp_path):
    from aegis_core import approval_shape

    repo = make_repo(tmp_path)
    fix = _fix(repo, "fix: bounds refusal", {"src/app.py": APP.format(1)})
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += f"\nAegis-Exempt-Test: {fix} \n"
    repo.git("commit", "-q", "--allow-empty", "--cleanup=verbatim", "-F", "-", stdin=message)

    item, = regression.check_ci_regressions(repo.root, "main").commits

    assert (item.status, item.exemption_code) == ("failed", "message_too_large")


@needs_git
@needs_signing
@pytest.mark.parametrize("code", ["message_too_large", "message_line_too_long", "invalid_message_shape"])
def test_refused_exemption_diagnostic_survives_discovery(tmp_path, code):
    from aegis_core import approval_shape

    key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, public)
    repo.write("src/app.py", APP.format(1))
    fix = repo.commit("fix: preserve rejected exemption diagnostics")
    marker = "private-exemption-prose-do-not-display"
    trailer = f"Aegis-Exempt-Test: {fix} checked manually\n"
    if code == "message_too_large":
        message = f"{marker}\n\n" + "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1) + "\n" + trailer
    elif code == "message_line_too_long":
        message = f"{marker}\n\n" + "x" * (approval_shape.MAX_LINE_LENGTH + 1) + "\n\n" + trailer
    else:
        message = f"{marker}\n\n{trailer} continued signed value\n"
    repo.git("-c", "gpg.format=ssh", "-c", f"user.signingkey={key}",
             "commit", "-q", "--allow-empty", "-S", "-F", "-", stdin=message)
    assert human_gate.verify_test_exemption(repo.root, repo.head(), fix, "main").code == code

    report = regression.check_ci_regressions(repo.root, "main")

    item, = report.commits
    finding, = report.findings
    assert (item.status, item.exemption_code) == ("failed", code)
    assert f"(its test exemption was rejected: {code})" in finding.message
    assert marker not in json.dumps(report.as_dict(repo.root))


@needs_git
def test_an_oversized_exemption_does_not_explain_another_fix(tmp_path):
    from aegis_core import approval_shape

    repo = make_repo(tmp_path)
    fixes = []
    for i in (1, 2):
        repo.write("src/app.py", APP.format(i))
        fixes.append(repo.commit(f"fix: constant {i}"))
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += f"\nAegis-Exempt-Test: {fixes[0]} reviewed by hand\n"
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)

    report = regression.check_ci_regressions(repo.root, "main")

    assert [(item.commit, item.exemption_code) for item in report.commits] == [
        (fixes[0], "message_too_large"), (fixes[1], None)]


@needs_git
@needs_signing
@pytest.mark.parametrize("valid_after", [False, True])
def test_a_valid_exemption_still_wins_over_an_oversized_one(tmp_path, valid_after):
    from aegis_core import approval_shape

    key, public = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, public)
    repo.write("src/app.py", APP.format(1))
    fix = repo.commit("fix: valid exemption wins")
    if not valid_after:
        repo.commit(human_gate.exemption_message(fix, "reviewed manually"), sign_key=key, allow_empty=True)
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += f"\nAegis-Exempt-Test: {fix} reviewed by hand\n"
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)
    if valid_after:
        repo.commit(human_gate.exemption_message(fix, "reviewed manually"), sign_key=key, allow_empty=True)

    report = regression.check_ci_regressions(repo.root, "main")

    item, = report.commits
    assert (item.status, item.exemption_code) == ("exempted", None)
    assert report.findings == ()


@needs_git
def test_unverified_tests_also_retain_a_rejected_exemption_code(tmp_path):
    from aegis_core import approval_shape

    repo = make_repo(tmp_path)
    repo.write("pkg/handler.go", "package pkg\n\nfunc Handle() int { return 2 }\n")
    repo.write("pkg/handler_test.go", 'package pkg\n\nimport "testing"\n\nfunc TestHandle(t *testing.T) {}\n')
    fix = repo.commit("fix: go handler")
    message = "prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)
    message += f"\nAegis-Exempt-Test: {fix} reviewed by hand\n"
    repo.git("commit", "-q", "--allow-empty", "-F", "-", stdin=message)

    report = regression.check_ci_regressions(repo.root, "main")

    item, = report.commits
    assert (item.status, item.reason, item.exemption_code) == ("unverifiable", "no_driver", "message_too_large")
    assert "(its test exemption was rejected: message_too_large)" in report.findings[0].message


@needs_git
def test_shared_snapshot_ids_are_indexed_once_for_many_fixes(tmp_path, monkeypatch):
    class CountedId(str):
        visits = 0

        def partition(self, separator):
            type(self).visits += 1
            return super().partition(separator)

    repo = make_repo(tmp_path)
    modules = [f"tests/test_case{i}.py" for i in range(100)]
    fixes = [_fix(repo, f"fix: group {group}", {"src/app.py": APP.format(1), f"src/group{group}.py": "value = 1\n", **{
        path: "def test_case(): pass\n" for path in modules[group::4]}}) for group in range(4)]
    ids = {CountedId(f"tests.test_case{i}.Case::test_{j}") for i in range(100) for j in range(200)}
    _fake_outcomes(monkeypatch, (ids, set(), set()), (set(), ids, set()))

    report = regression.check_ci_regressions(repo.root, "main")

    assert [c.commit for c in report.commits] == fixes
    assert all(c.status == "passed" and len(c.fail_to_pass_tests) == 5000 for c in report.commits)
    assert set().union(*(set(c.fail_to_pass_tests) for c in report.commits)) == ids
    assert CountedId.visits <= 2 * len(ids)


@needs_git
@pytest.mark.parametrize("failed", [False, True], ids=["deep-passed", "deep-failed"])
def test_deep_classname_index_work_is_bounded_by_wanted_modules(tmp_path, monkeypatch, failed):
    class CountedClass(str):
        copied = 0
        searches = 0

        def rpartition(self, separator):
            type(self).copied += len(self)
            assert type(self).copied <= 4 * len(classname), "unbounded ancestor materialization"
            prefix, separator, suffix = super().rpartition(separator)
            return type(self)(prefix), separator, suffix

        def find(self, *args):
            type(self).searches += 1
            return super().find(*args)

        def __getitem__(self, key):
            value = super().__getitem__(key)
            if isinstance(key, slice):
                type(self).copied += len(value)
            return value

    class CountedId(str):
        def partition(self, separator):
            classname, separator, name = super().partition(separator)
            return CountedClass(classname), separator, name

    classname = "tests.test_app." + "x." * 100000 + "Case"
    deep = CountedId(classname + "::test_deep")
    plain = "tests.test_app::test_plain"
    repo = make_repo(tmp_path)
    _fix(repo, "fix: deep classname", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    head = ({plain}, {deep}, set()) if failed else ({deep}, set(), set())
    # An ancestor beyond the wanted module's depth must still supply base collection evidence.
    base = (set(), {plain}, {"tests.test_app." + "x." * 10 + "x"})
    _fake_outcomes(monkeypatch, head, base)

    report = regression.check_ci_regressions(repo.root, "main")

    item, = report.commits
    assert (item.status, item.reason) == (("failed", "failed_on_head") if failed else ("passed", "ok"))
    assert item.fail_to_pass_tests == ((plain,) if failed else (deep,))
    assert CountedClass.searches <= 2
    assert CountedClass.copied <= 4 * len(classname)


@needs_git
def test_collection_error_attribution_work_is_linear_and_shared_by_classname(tmp_path, monkeypatch):
    work = {"comparisons": 0, "error_splits": 0, "class_splits": 0, "wanted_searches": 0}
    splits = {}
    count = 2000

    class CountedError(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            work["comparisons"] += 1
            assert work["comparisons"] <= 8 * count, "quadratic collection-error comparisons"
            return super().__eq__(other)

        def split(self, *args):
            work["error_splits"] += 1
            return super().split(*args)

    class CountedClass(str):
        def startswith(self, *args):
            work["comparisons"] += 1
            assert work["comparisons"] <= 8 * count, "quadratic collection-error comparisons"
            return super().startswith(*args)

        def find(self, *args):
            work["wanted_searches"] += 1
            return super().find(*args)

        def split(self, *args):
            splits[self] = splits.get(self, 0) + 1
            assert splits[self] <= (2 if self.startswith("tests.test_app.") else 1), "classname attribution repeated"
            work["class_splits"] += 1
            return super().split(*args)

    class CountedId(str):
        def partition(self, separator):
            classname, separator, name = super().partition(separator)
            return CountedClass(classname), separator, name

    repo = make_repo(tmp_path)
    _fix(repo, "fix: shared collection attribution", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    relevant = {CountedId(f"tests.test_app.Case::test_{i}") for i in range(count)}
    relevant.update(CountedId(f"tests.test_app.Class{i}::test_case") for i in range(count))
    unrelated = {CountedId(f"other.test_{i}.Case::test_case") for i in range(count)}
    errors = {CountedError(f"unrelated.module_{i}") for i in range(count)}
    errors.update(CountedError(f"tests.test_app.Class{i}") for i in range(count))
    errors.add(CountedError("tests.test_app.Case"))
    _fake_outcomes(monkeypatch, (relevant | unrelated, set(), set()), (set(), set(), errors))

    report = regression.check_ci_regressions(repo.root, "main")

    item, = report.commits
    assert (item.status, item.reason, set(item.fail_to_pass_tests)) == ("passed", "ok", relevant)
    assert work["error_splits"] <= len(errors)
    assert work["class_splits"] <= 3 * count + 2
    assert work["wanted_searches"] <= 2 * (count + 1)
    assert work["comparisons"] <= 8 * count


@needs_git
@pytest.mark.parametrize("errors,expected", [
    (set(), ("ok", "ok", "passed_on_base")),
    ({"tests.test_app"}, ("failed_on_head", "ok", "passed_on_base")),
    ({"tests.test_app.Child"}, ("ok", "failed_on_head", "passed_on_base")),
    ({"<suite:pytest>"}, ("failed_on_head", "failed_on_head", "failed_on_head")),
], ids=["base-ancestor", "exact-head-parent", "exact-head-child", "head-suite"])
def test_indexed_attribution_preserves_overlapping_modules_and_collection_rules(tmp_path, monkeypatch, errors, expected):
    repo = make_repo(tmp_path)
    paths = ("tests/test_app.py", "tests/test_app/Child.py", "tests/test_app_extra.py")
    for i, path in enumerate(paths):
        _fix(repo, f"fix: module {i}", {"src/app.py": APP.format(1), f"src/module{i}.py": "x = 1\n",
                                       path: "def test_case(): pass\n"})
    parent = "tests.test_app::test_plain"
    child = "tests.test_app.Child.Case::test_method"
    extra = "tests.test_app_extra::test_case"
    _fake_outcomes(monkeypatch, ({parent, child, extra}, set(), errors), (set(), set(), {"tests.test_app"}))

    report = regression.check_ci_regressions(repo.root, "main")

    assert tuple(c.reason for c in report.commits) == expected
    assert [c.fail_to_pass_tests for c in report.commits] == [tuple(sorted((parent, child))), (child,), ()]


@needs_git
@pytest.mark.parametrize("case", ["base-error", "unrelated-head-classname"])
def test_dotted_report_input_has_bounded_peak_allocation(tmp_path, monkeypatch, case):
    repo = make_repo(tmp_path)
    _fix(repo, "fix: bounded attribution memory", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    plain = "tests.test_app::test_plain"
    component = "a." if case == "base-error" else "ab."
    dotted = component * ((8 * 1024 * 1024 - 4096) // len(component)) + "Case"
    if case == "base-error":
        head, base = ({plain}, set(), set()), (set(), set(), {"tests.test_app." + dotted})
        expected = ("failed", "passed_on_base", ())
    else:
        identity = "other." + dotted + "::test_case"
        head, base = ({plain, identity}, set(), set()), (set(), {plain}, set())
        expected = ("passed", "ok", (plain,))
    _fake_outcomes(monkeypatch, head, base)

    tracemalloc.start()
    try:
        report = regression.check_ci_regressions(repo.root, "main")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    item, = report.commits
    assert (item.status, item.reason, item.fail_to_pass_tests) == expected
    print(f"{case}: input={len(dotted)} peak={peak} limit={4 * len(dotted)}")
    assert peak <= 4 * len(dotted), "attribution allocation grows with dotted components"


@needs_git
@pytest.mark.parametrize("head_ids", [set(), {"other.module.Case::test_case"}])
def test_base_error_index_is_not_built_without_wanted_classnames(tmp_path, monkeypatch, head_ids):
    class UnusedError(str):
        def find(self, *_args):
            pytest.fail("unused base collection error was indexed")

        def split(self, *_args):
            pytest.fail("unused base collection error was split")

    repo = make_repo(tmp_path)
    _fix(repo, "fix: no wanted result", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    _fake_outcomes(monkeypatch, (head_ids, set(), set()), (set(), set(), {UnusedError("tests.test_app.Case")}))

    item, = regression.check_ci_regressions(repo.root, "main").commits
    assert (item.status, item.reason, item.fail_to_pass_tests) == ("failed", "no_tests_collected", ())


@needs_git
@pytest.mark.parametrize("errors", [
    {"tests.test_app.Case.Left", "tests.test_app.Case.Right"},
    {"tests.test_app.Case", "tests.test_app.Case.Left"},
    {"tests.test_app.Case", "tests.test_app.Case_extra"},
    {"tests.test_app.", "tests.test_app..Child"},
    {"tests.test_app..Child", "tests.test_app..Other"},
    {"tests.test_app", "tests.test_app.Case.Left", "other"},
    {"tests", "other", ""},
    {"tests.test_app_extra", "tests.test_app.Case.Leftish"},
])
def test_compressed_collection_edges_preserve_exact_and_dotted_boundaries(tmp_path, monkeypatch, errors):
    repo = make_repo(tmp_path)
    _fix(repo, "fix: compressed collection boundaries", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    classes = ("tests.test_app", "tests.test_app.Case", "tests.test_app.Case.Left", "tests.test_app.Case.Right",
               "tests.test_app.Case.Leftish", "tests.test_app.Case_extra", "tests.test_app.",
               "tests.test_app..Child", "tests.test_app..Other", "tests.test_app_extra.Case", "other")
    identities = {classname + "::test_case" for classname in classes}
    _fake_outcomes(monkeypatch, (identities, set(), set()), (set(), set(), errors))
    # The documented public rule is exact classname equality or a dotted descendant.
    expected = tuple(sorted(classname + "::test_case" for classname in classes
                            if (classname == "tests.test_app" or classname.startswith("tests.test_app."))
                            and any(classname == error or classname.startswith(error + ".") for error in errors)))

    item, = regression.check_ci_regressions(repo.root, "main").commits
    assert item.fail_to_pass_tests == expected
    assert item.reason == ("ok" if expected else "passed_on_base")


@needs_git
def test_ids_belong_to_their_own_module_and_a_suite_level_error_fails_every_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """tests.test_app_extra is not part of tests/test_app.py, a class id is; a suite-level error on the
    head run fails every judged commit."""
    repo = make_repo(tmp_path)
    plain = _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_app.py": TEST_COMPUTE})
    extra = _fix(repo, "fix: other", {"src/other.py": "y = 1\n", "tests/test_app_extra.py": TEST_COMPUTE})
    head = ({"tests.test_app_extra::test_x", "tests.test_app.TestK::test_m"}, set(), set())
    base = ({"tests.test_app.TestK::test_m"}, {"tests.test_app_extra::test_x"}, set())
    seen = _fake_outcomes(monkeypatch, head, base)

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert sorted(seen) == ["base", "head"]
    assert {c.commit: (c.status, c.reason) for c in report.commits} == {
        plain: ("failed", "passed_on_base"), extra: ("passed", "ok")}

    _fake_outcomes(monkeypatch, (head[0], set(), {"<suite:pytest>"}), base)
    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert {c.commit: (c.status, c.reason) for c in report.commits} == {
        plain: ("failed", "failed_on_head"), extra: ("failed", "failed_on_head")}


@needs_git
def test_a_passing_fix_commit_looks_up_no_exemption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Review F3: Given three fix commits whose tests are fail-to-pass and one fix without a test, When
    regressions are checked, Then only the failing commit looks up a test exemption. Git rev-list
    runs once for metadata and once for discovery; discovery reads each commit body once."""

    repo = make_repo(tmp_path)
    test_one = "def test_one():\n    pass\n"
    passing = [
        _fix(repo, "fix: compute adds one", {"src/app.py": APP.format(1), "tests/test_one.py": test_one}),
        _fix(repo, "fix: other", {"src/other.py": "y = 1\n", "tests/test_two.py": test_one}),
        _fix(repo, "fix: third", {"src/third.py": "z = 1\n", "tests/test_three.py": test_one}),
    ]
    failing = _fix(repo, "fix: four without a test", {"src/four.py": "w = 1\n"})
    ids = {"tests.test_one::test_one", "tests.test_two::test_one", "tests.test_three::test_one"}
    _fake_outcomes(monkeypatch, (ids, set(), set()), (set(), ids, set()))
    looked_up: list = []
    real_finder = human_gate.exemption_finder

    def finder(root, head, base_ref):
        find = real_finder(root, head, base_ref)
        return lambda oid: looked_up.append(oid) or find(oid)

    monkeypatch.setattr(human_gate, "exemption_finder", finder)
    calls = _metadata_calls(monkeypatch)

    report = regression.check_ci_regressions(repo.root, "main", "HEAD")
    assert {c.commit: c.status for c in report.commits} == {**{oid: "passed" for oid in passing}, failing: "failed"}
    assert looked_up == [failing]
    assert sum(1 for c in calls if c and c[0] == "rev-list") == 2


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
    assert item.fail_to_pass_tests == ()


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
    failed = regression.CommitRegression("a" * 40, "fix: x", "failed", "no_test_changes")
    assert regression.RegressionReport(tier="gate", commits=(failed,)).blocking is True
    assert regression.RegressionReport(commits=(failed,)).blocking is False


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


def _commit_batch_reads(monkeypatch):
    """Observe declared commit reads at the public reader boundary, without changing content."""
    from aegis_core import gitsafe

    batches = []
    real = gitsafe.read_blobs

    def counted(cwd, oids, **kwargs):
        requested = list(oids)
        if kwargs.get("kind") == "commit":
            batches.append(requested)
        return real(cwd, requested, **kwargs)

    monkeypatch.setattr(gitsafe, "read_blobs", counted)
    return batches
