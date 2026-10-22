"""Tree identity runs no program a repository or one of its submodules chose (R-trust-18), while
the user's and the system's filter drivers run as in any git command (R-trust-20).

Every repository lives in a temporary directory under a throwaway HOME. The marker filters are
POSIX shell scripts outside every repository: a marker file means git ran one. Submodule files are
armed racily clean (the index is no older than they are), so git must hash their content through
the clean filter to know they are unchanged, and each such test first shows that plain git runs
the filter there (else it skips).
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

import pytest

from aegis_core import gitsafe, insights, treeid
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

pytestmark = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_filter = pytest.mark.skipif(os.name == "nt", reason="the marker filter is a POSIX shell script")
FILE_PROTOCOL = ("-c", "protocol.file.allow=always")
ATTRIBUTES = "*.py filter=evil\n*.md filter=a=b\n"
HARDENING = {"core.fsmonitor=false", f"core.hooksPath={os.devnull}", "protocol.allow=never", "credential.helper=",
             "core.sshCommand=false"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _origin(path: Path, home: hg.Home) -> hg.Repo:
    """A repository to add as a submodule: three Python files, a README and the attributes."""
    repo = hg.Repo(path, home)
    for name in ("a", "b", "c"):
        repo.write(f"{name}.py", f"{name} = 1\n")
    repo.write("README.md", "# sub\n")
    repo.write(".gitattributes", ATTRIBUTES)
    repo.commit("sub")
    return repo


def _project(tmp_path: Path) -> hg.Repo:
    """The work tree of helpers_verified, with the same attributes and ``vendor/sub`` checked out."""
    repo = hv.make_project(tmp_path, runner=None)
    repo.write(".gitattributes", ATTRIBUTES)
    sub = _origin(tmp_path / "sub-origin", repo.home)
    repo.git(*FILE_PROTOCOL, "submodule", "add", "-q", str(sub.root), "vendor/sub")
    repo.commit("add vendor/sub")
    return repo


def _filter_script(tmp_path: Path, marker: Path, extra: str = "") -> str:
    script = tmp_path / f"filter-{marker.name}"
    script.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\ncat\n{extra}'.encode("utf-8"))
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _plant(repo: Path, driver: str, script: str) -> None:
    """``repo``'s own config (a submodule's lives in .git/modules/<path>/config) defines ``driver``."""
    hg.git(repo, "config", f"filter.{driver}.clean", script)
    hg.git(repo, "config", f"filter.{driver}.required", "true")


def _racily_clean(repo: Path) -> None:
    index = repo / hg.git(repo, "rev-parse", "--git-path", "index")
    oldest = min((repo / name).stat().st_mtime for name in ("a.py", "b.py", "c.py", "README.md"))
    os.utime(index, (oldest, oldest))


def _git_runs_the_filter_or_skip(root: Path, marker: Path) -> None:
    """Positive control: plain ``git status`` (the index left alone) runs the filter here."""
    hg.run_git(root, "status", "--porcelain", env={"GIT_OPTIONAL_LOCKS": "0"}, check=False)
    if not marker.exists():
        pytest.skip("this git does not run a submodule's clean filter from git status")
    marker.unlink()


def _armed(tmp_path: Path, sub: Path, root: Path) -> Path:
    """``sub`` defines a marker clean filter for its ``*.py``; returns the marker."""
    marker = tmp_path / "SUB_FILTER_RAN"
    _plant(sub, "evil", _filter_script(tmp_path, marker))
    _racily_clean(sub)
    _git_runs_the_filter_or_skip(root, marker)
    return marker


@posix_filter
def test_a_clean_filter_only_a_submodule_config_defines_never_runs(tmp_path):
    repo = _project(tmp_path)
    sub = repo.root / "vendor" / "sub"
    before = treeid.tree_of(repo.root)
    assert before.status == "ok" and before.gitlinks == ("vendor/sub",)
    marker = _armed(tmp_path, sub, repo.root)

    after = treeid.tree_of(repo.root)
    assert (after.status, after.tree) == ("ok", before.tree)
    assert not marker.exists(), "tree identity ran a clean filter from a submodule's config"

    (sub / "b.py").write_bytes(b"b = 2\n")  # the same size: only its content says it changed
    changed = treeid.tree_of(repo.root)
    assert changed.status == "partial" and "vendor/sub" in changed.reason
    assert not marker.exists(), "tree identity ran a clean filter from a submodule's config"


@posix_filter
def test_a_clean_filter_a_nested_submodule_config_defines_never_runs(tmp_path):
    home = hg.Home(tmp_path / "home")
    inner = _origin(tmp_path / "inner-origin", home)
    outer = _origin(tmp_path / "outer-origin", home)
    outer.git(*FILE_PROTOCOL, "submodule", "add", "-q", str(inner.root), "deps/inner")
    outer.commit("add deps/inner")
    repo = hv.make_project(tmp_path, runner=None)
    repo.git(*FILE_PROTOCOL, "submodule", "add", "-q", str(outer.root), "vendor/outer")
    repo.git(*FILE_PROTOCOL, "submodule", "update", "-q", "--init", "--recursive")
    repo.commit("add vendor/outer")
    nested = repo.root / "vendor" / "outer" / "deps" / "inner"
    assert treeid.tree_of(repo.root).status == "ok"
    marker = _armed(tmp_path, nested, repo.root)

    assert treeid.tree_of(repo.root).status == "ok"
    assert not marker.exists(), "tree identity ran a clean filter from a nested submodule's config"

    (nested / "b.py").write_bytes(b"b = 2\n")
    changed = treeid.tree_of(repo.root)
    assert changed.status == "partial" and "vendor/outer" in changed.reason
    assert not marker.exists(), "tree identity ran a clean filter from a nested submodule's config"


@posix_filter
@pytest.mark.parametrize("where", ["worktree", "submodule"])
def test_a_driver_name_git_c_cannot_carry_makes_the_tree_unbindable(tmp_path, where):
    repo = _project(tmp_path)
    target = repo.root if where == "worktree" else repo.root / "vendor" / "sub"
    marker = tmp_path / "EQ_FILTER_RAN"
    _plant(target, "a=b", _filter_script(tmp_path, marker))  # `-c filter.a=b.clean=` sets filter.a
    if where == "submodule":
        _racily_clean(target)
    readme = target / "README.md"
    readme.write_bytes(readme.read_bytes().upper())  # the same size

    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)
    assert "a=b" in binding.reason
    assert not marker.exists(), "tree identity ran a filter driver it cannot switch off"


@posix_filter
def test_a_driver_name_that_is_not_utf8_makes_the_tree_unbindable(tmp_path):
    repo = _project(tmp_path)
    marker = tmp_path / "BYTES_FILTER_RAN"
    script = _filter_script(tmp_path, marker)
    config = repo.root / ".git" / "config"
    config.write_bytes(config.read_bytes() + b'[filter "\xff"]\n\tclean = ' + os.fsencode(script) + b"\n")
    (repo.root / ".gitattributes").write_bytes(b"*.md filter=\xff\n")
    (repo.root / "README.md").write_bytes(b"# changed\n")

    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)
    assert not marker.exists(), "tree identity ran a filter driver it cannot switch off"


def test_the_work_tree_s_git_variables_never_reach_a_submodule(tmp_path, monkeypatch):
    repo = _project(tmp_path)
    git_dir = repo.root / ".git"
    for name, value in (("GIT_DIR", git_dir), ("GIT_WORK_TREE", repo.root), ("GIT_INDEX_FILE", git_dir / "index")):
        monkeypatch.setenv(name, str(value))
    assert treeid.tree_of(repo.root).status == "ok"

    (repo.root / "vendor" / "sub" / "stray.txt").write_bytes(b"untracked\n")
    binding = treeid.tree_of(repo.root)
    assert binding.status == "partial" and "vendor/sub" in binding.reason


def test_a_replace_ref_cannot_make_a_dirty_submodule_read_clean(tmp_path):
    repo = _project(tmp_path)
    sub = repo.root / "vendor" / "sub"
    base = hg.git(sub, "rev-parse", "HEAD")
    (sub / "a.py").write_bytes(b"a = 2\n")
    hg.git(sub, "add", "a.py")
    forged = hg.git(sub, "-c", "user.email=f@example.com", "-c", "user.name=F", "commit-tree",
                    hg.git(sub, "write-tree"), "-m", "forged")
    hg.git(sub, "replace", base, forged)
    assert hg.git(sub, "status", "--porcelain") == ""  # plain git reads the staged change as clean

    binding = treeid.tree_of(repo.root)
    assert binding.status == "partial" and "vendor/sub" in binding.reason


@posix_filter
def test_dirty_paths_runs_no_clean_filter_a_submodule_config_defines(tmp_path):
    repo = _project(tmp_path)
    sub = repo.root / "vendor" / "sub"
    marker = _armed(tmp_path, sub, repo.root)
    (sub / "b.py").write_bytes(b"b = 2\n")

    assert insights.dirty_paths(repo.root) == []  # a dirty submodule is not a changed file
    assert not marker.exists(), "insights.dirty_paths ran a clean filter from a submodule's config"


def test_without_git_the_binding_is_unbindable_and_nothing_raises(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path, runner=None)
    empty = tmp_path / "no-git"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)

    monkeypatch.setattr(gitsafe, "toplevel", lambda cwd: repo.root)  # git gone after the work tree was found
    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)
    assert "git is not installed" in binding.reason


def test_submodules_nested_deeper_than_the_cap_make_the_tree_unbindable(tmp_path):
    repo = hv.make_project(tmp_path, runner=None)
    oid, here, chain = repo.head(), repo.root, []
    for _ in range(17):  # each a checked-out gitlink, the only entry of the one above it
        hg.git(here, "init", "-q", "d")
        hg.git(here, "update-index", "--add", "--cacheinfo", f"160000,{oid},d")
        here = here / "d"
        chain.append(here)

    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)
    assert "16 deep" in binding.reason

    os.rename(chain[-1] / ".git", chain[-1] / "git-off")  # 16 deep: within the cap
    assert "16 deep" not in treeid.tree_of(repo.root).reason


def test_a_git_call_that_times_out_is_an_unbindable_answer_not_an_exception(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path, runner=None)
    real_run = subprocess.run

    def config_times_out(argv, *args, **kwargs):
        if "config" in argv and "--list" in argv:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout") or 0)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", config_times_out)
    binding = treeid.tree_of(repo.root)
    assert (binding.status, binding.tree) == ("unbindable", None)
    assert "timed out" in binding.reason


def test_every_git_call_of_tree_identity_is_hardened(tmp_path, monkeypatch):
    repo = _project(tmp_path)
    (repo.root / "vendor" / "sub" / "stray.txt").write_bytes(b"untracked\n")
    real_run, calls = subprocess.run, []

    def spy(argv, *args, **kwargs):
        calls.append(list(argv))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    assert treeid.tree_of(repo.root).status == "partial"

    def settings(argv):
        return {value for flag, value in zip(argv, argv[1:]) if flag == "-c"}

    assert calls and [argv[1:4] for argv in calls if not HARDENING <= settings(argv)] == []


# ── The user's and the system's drivers run, as in any git command (R-trust-20) ──

def _txt_project(tmp_path: Path, driver: str) -> hg.Repo:
    """``*.txt`` is assigned ``driver`` (defined nowhere yet) and ``notes.txt`` has changed."""
    repo = hv.make_project(tmp_path, runner=None)
    repo.write(".gitattributes", f"*.txt filter={driver}\n")
    repo.write("notes.txt", "one\n")
    repo.commit("notes")
    repo.write("notes.txt", "two\n")
    return repo


def _git_tree(root: Path, *flags: str) -> str:
    """The tree plain git commits for the work tree (through a throwaway index), ``flags`` first."""
    env = {"GIT_INDEX_FILE": str(root.parent / f"index-{root.name}")}
    try:
        hg.git(root, *flags, "read-tree", "HEAD", env=env)
        hg.git(root, *flags, "add", "-A", env=env)
        return hg.git(root, *flags, "write-tree", env=env)
    finally:
        os.unlink(env["GIT_INDEX_FILE"])


@posix_filter
def test_a_user_clean_filter_runs_so_the_tree_is_the_one_git_commits(tmp_path):
    repo = _txt_project(tmp_path, "lfsish")
    marker = tmp_path / "USER_FILTER_RAN"
    repo.home.config("filter.lfsish.clean", _filter_script(tmp_path, marker, extra="echo cleaned\n"))

    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and marker.exists(), "the user's own filter did not run"
    assert binding.tree == _git_tree(repo.root)
    assert binding.tree != _git_tree(repo.root, "-c", "filter.lfsish.clean=")  # the filter changes the tree


@posix_filter
def test_a_clean_filter_the_repository_config_defines_is_still_switched_off(tmp_path):
    repo = _txt_project(tmp_path, "repof")
    marker = tmp_path / "REPO_FILTER_RAN"
    hg.git(repo.root, "config", "filter.repof.clean", _filter_script(tmp_path, marker, extra="echo cleaned\n"))

    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and not marker.exists()
    assert binding.tree == _git_tree(repo.root, "-c", "filter.repof.clean=")


@posix_filter
def test_a_user_driver_whose_name_holds_an_equals_sign_runs(tmp_path):
    repo = _txt_project(tmp_path, "a=b")
    marker = tmp_path / "USER_EQ_FILTER_RAN"
    repo.home.config("filter.a=b.clean", _filter_script(tmp_path, marker, extra="echo cleaned\n"))

    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and marker.exists()
    assert binding.tree == _git_tree(repo.root)


@posix_filter
def test_a_driver_the_repository_also_defines_is_switched_off_in_every_scope(tmp_path):
    repo = _txt_project(tmp_path, "dual")
    user_marker, repo_marker = tmp_path / "USER_RAN", tmp_path / "REPO_RAN"
    repo.home.config("filter.dual.clean", _filter_script(tmp_path, user_marker, extra="echo user\n"))
    hg.git(repo.root, "config", "filter.dual.clean", _filter_script(tmp_path, repo_marker, extra="echo repo\n"))

    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and not user_marker.exists() and not repo_marker.exists()
    assert binding.tree == _git_tree(repo.root, "-c", "filter.dual.clean=")


@posix_filter
def test_a_git_without_show_scope_switches_off_every_driver(tmp_path, monkeypatch):
    repo = _txt_project(tmp_path, "lfsish")
    marker = tmp_path / "USER_FILTER_RAN"
    repo.home.config("filter.lfsish.clean", _filter_script(tmp_path, marker, extra="echo cleaned\n"))
    real_run = subprocess.run

    def git_before_2_26(argv, *args, **kwargs):
        if "--show-scope" in argv:
            return subprocess.CompletedProcess(argv, 129, b"", b"error: unknown option `show-scope'\n")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", git_before_2_26)
    binding = treeid.tree_of(repo.root)
    assert binding.status == "ok" and not marker.exists()
    assert binding.tree == _git_tree(repo.root, "-c", "filter.lfsish.clean=")
