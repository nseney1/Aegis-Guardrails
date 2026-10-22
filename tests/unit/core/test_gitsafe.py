"""aegis_core.gitsafe: every git subprocess Aegis runs (D20, host-matrix §3.7, v4.3 §10.1)."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

import pytest

from aegis_core import gitsafe

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


def _git(repo: Path, *args: str) -> str:
    # The same config gitsafe reads (system config included), so a commit made here
    # stores what a user's git would store: Git for Windows' system core.autocrlf=true
    # turns the CRLF that write_text writes there into LF blobs.
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, text=True,
    ).stdout


def _repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    return path


def _commit(repo: Path, message: str = "c") -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = _repo(tmp_path / "repo")
    (root / "a.py").write_text("a = 1\n", encoding="utf-8")
    (root / "b.py").write_text("b = 1\n", encoding="utf-8")
    (root / "gone.py").write_text("gone = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    _commit(root, "init")
    return root


# ── Hardening ────────────────────────────────────────────────────────────────

def test_every_call_is_hardened(monkeypatch, tmp_path: Path):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(gitsafe.subprocess, "run", fake_run)
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    gitsafe.run(["rev-parse", "HEAD"], tmp_path)

    argv, kwargs = seen["argv"], seen["kwargs"]
    assert Path(argv[0]).name.startswith("git")
    assert argv[1:19] == [
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.allow=never",
        "-c", "core.sshCommand=false",
        "-c", "credential.helper=",
        "-c", "log.showSignature=false",
        "-c", f"gpg.program={os.devnull}",
        "-c", f"gpg.openpgp.program={os.devnull}",
        "-c", f"gpg.x509.program={os.devnull}",
    ]
    assert argv[19:] == ["rev-parse", "HEAD"]
    assert "shell" not in kwargs and kwargs["timeout"] == gitsafe.GIT_TIMEOUT_SECONDS
    env = kwargs["env"]
    assert {k: env[k] for k in ("GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "LC_ALL")} == {
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C",
    }
    # The administrator's system config is read (Git for Windows keeps core.autocrlf
    # there); what the repository's config could do is overridden by the -c options.
    assert "GIT_CONFIG_NOSYSTEM" not in env


def test_timeout_and_missing_git_raise_git_error(monkeypatch, tmp_path: Path):
    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(gitsafe.subprocess, "run", slow)
    with pytest.raises(gitsafe.GitError, match="timed out after 0.5s"):
        gitsafe.run(["status"], tmp_path, timeout=0.5)
    assert gitsafe.changed_files(tmp_path) is None  # helpers degrade to "unknown"

    (tmp_path / "no-git").mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "no-git"))
    with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH$"):
        gitsafe.run(["status"], tmp_path)


# ── Which git runs: absolute PATH entries only (aegis_core.pathlookup) ──────

_REAL_GIT_DIR = os.path.dirname(shutil.which("git") or "")


def _plant_git(directory: Path, marker: Path) -> None:
    """A `git` that leaves ``marker`` when run. Windows runs only PATHEXT types, so
    there it is a .cmd beside the script."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        (directory / "git.cmd").write_text(f'@echo ran> "{marker}"\n', encoding="utf-8")
        return
    program = directory / "git"
    program.write_text(f'#!/bin/sh\necho ran >> "{marker}"\nexit 0\n', encoding="utf-8")
    program.chmod(0o755)


@pytest.mark.parametrize("entry", ["", ".", "bin"])
def test_a_git_planted_behind_an_empty_or_relative_path_entry_is_never_run(tmp_path, monkeypatch, entry):
    # Each entry names a directory relative to the cwd: the repository, where a
    # clone can plant a `git` that doctor's hook check or `aegis check` would start.
    repo = tmp_path / "repo"
    marker = tmp_path / "PWNED"
    _plant_git(repo, marker)
    _plant_git(repo / "bin", marker)
    monkeypatch.chdir(repo)

    monkeypatch.setenv("PATH", os.pathsep.join([entry, _REAL_GIT_DIR]))
    proc = gitsafe.run(["--version"], repo)
    assert proc.returncode == 0 and proc.stdout.startswith(b"git version")
    assert not marker.exists(), "a git found through a relative PATH entry was run"

    monkeypatch.setenv("PATH", entry)
    with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH$"):
        gitsafe.run(["--version"], repo)
    assert not marker.exists()


def test_on_windows_the_current_directory_is_not_searched_for_git(tmp_path, monkeypatch):
    # shutil.which searches the cwd first on Windows whatever PATH says: with the cwd
    # in a cloned repository, its git.exe would run.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD"]))
    for where in (tmp_path / "repo", tmp_path / "Git" / "cmd"):
        where.mkdir(parents=True)
        (where / "git.exe").write_bytes(b"MZ")
        (where / "git.exe").chmod(0o755)
    monkeypatch.chdir(tmp_path / "repo")
    monkeypatch.setenv("PATH", str(tmp_path / "Git" / "cmd"))
    started = []

    def record(argv, **kwargs):
        started.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(gitsafe.subprocess, "run", record)
    gitsafe.run(["status"], tmp_path / "repo")
    assert started == [str(tmp_path / "Git" / "cmd" / "git.exe")]


# ── The fsmonitor regression (red team blocker) ──────────────────────────────

def _plant_fsmonitor(repo: Path, marker: Path) -> None:
    hook = repo.parent / "fsmonitor-hook"
    hook.write_text(f'#!/bin/sh\necho ran >> "{marker}"\nexit 1\n', encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    _git(repo, "config", "core.fsmonitor", str(hook))


@pytest.fixture
def fsmonitor_repo(repo: Path, tmp_path: Path):
    """A repo whose .git/config runs a marker-writing fsmonitor, with changes in every mode."""
    if os.name == "nt":
        pytest.skip("the marker hook is a POSIX shell script")
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    _commit(repo, "feature")
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    (repo / "staged.py").write_text("s = 1\n", encoding="utf-8")
    _git(repo, "add", "staged.py")
    (repo / "new.py").write_text("n = 1\n", encoding="utf-8")
    marker = tmp_path / "FSMONITOR_RAN"
    _plant_fsmonitor(repo, marker)
    # Positive control: plain porcelain runs the hook, so the setup is effective.
    subprocess.run(["git", "status", "--porcelain"], cwd=str(repo), capture_output=True)
    if not marker.exists():
        pytest.skip("this git does not run core.fsmonitor hooks from git status")
    marker.unlink()
    return repo, marker


def test_no_gitsafe_call_runs_a_repo_fsmonitor(fsmonitor_repo):
    repo, marker = fsmonitor_repo

    assert sorted(gitsafe.changed_files(repo, "working")) == ["b.py", "staged.py"]
    assert sorted(gitsafe.changed_files(repo, "working", untracked=True)) == ["b.py", "new.py", "staged.py"]
    assert gitsafe.changed_files(repo, "staged") == ["staged.py"]
    assert gitsafe.changed_files(repo, "head") == ["a.py"]
    assert gitsafe.changed_files(repo, "range", base="main") == ["a.py"]
    assert "new.py" in gitsafe.list_files(repo)
    assert gitsafe.read_blob(repo, "HEAD", "a.py") == b"a = 2\n"
    assert gitsafe.toplevel(repo) == repo.resolve()
    assert gitsafe.git_path(repo, "hooks") is not None
    assert gitsafe.head_commit(repo) and gitsafe.merge_base(repo, "main")
    assert gitsafe.resolve_base_ref(repo, environ={}) == "main"

    assert not marker.exists(), "a gitsafe call ran the repository's core.fsmonitor"


def test_aegis_commands_never_run_a_repo_fsmonitor(fsmonitor_repo, monkeypatch, capsys):
    from aegis_cli.cli import main

    repo, marker = fsmonitor_repo
    (repo / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (repo / ".aegis" / "rules" / "traps" / "trap-x.md").write_text(
        "---\nid: trap-x\ntype: trap\nhypothesis: h\ntarget_paths:\n  - '*.py'\n---\nbody\n", encoding="utf-8"
    )
    monkeypatch.chdir(repo)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)

    for argv in (["check"], ["check", "--hook"], ["scan", "--json"], ["status"]):
        try:
            main(argv)
        except SystemExit:
            pass
    capsys.readouterr()

    assert not marker.exists(), "an aegis command ran the repository's core.fsmonitor"


# ── Clean filters a repository's config names ───────────────────────────────

def _select_filter(repo: Path, driver: str = "evil") -> None:
    """Commit a .gitattributes that selects ``driver`` for ``*.py`` (no driver exists yet, so nothing runs)."""
    (repo / ".gitattributes").write_text(f"*.py filter={driver}\n", encoding="utf-8")
    _commit(repo, "attributes")


def _plant_clean_filter(repo: Path, marker: Path, driver: str = "evil") -> None:
    """The repository's own config defines ``driver``: a marker-writing clean filter."""
    if os.name == "nt":
        pytest.skip("the marker filter is a POSIX shell script")
    script = repo.parent / f"clean-filter-{repo.name}"
    script.write_text(f'#!/bin/sh\necho ran >> "{marker}"\ncat\n', encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    _git(repo, "config", f"filter.{driver}.clean", str(script))
    _git(repo, "config", f"filter.{driver}.required", "true")


def _make_racily_clean(repo: Path) -> None:
    """Every index entry stat-matches its file but is not older than the index, so git
    must hash the file's content (through the clean filter) to know it is unchanged."""
    index = repo / _git(repo, "rev-parse", "--git-path", "index").strip()
    oldest = min((repo / name).stat().st_mtime for name in ("a.py", "b.py", "gone.py"))
    os.utime(index, (oldest, oldest))


def _porcelain_runs_the_filter_or_skip(repo: Path, marker: Path) -> None:
    # Positive control without rewriting the index (that would clear what is under test).
    subprocess.run(["git", "status", "--porcelain"], cwd=str(repo), capture_output=True,
                   env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    if not marker.exists():
        pytest.skip("this git does not run the clean filter from git status")
    marker.unlink()


def test_no_changed_files_call_runs_a_clean_filter_from_the_repository_config(repo: Path, tmp_path: Path):
    marker = tmp_path / "FILTER_RAN"
    _select_filter(repo)
    _plant_clean_filter(repo, marker)
    past = time.time() + 5
    os.utime(repo / "b.py", (past, past))                     # stat-dirty, same bytes
    (repo / "gone.py").write_text("gone = 2\n", encoding="utf-8")  # a real change
    _make_racily_clean(repo)                                  # a.py: racily clean
    _porcelain_runs_the_filter_or_skip(repo, marker)

    assert gitsafe.changed_files(repo, "working") == ["gone.py"]
    assert gitsafe.changed_files(repo, "working", untracked=True) == ["gone.py"]

    assert not marker.exists(), "a gitsafe call ran a clean filter from the repository's config"


def test_a_filter_driver_name_that_cannot_be_switched_off_leaves_changes_unknown(repo: Path, tmp_path: Path):
    marker = tmp_path / "FILTER_RAN"
    _select_filter(repo, driver="a=b")
    _plant_clean_filter(repo, marker, driver="a=b")  # `-c filter.a=b.clean=` cannot name it
    _make_racily_clean(repo)

    assert gitsafe.changed_files(repo, "working") is None
    assert gitsafe.changed_files(repo, "staged") == []  # index against HEAD reads no working-tree file
    assert not marker.exists()


def test_no_changed_files_call_runs_a_clean_filter_from_a_submodule_config(repo: Path, tmp_path: Path):
    marker = tmp_path / "FILTER_RAN"
    sub_origin = _repo(tmp_path / "sub-origin")
    (sub_origin / "a.py").write_text("s = 1\n", encoding="utf-8")
    (sub_origin / "b.py").write_text("s = 1\n", encoding="utf-8")
    (sub_origin / "gone.py").write_text("s = 1\n", encoding="utf-8")
    _commit(sub_origin, "sub")
    _select_filter(sub_origin)
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub_origin), "sub")
    _commit(repo, "add sub")
    sub = repo / "sub"
    _plant_clean_filter(sub, marker)
    _make_racily_clean(sub)
    (sub / "gone.py").write_text("s = 2\n", encoding="utf-8")  # the submodule's work tree is dirty
    _porcelain_runs_the_filter_or_skip(sub, marker)

    assert gitsafe.changed_files(repo, "working") == []  # a dirty submodule is not a changed file
    assert not marker.exists(), "a gitsafe call ran a clean filter from a submodule's config"

    _git(sub, "reset", "-q", "--soft", "HEAD~1")  # moves the submodule's HEAD, reads no file
    assert not marker.exists()
    assert gitsafe.changed_files(repo, "working") == ["sub"]  # a moved submodule still is
    assert not marker.exists(), "a gitsafe call ran a clean filter from a submodule's config"


# ── changed_files semantics ──────────────────────────────────────────────────

def test_working_mode_is_head_against_worktree_and_index(repo: Path):
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")         # modified, unstaged
    (repo / "staged.py").write_text("s\n", encoding="utf-8")         # added, staged
    _git(repo, "add", "staged.py")
    (repo / "untracked.py").write_text("u\n", encoding="utf-8")      # untracked
    (repo / "ignored.txt").write_text("i\n", encoding="utf-8")       # ignored
    (repo / "gone.py").unlink()                                      # deleted: not listed
    past = time.time() + 5
    os.utime(repo / "b.py", (past, past))                            # stat-only change: not listed

    assert sorted(gitsafe.changed_files(repo, "working")) == ["a.py", "staged.py"]
    assert sorted(gitsafe.changed_files(repo, "working", untracked=True)) == ["a.py", "staged.py", "untracked.py"]
    assert gitsafe.changed_files(repo, "staged") == ["staged.py"]


# Line endings: git's own normalization decides what changed, on every OS. The system
# and global config files are this test's own, for its git and gitsafe alike, so the
# runner's config cannot decide the outcome (git 2.32+ reads GIT_CONFIG_SYSTEM/GLOBAL).

_AUTOCRLF = "[core]\n\tautocrlf = true\n"  # what Git for Windows' system config holds


@pytest.fixture
def git_config(tmp_path: Path, monkeypatch):
    def configure(system: str = "", global_: str = "") -> None:
        system_file, global_file = tmp_path / "gitconfig-system", tmp_path / "gitconfig-global"
        system_file.write_text(system, encoding="utf-8")
        global_file.write_text(global_, encoding="utf-8")
        monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_file))
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_file))
        probe = subprocess.run(["git", "config", "--system", "--get", "core.autocrlf"],
                               capture_output=True, text=True, cwd=str(tmp_path))
        if ("autocrlf" in system) != (probe.stdout.strip() == "true"):
            pytest.skip("this git does not read GIT_CONFIG_SYSTEM")
    return configure


def test_a_crlf_work_tree_of_normalized_blobs_is_unchanged(tmp_path: Path, git_config):
    """A clone on Windows: LF blobs, CRLF files, every index entry racily clean."""
    git_config(system=_AUTOCRLF)
    origin = _repo(tmp_path / "origin")
    (origin / "a.py").write_bytes(b"a = 1\r\n")
    _commit(origin, "crlf in, lf stored")
    assert gitsafe.read_blob(origin, "HEAD", "a.py") == b"a = 1\n"
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "-q", str(origin), str(clone))
    assert (clone / "a.py").read_bytes() == b"a = 1\r\n"
    assert _git(clone, "status", "--porcelain") == ""

    assert gitsafe.changed_files(clone, "working") == []
    assert gitsafe.changed_files(origin, "working") == []

    (clone / "a.py").write_bytes(b"a = 2\r\n")
    assert gitsafe.changed_files(clone, "working") == ["a.py"]


@pytest.mark.parametrize("system, attributes, git_lists_it", [
    (_AUTOCRLF, None, False),     # Git for Windows: CRLF in the work tree is LF in the repository
    ("", "*.py text\n", False),   # .gitattributes asks for the same normalization
    ("", None, True),             # no normalization: the CRLF bytes would be committed
])
def test_a_file_rewritten_with_crlf_is_a_change_only_where_git_says_so(
    tmp_path: Path, git_config, system: str, attributes, git_lists_it: bool,
):
    git_config(system=system)
    repo = _repo(tmp_path / "repo")
    if attributes:
        (repo / ".gitattributes").write_text(attributes, encoding="utf-8")
    (repo / "a.py").write_bytes(b"a = 1\n")
    _commit(repo, "lf")
    (repo / "a.py").write_bytes(b"a = 1\r\n")  # an editor or a checkout rewrote the line endings
    past = time.time() + 5
    os.utime(repo / "a.py", (past, past))
    expected = ["a.py"] if git_lists_it else []
    assert _git(repo, "diff", "--name-only", "HEAD").split() == expected  # the oracle: git itself

    assert gitsafe.changed_files(repo, "working") == expected


@pytest.mark.parametrize("name", [
    "café menu.py",
    pytest.param('"quoted\\back\tslash\nnewline\r.py', marks=pytest.mark.skipif(os.name == "nt", reason="not a Windows file name")),
])
def test_any_file_name_gets_git_line_ending_normalization(tmp_path: Path, git_config, name: str):
    git_config(system=_AUTOCRLF)
    repo = _repo(tmp_path / "repo")
    (repo / name).write_bytes(b"x = 1\n")
    _commit(repo, "lf")
    (repo / name).write_bytes(b"x = 1\r\n")

    assert gitsafe.changed_files(repo, "working") == []

    (repo / name).write_bytes(b"x = 2\r\n")
    assert gitsafe.changed_files(repo, "working") == [name]


_STRIP_TRAILING_SPACES = "[filter \"strip\"]\n\tclean = sed -e 's/ *$//'\n"


@pytest.mark.parametrize("defined_in, listed", [
    ("global", []),        # the user's own driver (git-lfs lives in ~/.gitconfig) runs, as in their git
    ("repo", ["a.py"]),    # the repository's driver is switched off, so the raw bytes count
])
def test_only_filter_drivers_outside_the_repository_config_clean_content(
    tmp_path: Path, git_config, defined_in: str, listed: list,
):
    if os.name == "nt":
        pytest.skip("the filter is a POSIX sed command")
    git_config(global_=_STRIP_TRAILING_SPACES if defined_in == "global" else "")
    repo = _repo(tmp_path / "repo")
    if defined_in == "repo":
        (repo / ".git" / "config").write_text(
            (repo / ".git" / "config").read_text(encoding="utf-8") + _STRIP_TRAILING_SPACES, encoding="utf-8")
    (repo / ".gitattributes").write_text("*.py filter=strip\n", encoding="utf-8")
    (repo / "a.py").write_bytes(b"a = 1\n")
    _commit(repo, "clean")
    (repo / "a.py").write_bytes(b"a = 1   \n")
    assert _git(repo, "diff", "--name-only", "HEAD").split() == []  # git cleans it either way

    assert gitsafe.changed_files(repo, "working") == listed

    (repo / "a.py").write_bytes(b"a = 2   \n")
    assert gitsafe.changed_files(repo, "working") == ["a.py"]


def test_a_symlink_whose_stat_changed_but_target_did_not_is_unchanged(repo: Path):
    link = repo / "link.py"
    try:
        link.symlink_to("a.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    _commit(repo, "link")
    if _git(repo, "ls-files", "-s", "link.py").split()[0] != "120000":
        pytest.skip("this checkout stores symlinks as plain files (core.symlinks=false)")
    if os.utime not in os.supports_follow_symlinks:
        pytest.skip("cannot touch a symlink itself here")
    past = time.time() + 5
    os.utime(link, (past, past), follow_symlinks=False)

    assert gitsafe.changed_files(repo, "working") == []  # the link's own content is its target

    link.unlink()
    link.symlink_to("b.py")
    assert gitsafe.changed_files(repo, "working") == ["link.py"]


def test_staged_then_reverted_file_is_still_a_working_change(repo: Path):
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    _git(repo, "add", "a.py")
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")  # the worktree matches HEAD again

    assert gitsafe.changed_files(repo, "working") == ["a.py"]


def test_head_and_range_modes(repo: Path):
    _git(repo, "checkout", "-q", "-b", "topic")
    (repo / "a.py").write_text("a = 3\n", encoding="utf-8")
    _commit(repo, "one")
    (repo / "c.py").write_text("c\n", encoding="utf-8")
    _commit(repo, "two")

    assert gitsafe.changed_files(repo, "head") == ["c.py"]
    assert sorted(gitsafe.changed_files(repo, "range", base="main")) == ["a.py", "c.py"]
    assert gitsafe.changed_files(repo, "range", base="no-such-branch") is None


def test_root_commit_and_unborn_head(tmp_path: Path):
    unborn = _repo(tmp_path / "unborn")
    (unborn / "first.py").write_text("x\n", encoding="utf-8")
    _git(unborn, "add", "first.py")
    assert gitsafe.changed_files(unborn, "staged") == ["first.py"]
    assert gitsafe.changed_files(unborn, "working") == ["first.py"]
    assert gitsafe.changed_files(unborn, "head") is None

    _commit(unborn, "root")
    assert gitsafe.changed_files(unborn, "head") == ["first.py"]


def test_outside_a_repository_nothing_is_known(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    if gitsafe.toplevel(plain) is not None:
        pytest.skip("tmp_path is inside a git repository")
    assert gitsafe.changed_files(plain) is None
    assert gitsafe.list_files(plain) is None
    assert gitsafe.git_path(plain, "hooks") is None
    assert gitsafe.read_blob(plain, "HEAD", "a.py") is None


def test_invalid_modes_are_rejected(repo: Path):
    with pytest.raises(ValueError, match="mode must be one of"):
        gitsafe.changed_files(repo, "everything")
    with pytest.raises(ValueError, match="needs a base"):
        gitsafe.changed_files(repo, "range")
    assert gitsafe.resolve_commit(repo, "--output=/tmp/x") is None


def test_list_files_under_a_directory(repo: Path):
    (repo / "pkg").mkdir()
    (repo / "pkg" / "m.py").write_text("m\n", encoding="utf-8")
    _commit(repo)
    (repo / "pkg" / "n.py").write_text("n\n", encoding="utf-8")
    (repo / "pkg" / "ignored.txt").write_text("i\n", encoding="utf-8")

    assert sorted(gitsafe.list_files(repo, ["pkg"])) == ["pkg/m.py", "pkg/n.py"]
    assert gitsafe.list_files(repo, ["pkg"], untracked=False) == ["pkg/m.py"]


def test_list_files_answers_relative_to_the_workspace_not_the_repository_top(repo: Path, tmp_path: Path):
    """Given ``pkg/src/a.py`` tracked and ``pkg/new.txt`` untracked, When list_files runs with
    cwd ``<repo>/pkg``, Then the paths are relative to ``pkg`` (the frame its callers use)."""
    (repo / "pkg" / "src").mkdir(parents=True)
    (repo / "pkg" / "src" / "a.py").write_text("a\n", encoding="utf-8")
    _commit(repo)
    (repo / "pkg" / "new.txt").write_text("n\n", encoding="utf-8")
    assert sorted(gitsafe.list_files(repo / "pkg")) == ["new.txt", "src/a.py"]
    plain = tmp_path / "plain"
    plain.mkdir()
    if gitsafe.toplevel(plain) is None:
        assert gitsafe.list_files(plain) is None


# ── read_blob ────────────────────────────────────────────────────────────────

def test_read_blob_returns_committed_bytes(repo: Path):
    (repo / "a.py").write_text("a = 9\n", encoding="utf-8")  # the worktree is not what is read
    assert gitsafe.read_blob(repo, "HEAD", "a.py") == b"a = 1\n"
    assert gitsafe.read_blob(repo, "HEAD", "missing.py") is None
    assert gitsafe.read_blob(repo, "no-such-rev", "a.py") is None


def test_read_blob_rejects_content_that_does_not_match_the_object_id(repo: Path, monkeypatch):
    real_run = gitsafe.run

    def tampering_run(args, cwd, **kwargs):
        res = real_run(args, cwd, **kwargs)
        if args and args[0] == "cat-file":
            header, _, body = res.stdout.partition(b"\n")
            forged = b"a = 666\n"
            res = subprocess.CompletedProcess(res.args, 0, header.rsplit(b" ", 1)[0] + b" %d\n" % len(forged) + forged + b"\n", b"")
        return res

    monkeypatch.setattr(gitsafe, "run", tampering_run)
    with pytest.raises(gitsafe.GitError, match="does not match object"):
        gitsafe.read_blob(repo, "HEAD", "a.py")


# ── Consolidated plumbing primitives ─────────────────────────────────────────

def test_blob_id_computes_sha1_and_sha256_blob_hashes(repo: Path):
    data = b"a = 1\n"
    expected_sha1 = _git(repo, "rev-parse", "HEAD:a.py").strip()
    assert gitsafe.blob_id(data) == expected_sha1
    assert gitsafe._blob_id(data, 40) == expected_sha1
    sha256_id = gitsafe.blob_id(data, 64)
    assert len(sha256_id) == 64 and sha256_id != expected_sha1


def test_read_blobs_batches_and_verifies_hashes(repo: Path, monkeypatch):
    oid_a = _git(repo, "rev-parse", "HEAD:a.py").strip()
    oid_b = _git(repo, "rev-parse", "HEAD:b.py").strip()
    assert gitsafe.read_blobs(repo, []) == {}
    blobs = gitsafe.read_blobs(repo, [oid_a, oid_b, oid_a])
    assert blobs == {oid_a: b"a = 1\n", oid_b: b"b = 1\n"}

    with pytest.raises(gitsafe.GitError, match="cannot read object"):
        gitsafe.read_blobs(repo, ["0" * 40])

    head_commit_oid = gitsafe.head_commit(repo)
    assert head_commit_oid is not None
    with pytest.raises(gitsafe.GitError, match="cannot read object"):
        gitsafe.read_blobs(repo, [head_commit_oid])

    real_run = gitsafe.run

    def forged_run(args, cwd, **kwargs):
        if args and args[0] == "cat-file":
            forged = f"{oid_a} blob 6\nlies!\n\n".encode("ascii")
            return subprocess.CompletedProcess(["git", *args], 0, forged, b"")
        return real_run(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", forged_run)
    with pytest.raises(gitsafe.GitError, match="does not match the object id"):
        gitsafe.read_blobs(repo, [oid_a])


def test_tree_blobs_lists_blobs_and_filters_paths_and_symlinks(repo: Path):
    (repo / "pkg").mkdir()
    (repo / "pkg" / "mod.py").write_text("m = 1\n", encoding="utf-8")
    link = repo / "pkg" / "link.py"
    has_symlink = False
    try:
        link.symlink_to("../a.py")
        has_symlink = True
    except (OSError, NotImplementedError):
        pass
    _commit(repo, "add pkg")

    all_blobs = gitsafe.tree_blobs(repo, "HEAD")
    assert "a.py" in all_blobs and "pkg/mod.py" in all_blobs
    mode_a, oid_a = all_blobs["a.py"]
    assert mode_a == "100644" and oid_a == gitsafe.blob_id(b"a = 1\n")

    scoped = gitsafe.tree_blobs(repo, "HEAD", paths=("pkg",))
    assert "pkg/mod.py" in scoped and "a.py" not in scoped
    if has_symlink and _git(repo, "ls-files", "-s", "pkg/link.py").split()[0] == "120000":
        assert "pkg/link.py" not in scoped
        with_links = gitsafe.tree_blobs(repo, "HEAD", paths=("pkg",), include_symlinks=True)
        assert with_links["pkg/link.py"][0] == "120000"

    with pytest.raises(gitsafe.GitError):
        gitsafe.tree_blobs(repo, "no-such-revision")
    with pytest.raises(gitsafe.GitError):
        gitsafe.tree_blobs(repo, "--bad-flag")


def test_parse_name_status_z_handles_renames_and_copies_without_desync(repo: Path):
    raw = (
        b"R100\0old_a.py\0new_a.py\0"
        b"M\0mod.py\0"
        b"C100\0src.py\0copy.py\0"
        b"A\0added.py\0"
        b"D\0deleted.py\0"
        b"T\0typechanged.py\0"
    )
    parsed = gitsafe.parse_name_status_z(raw)
    assert parsed == [
        ("R100", "old_a.py", "new_a.py"),
        ("M", "mod.py", None),
        ("C100", "src.py", "copy.py"),
        ("A", "added.py", None),
        ("D", "deleted.py", None),
        ("T", "typechanged.py", None),
    ]
    assert gitsafe.parse_name_status_z(b"") == []


def test_export_tree_with_and_without_overlay_and_fallback(repo: Path, tmp_path: Path, monkeypatch):
    (repo / "sub").mkdir()
    (repo / "sub" / "nested.py").write_text("n = 1\n", encoding="utf-8")
    _commit(repo, "nested")
    (repo / "a.py").write_text("dirty worktree\n", encoding="utf-8")

    dest1 = tmp_path / "export1"
    gitsafe.export_tree(repo, "HEAD", dest1)
    assert (dest1 / "a.py").read_bytes() == b"a = 1\n"
    assert (dest1 / "sub" / "nested.py").read_bytes() == b"n = 1\n"

    dest2 = tmp_path / "export2"
    overlay = {
        "a.py": b"a = 42\n",
        "extra/new_test.py": b"assert True\n",
        "../escape.py": b"should not write\n",
    }
    gitsafe.export_tree(repo, "HEAD", dest2, overlay=overlay)
    assert (dest2 / "a.py").read_bytes() == b"a = 42\n"
    assert (dest2 / "sub" / "nested.py").read_bytes() == b"n = 1\n"
    assert (dest2 / "extra" / "new_test.py").read_bytes() == b"assert True\n"
    assert not (tmp_path / "escape.py").exists()

    # Fallback to tree_blobs + read_blobs when checkout-index fails
    real_run = gitsafe.run

    def fail_checkout_index(args, cwd, **kwargs):
        if args and args[0] == "checkout-index":
            return subprocess.CompletedProcess(["git", *args], 1, b"", b"checkout-index failed")
        return real_run(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", fail_checkout_index)
    dest3 = tmp_path / "export3"
    gitsafe.export_tree(repo, "HEAD", dest3, overlay={"b.py": b"b = 99\n"})
    assert (dest3 / "a.py").read_bytes() == b"a = 1\n"
    assert (dest3 / "b.py").read_bytes() == b"b = 99\n"
    assert (dest3 / "sub" / "nested.py").read_bytes() == b"n = 1\n"


# Every write derived from a tree entry or overlay key lands below the destination: a `..`
# part, a leading `/`, and (on Windows, where `:` is a drive or stream separator) a drive or
# stream component are skipped. The rules are pure path logic, so `_on_windows` is patched
# to run the Windows ones on every OS.

def _outside(top: Path, dest: Path) -> list:
    return [p for p in top.rglob("*") if p != dest and dest not in p.parents]


@pytest.mark.skipif(os.name == "nt", reason="a file name with a colon is a POSIX tree entry")
def test_the_fallback_export_keeps_a_posix_file_name_with_a_colon(tmp_path: Path, monkeypatch):
    root = _repo(tmp_path / "repo")
    (root / "a:b.py").write_bytes(b"colon\n")
    (root / "src").mkdir()
    (root / "src" / "x.py").write_bytes(b"x\n")
    _commit(root)
    monkeypatch.setattr(gitsafe, "_filter_overrides", lambda cwd: None)  # checkout-index is not tried
    dest = tmp_path / "dest"
    gitsafe.export_tree(root, "HEAD", dest)
    assert (dest / "a:b.py").read_bytes() == b"colon\n" and (dest / "src" / "x.py").read_bytes() == b"x\n"


@pytest.mark.parametrize("key", ["../x", "/x", "a/../../x", "a\\..\\..\\x", "", "."])
def test_an_overlay_key_outside_the_destination_is_skipped(repo: Path, tmp_path: Path, key):
    dest = tmp_path / "out" / "dest"
    gitsafe.export_tree(repo, "HEAD", dest, overlay={key: b"evil\n", "ok.py": b"ok\n"})
    assert (dest / "ok.py").read_bytes() == b"ok\n"
    assert _outside(tmp_path / "out", dest) == []


def test_with_windows_rules_a_drive_or_stream_name_is_skipped(tmp_path: Path, monkeypatch):
    root = _repo(tmp_path / "repo")
    (root / "src").mkdir()
    (root / "src" / "x.py").write_bytes(b"x\n")
    if os.name != "nt":
        (root / "a:b.py").write_bytes(b"colon\n")
    _commit(root)
    monkeypatch.setattr(gitsafe, "_on_windows", lambda: True)
    monkeypatch.setattr(gitsafe, "_filter_overrides", lambda cwd: None)
    dest = tmp_path / "out" / "dest"
    overlay = {"D:evil.py": b"x", "D:/x/evil.py": b"x", "x:stream": b"x", "ok.py": b"y"}
    gitsafe.export_tree(root, "HEAD", dest, overlay=overlay)
    assert (dest / "ok.py").read_bytes() == b"y" and (dest / "src" / "x.py").read_bytes() == b"x\n"
    assert not [p.name for p in dest.rglob("*") if ":" in p.name]
    assert not [p for p in _outside(tmp_path / "out", dest) if "evil" in p.name]


def test_a_part_that_joins_onto_another_drive_is_outside_the_destination(tmp_path: Path, monkeypatch):
    """The joined target is checked, not only the string: pathlib's Windows flavour joins
    ``D:evil.py`` onto drive D, whichever OS runs the check."""
    from pathlib import PureWindowsPath

    monkeypatch.setattr(gitsafe, "_on_windows", lambda: False)  # the join check alone
    for key in ("D:evil.py", "D:/x/evil.py"):
        assert gitsafe._safe_export_target(PureWindowsPath(r"C:\snap\x"), key) is None, key
    assert gitsafe._safe_export_target(tmp_path, "src/x.py") == tmp_path / "src" / "x.py"


@pytest.mark.skipif(os.name != "nt", reason="a drive-relative name exists only on Windows")
def test_on_windows_a_drive_relative_overlay_key_writes_nothing_outside(repo: Path, tmp_path: Path):
    dest = tmp_path / "out" / "dest"
    gitsafe.export_tree(repo, "HEAD", dest, overlay={"D:evil.py": b"x", "ok.py": b"y"})
    assert (dest / "ok.py").read_bytes() == b"y"
    assert not [p for p in _outside(tmp_path / "out", dest) if "evil" in p.name]


def test_with_windows_rules_a_rule_id_with_a_drive_or_stream_is_refused(monkeypatch):
    from aegis_core.lifecycle import parsers

    monkeypatch.setattr(parsers, "_on_windows", lambda: True)
    for bad in ("D:x", "x:stream", "C:"):
        with pytest.raises(ValueError, match="path traversal"):
            parsers.validate_rule_id(bad)
        assert parsers.sanitize_rule_id(bad) is None
    for good in ("trap-ok", "a.b"):
        parsers.validate_rule_id(good)
        assert parsers.sanitize_rule_id(good) == good


@pytest.mark.skipif(os.name == "nt", reason="a rule id with a colon is a legal POSIX file name")
def test_on_posix_a_rule_id_with_a_colon_still_creates_its_rule(tmp_path: Path):
    from aegis_core.lifecycle import parsers
    from aegis_core.lifecycle.creation import create_rule

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    parsers.validate_rule_id("a:b")
    path = create_rule("trap", "colon id", id_override="a:b", workspace=tmp_path)
    assert path.name == "a:b.md" and path.is_file()


@pytest.mark.skipif(os.name != "nt", reason="a drive-relative rule id exists only on Windows")
def test_on_windows_a_drive_relative_rule_id_creates_nothing(tmp_path: Path):
    from aegis_core.lifecycle.creation import create_rule

    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    with pytest.raises(ValueError, match="path traversal"):
        create_rule("trap", "drive id", id_override="D:x", workspace=tmp_path)
    assert list((tmp_path / ".aegis" / "rules").rglob("*.md")) == []


# ── add_trailer: interpret-trailers where no repository config is read ────────
#
# A repository's trailer.<alias>.cmd (for the trailer's key) and trailer.<any>.command name
# programs interpret-trailers runs. Given such config, When add_trailer edits a message
# file, Then the program never runs and the trailer is written, even when the caller
# inherited GIT_DIR, GIT_COMMON_DIR and GIT_WORK_TREE (a linked worktree's hook does).

posix_only = pytest.mark.skipif(os.name == "nt", reason="a shell-script trailer command")


def _plant_trailer_commands(repo: Path, tmp_path: Path) -> Path:
    marker, program = tmp_path / "trailer-ran", tmp_path / "trailer.sh"
    program.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\necho planted\n'.encode())
    program.chmod(0o755)
    _git(repo, "config", "trailer.x.key", "Aegis-Check")
    _git(repo, "config", "trailer.x.cmd", str(program))
    _git(repo, "config", "trailer.unrelated.command", str(program))
    return marker


@posix_only
def test_add_trailer_runs_no_trailer_command_of_the_repository(repo: Path, tmp_path: Path, monkeypatch):
    marker = _plant_trailer_commands(repo, tmp_path)
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_COMMON_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(repo))
    monkeypatch.chdir(repo)
    message = tmp_path / "msg"
    message.write_bytes(b"subject\n")
    assert gitsafe.add_trailer(message, "Aegis-Check: tree=abc exit=0") is True
    assert not marker.exists()
    assert message.read_bytes() == b"subject\n\nAegis-Check: tree=abc exit=0\n"


def test_add_trailer_resolves_a_relative_message_file_against_the_callers_directory(repo: Path, monkeypatch):
    (repo / ".git" / "COMMIT_EDITMSG").write_bytes(b"subject\n")
    monkeypatch.chdir(repo)
    assert gitsafe.add_trailer(os.path.join(".git", "COMMIT_EDITMSG"), "Aegis-Check: tree=abc exit=0") is True
    assert (repo / ".git" / "COMMIT_EDITMSG").read_bytes() == b"subject\n\nAegis-Check: tree=abc exit=0\n"


def test_add_trailer_replaces_its_own_key_and_keeps_other_trailers(tmp_path: Path):
    message = tmp_path / "msg"
    message.write_bytes(b"subject\n\nSigned-off-by: A <a@example.com>\nAegis-Check: tree=old exit=0\n")
    assert gitsafe.add_trailer(message, "Aegis-Check: tree=abc exit=0") is True
    text = message.read_bytes().decode()
    assert "Signed-off-by: A <a@example.com>" in text
    assert [line for line in text.splitlines() if line.startswith("Aegis-Check")] == ["Aegis-Check: tree=abc exit=0"]


def test_add_trailer_on_a_missing_file_is_false_not_an_exception(tmp_path: Path):
    assert gitsafe.add_trailer(tmp_path / "absent", "Aegis-Check: tree=abc exit=0") is False
    assert not (tmp_path / "absent").exists()


# ── Other queries ────────────────────────────────────────────────────────────

def test_git_path_honours_the_repository_hooks_path(repo: Path, tmp_path: Path):
    custom = tmp_path / "custom-hooks"
    _git(repo, "config", "core.hooksPath", str(custom))
    assert gitsafe.git_path(repo, "hooks") == custom


def test_resolve_base_ref_prefers_the_pull_request_base(repo: Path):
    _git(repo, "branch", "develop")
    _git(repo, "branch", "release")
    assert gitsafe.resolve_base_ref(repo, environ={"GITHUB_BASE_REF": "release"}) == "release"
    assert gitsafe.resolve_base_ref(repo, environ={}) == "main"
    _git(repo, "branch", "-m", "main", "trunk")
    assert gitsafe.resolve_base_ref(repo, environ={}) == "develop"


# ── Ratchet: no git subprocess outside gitsafe ───────────────────────────────

_SPAWNERS = {
    ("subprocess", "run"), ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("subprocess", "call"), ("subprocess", "Popen"), ("os", "system"), ("os", "popen"),
}


def _is_git_program(node: ast.AST) -> bool:
    """argv[0] of a git call: "git" (a list's first element)."""
    return isinstance(node, ast.Constant) and node.value == "git"


def _is_git_command_line(node: ast.AST) -> bool:
    """A shell command line that runs git ("git status ...")."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and (
        node.value == "git" or node.value.startswith("git ")
    )


def _calls_git_executable(node: ast.AST) -> bool:
    """argv[0] of a git call through a lookup: ``git_executable()``, ``gitsafe.git_executable()`` or a copy."""
    func = node.func if isinstance(node, ast.Call) else None
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    return name.endswith("git_executable")


# treeid spawns git itself: it needs a scrubbed environment and a private index, which gitsafe.run
# cannot give (SECURITY.md, Repository trust). Its argv heads are gitsafe.git_executable() calls.
_GIT_EXECUTABLE_HEADS_ALLOWED = {"aegis_core/gitsafe.py", "aegis_core/treeid.py"}


def _git_spawn_offenders(rel: str, source: str) -> list:
    tree = ast.parse(source)
    # `binary in ("git", "gh")` names git without running it
    membership = {
        id(comparator)
        for node in ast.walk(tree) if isinstance(node, ast.Compare)
        for op, comparator in zip(node.ops, node.comparators) if isinstance(op, (ast.In, ast.NotIn))
    }
    offenders = []
    for node in ast.walk(tree):
        # an argv list or tuple whose program is git
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts and _is_git_program(node.elts[0]) \
                and id(node) not in membership:
            offenders.append(f"{rel}:{node.lineno} builds a git argv")
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts and _calls_git_executable(node.elts[0]) \
                and rel not in _GIT_EXECUTABLE_HEADS_ALLOWED:
            offenders.append(f"{rel}:{node.lineno} builds a git argv from git_executable()")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) \
                and (node.func.value.id, node.func.attr) in _SPAWNERS \
                and node.args and _is_git_command_line(node.args[0]):
            offenders.append(f"{rel}:{node.lineno} runs git through {node.func.value.id}.{node.func.attr}")
    return offenders


def test_no_git_subprocess_outside_gitsafe():
    offenders = []
    for pkg in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in sorted((ROOT / pkg).rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if rel != "aegis_core/gitsafe.py":
                offenders += _git_spawn_offenders(rel, path.read_text(encoding="utf-8"))
    assert offenders == []


def test_the_ratchet_flags_a_git_argv_headed_by_a_git_executable_call():
    source = "import subprocess\nfrom aegis_core import gitsafe\nsubprocess.run([gitsafe.git_executable(), 'status'])\n"
    assert _git_spawn_offenders("aegis_core/x.py", source) == ["aegis_core/x.py:3 builds a git argv from git_executable()"]
    assert _git_spawn_offenders("aegis_core/treeid.py", source) == []


# ── merge_base: a full oid is not re-resolved; a revision is validated (R-trust-61) ──

@pytest.fixture
def git_calls(monkeypatch):
    """The argv of every git call gitsafe makes, in order."""
    real_run, calls = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        calls.append(list(args))
        return real_run(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return calls


@pytest.fixture
def forked(repo: Path):
    """main moves on after `side` branches off: (fork point, main tip, side tip) as full oids."""
    fork = gitsafe.head_commit(repo)
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "b.py").write_text("b = 2\n", encoding="utf-8")
    _commit(repo, "side")
    side = gitsafe.head_commit(repo)
    _git(repo, "checkout", "-q", "main")
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    _commit(repo, "main")
    return fork, gitsafe.head_commit(repo), side


def test_merge_base_of_two_full_oids_is_one_git_call(repo: Path, forked, git_calls):
    fork, main_tip, side_tip = forked
    git_calls.clear()
    assert gitsafe.merge_base(repo, main_tip, side_tip) == fork
    assert git_calls == [["merge-base", main_tip, side_tip]]


def test_a_name_or_a_short_oid_is_still_resolved_to_the_same_answer(repo: Path, forked, git_calls):
    fork, main_tip, side_tip = forked
    git_calls.clear()
    assert gitsafe.merge_base(repo, "side", main_tip) == fork
    assert gitsafe.merge_base(repo, side_tip[:12], "HEAD") == fork
    assert [call[0] for call in git_calls] == ["rev-parse", "merge-base", "rev-parse", "rev-parse", "merge-base"]


def test_a_full_oid_that_names_no_commit_gives_none(repo: Path, forked):
    _fork, main_tip, _side = forked
    tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
    assert gitsafe.merge_base(repo, tree, main_tip) is None
    assert gitsafe.merge_base(repo, "0" * 40, main_tip) is None


def test_a_leading_dash_revision_never_reaches_git(repo: Path, git_calls):
    git_calls.clear()
    assert gitsafe.merge_base(repo, "--x", "HEAD") is None
    assert git_calls == []
    assert gitsafe.merge_base(repo, "HEAD", "--output=x") is None
    assert not any(arg.startswith("--output=x") for call in git_calls for arg in call)


def test_a_snapshot_rerun_of_a_leading_dash_revision_fails_without_reaching_git(repo: Path, git_calls):
    from aegis_core import checkrun

    git_calls.clear()
    assert checkrun.rerun_commit_snapshot(repo, "--output=x", "main") == {"tree": "", "exit": 1}
    assert not any("--output=x" in arg for call in git_calls for arg in call)


# ── one request's repository facts: memo and layout (R-structure-4) ─────────

def test_a_memo_scope_asks_git_once_for_the_top_level_and_the_common_dir(repo: Path, git_calls):
    (repo / "sub").mkdir()
    git_calls.clear()
    with gitsafe.memo():
        for _ in range(3):
            assert gitsafe.toplevel(repo / "sub") == repo.resolve()
            assert gitsafe.common_dir(repo / "sub") == repo / "sub" / ".." / ".git"
            assert gitsafe.toplevel(str(repo / "sub")) == repo.resolve()
    assert len(git_calls) == 1, git_calls
    git_calls.clear()
    assert gitsafe.toplevel(repo / "sub") == repo.resolve()
    assert gitsafe.common_dir(repo / "sub") == repo / "sub" / ".." / ".git"
    assert len(git_calls) == 2  # outside a scope every question is asked


def test_a_nested_memo_shares_the_outer_one_and_every_exit_path_clears_it(repo: Path, git_calls):
    git_calls.clear()
    with gitsafe.memo():
        gitsafe.toplevel(repo)
        with gitsafe.memo():
            gitsafe.toplevel(repo)
        gitsafe.toplevel(repo)  # the inner exit did not clear the outer scope
    assert len(git_calls) == 1
    with pytest.raises(RuntimeError):
        with gitsafe.memo():
            gitsafe.toplevel(repo)
            raise RuntimeError("the body fails")
    with gitsafe.memo():
        gitsafe.toplevel(repo)
    assert len(git_calls) == 3


def test_memoized_answers_none_once_and_computes_every_time_outside_a_scope():
    produced = []
    with gitsafe.memo():
        assert [gitsafe.memoized(("k",), lambda: produced.append(1)) for _ in range(3)] == [None, None, None]
    assert produced == [1]
    gitsafe.memoized(("k",), lambda: produced.append(2))
    gitsafe.memoized(("k",), lambda: produced.append(3))
    assert produced == [1, 2, 3]


def test_layout_names_the_common_dir_prefix_shallowness_and_top_level(repo: Path, tmp_path: Path):
    (repo / "sub").mkdir()
    assert gitsafe.layout(repo) == gitsafe.Layout(".git", "", False, str(repo.resolve()))
    assert gitsafe.layout(repo / "sub") == gitsafe.Layout("../.git", "sub/", False, str(repo.resolve()))
    inside = gitsafe.layout(repo / ".git")  # git places it, but no work tree contains it
    assert inside is not None and inside.top is None and inside.common_dir == "."
    plain = tmp_path / "plain"
    plain.mkdir()
    if gitsafe.toplevel(plain) is None:  # not inside some enclosing repository
        assert gitsafe.layout(plain) is None


def test_a_bare_repository_has_a_common_dir_and_no_top_level(repo: Path, tmp_path: Path):
    bare = tmp_path / "bare.git"
    _git(tmp_path, "clone", "-q", "--bare", str(repo), str(bare))
    assert gitsafe.toplevel(bare) is None
    assert gitsafe.common_dir(bare) == Path(os.path.abspath(bare)) / "."
    assert gitsafe.layout(bare).shallow is False


@pytest.mark.skipif(os.name == "nt", reason="Windows forbids a newline in a path")
def test_a_workspace_path_with_a_newline_keeps_the_answers_of_the_single_calls(repo: Path, git_calls):
    odd = repo / "line\nbreak"
    odd.mkdir()
    git_calls.clear()
    with gitsafe.memo():
        assert gitsafe.toplevel(odd) == repo.resolve()
        assert gitsafe.common_dir(odd) == odd / ".." / ".git"
        assert gitsafe.layout(odd).prefix == "line\nbreak/"
    assert len(git_calls) >= 2  # the combined answer cannot be split by line, so it is asked again

# ── the git executable is resolved once per PATH value (R-structure-10) ─────

@pytest.fixture
def fresh_git_lookup():
    gitsafe._reset_for_tests()
    yield
    gitsafe._reset_for_tests()


def _counting_which(monkeypatch):
    from aegis_core import pathlookup

    real, asked = pathlookup.which, []
    monkeypatch.setattr(pathlookup, "which", lambda name, *a, **kw: asked.append(name) or real(name, *a, **kw))
    return asked


def test_twenty_git_calls_with_one_path_look_git_up_once(tmp_path, monkeypatch, fresh_git_lookup):
    asked = _counting_which(monkeypatch)
    for _ in range(20):
        assert gitsafe.run(["--version"], tmp_path).returncode == 0
    assert asked == ["git"]
    assert os.path.samefile(gitsafe.git_executable(), shutil.which("git")) and asked == ["git"]


def _copy_git(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    real = Path(shutil.which("git"))
    copy = directory / real.name
    shutil.copy2(str(real), str(copy))
    return copy


@pytest.mark.skipif(os.name == "nt", reason="copies the git binary; Git for Windows needs its whole tree")
def test_a_new_path_finds_its_own_git_and_a_deleted_git_fails_loudly(tmp_path, monkeypatch, fresh_git_lookup):
    copy = _copy_git(tmp_path / "other")
    monkeypatch.setenv("PATH", str(tmp_path / "other"))
    assert gitsafe.git_executable() == str(copy)
    assert gitsafe.run(["--version"], tmp_path).returncode == 0
    saved = copy.read_bytes()
    copy.unlink()
    with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH$"):
        gitsafe.run(["--version"], tmp_path)
    copy.write_bytes(saved)
    copy.chmod(0o755)
    assert gitsafe.run(["--version"], tmp_path).returncode == 0


def test_a_cached_git_never_outlives_a_path_that_only_holds_a_relative_entry(tmp_path, monkeypatch,
                                                                            fresh_git_lookup):
    marker = tmp_path / "PWNED"
    _plant_git(tmp_path / "repo", marker)
    monkeypatch.chdir(tmp_path / "repo")
    assert gitsafe.run(["--version"], tmp_path).returncode == 0  # cached under the real PATH
    monkeypatch.setenv("PATH", ".")
    with pytest.raises(gitsafe.GitError, match="^git is not installed or not on PATH$"):
        gitsafe.run(["--version"], tmp_path)
    assert not marker.exists()
