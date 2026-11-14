"""aegis_core.gitsafe: every git subprocess Aegis runs (D20, host-matrix §3.7, v4.3 §10.1)."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

import pytest

from aegis_core import gitsafe, gitsafe_run, gitops_fds

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


def strict_program_guard(*, optional=False, native_fixture=False):
    """One capability check, exposed as a fixture and for conditional helper setup."""
    supported = gitsafe_run._program_supported()
    reason = "strict runner requires descriptor-bound native executable support"
    if supported and native_fixture and shutil.which("cc") is None:
        supported = False
        reason = "native strict-effect fixture needs an installed C compiler"
    if not supported and not optional:
        pytest.skip(reason)
    return supported


@pytest.fixture
def strict_program():
    return strict_program_guard()


_NATIVE_STUB = {}


def _native_program(path, source, *, compiler=None):
    """Native test executable with an owner-chosen, embedded fixture interpreter."""
    import json
    import tempfile
    binary = _NATIVE_STUB.get("binary")
    if binary is None or not binary.is_file():
        compiler = compiler or shutil.which("cc")
        if compiler is None:
            pytest.skip("native strict-effect fixture needs an installed C compiler")
        directory = Path(tempfile.mkdtemp(prefix="native-stub-", dir=path.parent))
        binary = directory / "launcher"
        _NATIVE_STUB["binary"] = binary
        code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
    char self[16384], data[16392];
    ssize_t length=readlink("/proc/self/exe",self,sizeof(self)-1);
    if(length<0 || length>=(ssize_t)sizeof(self)-1) return 124;
    self[length]=0;
    snprintf(data,sizeof(data),"%s.source",self);
    FILE *f=fopen(data,"rb");
    if(!f) return 124;
    struct stat st;
    if(fstat(fileno(f),&st) || st.st_size<2 || st.st_size>1048576) {fclose(f);return 124;}
    char *body=calloc((size_t)st.st_size+1,1);
    if(!body) {fclose(f);return 124;}
    if(fread(body,1,(size_t)st.st_size,f)!=(size_t)st.st_size) {fclose(f);free(body);return 124;}
    fclose(f);
    char **args=calloc((size_t)argc+5,sizeof(char*));
    if(!args) {free(body);return 124;}
    args[0]=body[0]=='P'?PYTHON:"/bin/sh";
    args[1]="-c";
    args[2]=body+2;
    int offset=body[0]=='P'?2:3;
    if(offset==3) args[3]=self;
    for(int i=1;i<argc;i++) args[i+offset]=argv[i];
    execv(args[0],args);
    free(args);free(body);return 124;
}
'''
        code = "#define PYTHON " + json.dumps(sys.executable) + "\n" + code
        subprocess.run([compiler, "-x", "c", "-O2", "-o", str(binary), "-"],
            input=code.encode(), env={"PATH": os.defpath, "LC_ALL": "C"}, check=True, capture_output=True, timeout=30)
    first, _, body = source.partition("\n")
    python = "python" in first or sys.executable in first
    if python:
        body = "import sys; sys.argv[0]=" + repr(str(path)) + "\n" + body
    path.with_name(path.name + ".source").write_text(("P\n" if python else "S\n") + body, encoding="utf-8")
    shutil.copy2(binary, path)
    path.chmod(0o700)


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


def _switched_off(driver: str) -> list:
    return ["-c", f"filter.{driver}.clean=", "-c", f"filter.{driver}.smudge=", "-c", f"filter.{driver}.process=",
            "-c", f"filter.{driver}.required=false"]


def test_filter_overrides_name_the_repository_drivers_or_with_scope_all_every_driver(tmp_path: Path, git_config):
    git_config(global_=_STRIP_TRAILING_SPACES + "[filter \"a=b\"]\n\tclean = cat\n")
    repo = _repo(tmp_path / "repo")
    _git(repo, "config", "filter.mine.clean", "cat")
    assert gitsafe.TRUSTED_SCOPES == frozenset({"system", "global", "command"})

    assert gitsafe.filter_overrides(repo) == tuple(_switched_off("mine"))  # the user's a=b is not named
    assert gitsafe.filter_overrides(repo, scope="all") is None  # a=b cannot be switched off
    _git(tmp_path, "config", "--global", "--remove-section", "filter.a=b")
    assert gitsafe.filter_overrides(repo, scope="all") == (*_switched_off("strip"), *_switched_off("mine"))


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
    assert gitsafe.blob_id(data, 40) == expected_sha1
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


# ── blob_sizes and run_checked: the one batch reader, the one checked call (R-structure-22) ──

def _answering(monkeypatch, stdout: bytes = b"", returncode: int = 0, stderr: bytes = b"") -> None:
    """``gitsafe.run`` answers every ``cat-file`` with the given reply; anything else runs git."""
    real_run = gitsafe.run

    def forged(args, cwd, **kwargs):
        if args and args[0] == "cat-file":
            return subprocess.CompletedProcess(["git", *args], returncode, stdout, stderr)
        return real_run(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", forged)


def test_blob_sizes_reads_each_blobs_size_from_its_header(repo: Path):
    oid_a = _git(repo, "rev-parse", "HEAD:a.py").strip()
    oid_gone = _git(repo, "rev-parse", "HEAD:gone.py").strip()
    sizes = {oid: int(_git(repo, "cat-file", "-s", oid)) for oid in (oid_a, oid_gone)}
    assert gitsafe.blob_sizes(repo, []) == {}
    assert gitsafe.blob_sizes(repo, [oid_a, oid_gone, oid_a]) == sizes


@pytest.mark.parametrize("what", ["missing", "commit"])
def test_blob_sizes_refuses_an_object_that_is_not_a_blob(repo: Path, what: str):
    oid = "0" * 40 if what == "missing" else gitsafe.head_commit(repo)
    with pytest.raises(gitsafe.GitError, match=f"^git cannot read object {oid}$"):
        gitsafe.blob_sizes(repo, [oid])


@pytest.mark.parametrize("reply", ["{oid} blob 6x\n", "{oid} blob -6\n", "{oid} blob\n", "", "{other} blob 6\n"],
                         ids=["suffix", "negative", "short", "empty", "other-oid"])
def test_a_malformed_size_line_is_a_git_error_not_a_value_error(repo: Path, monkeypatch, reply: str):
    oid = _git(repo, "rev-parse", "HEAD:a.py").strip()
    _answering(monkeypatch, reply.format(oid=oid, other="1" * 40).encode("ascii"))
    with pytest.raises(gitsafe.GitError, match=f"^git cannot read object {oid}$"):
        gitsafe.blob_sizes(repo, [oid])
    with pytest.raises(gitsafe.GitError, match=f"^git cannot read object {oid}$"):
        gitsafe.read_blobs(repo, [oid])


def test_a_failed_batch_call_names_gits_stderr_collapsed_and_capped(repo: Path, monkeypatch):
    oid = _git(repo, "rev-parse", "HEAD:a.py").strip()
    noise = ("fatal:\n  object  store\tbroken " * 20)[:500].encode("ascii")
    _answering(monkeypatch, returncode=128, stderr=noise)
    expected = "git cat-file failed: " + " ".join(noise.decode("ascii").split())[:200]
    for read in (gitsafe.blob_sizes, gitsafe.read_blobs):
        with pytest.raises(gitsafe.GitError) as info:
            read(repo, [oid])
        assert str(info.value) == expected and "\n" not in str(info.value)


class _DomainError(Exception):
    pass


def test_run_checked_returns_a_zero_exit_and_raises_the_requested_error_otherwise(repo: Path, monkeypatch):
    done = gitsafe.run_checked(["rev-parse", "--verify", "HEAD"], repo)
    assert done.returncode == 0 and done.stdout.strip() == gitsafe.head_commit(repo).encode("ascii")
    with pytest.raises(_DomainError, match=r"^git rev-parse failed: fatal: "):
        gitsafe.run_checked(["rev-parse", "--verify", "no-such-ref"], repo, error=_DomainError)
    with pytest.raises(gitsafe.GitError, match=r"^git rev-parse failed: "):
        gitsafe.run_checked(["rev-parse", "--verify", "no-such-ref"], repo)
    long_noise = ("line one\n\n  line two " * 40).encode("ascii")
    monkeypatch.setattr(gitsafe, "run", lambda args, cwd, **kw: subprocess.CompletedProcess(args, 1, b"", long_noise))
    with pytest.raises(_DomainError) as info:
        gitsafe.run_checked(["ls-tree", "HEAD"], repo, error=_DomainError)
    assert str(info.value) == "git ls-tree failed: " + " ".join(long_noise.decode("ascii").split())[:200]


def test_run_checked_turns_a_spawn_failure_into_the_requested_error(repo: Path, monkeypatch):
    def cannot_start(args, cwd, **kwargs):
        raise gitsafe.GitError("cannot run git: [Errno 2] No such file or directory")

    monkeypatch.setattr(gitsafe, "run", cannot_start)
    with pytest.raises(_DomainError, match=r"^cannot run git: \[Errno 2\]") as info:
        gitsafe.run_checked(["rev-parse", "HEAD"], repo, error=_DomainError)
    assert isinstance(info.value.__cause__, gitsafe.GitError)
    with pytest.raises(gitsafe.GitError, match="^cannot run git"):
        gitsafe.run_checked(["rev-parse", "HEAD"], repo)


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
    monkeypatch.setattr(gitsafe, "filter_overrides", lambda cwd, scope="untrusted": None)  # checkout-index is not tried
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
    monkeypatch.setattr(gitsafe, "filter_overrides", lambda cwd, scope="untrusted": None)
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


# ── The default base: the branch origin/HEAD names, then the legacy list (R-trust-21) ──

@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GITHUB_BASE_REF", "AEGIS_WORKSPACE", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return home


def _gitflow(tmp_path: Path):
    """``develop`` holds a rule change ``main`` lacks; ``feature`` (checked out, off develop) touches
    only src/; origin/HEAD names origin/develop and origin/main exists too. Returns (repo, develop)."""
    from tests import helpers_humangate as hg
    from tests import helpers_verified as hv

    repo = hv.make_project(tmp_path, runner=None)
    repo.git("checkout", "-q", "-b", "develop", "main")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("hypothesis: sample", "hypothesis: sharper"))
    develop = repo.commit("develop sharpens a rule")
    repo.git("checkout", "-q", "-b", "feature")
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit("feature")
    repo.git("update-ref", "refs/remotes/origin/main", "main")
    repo.git("update-ref", "refs/remotes/origin/develop", develop)
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/develop")
    return repo, develop


def test_the_default_base_is_the_branch_origin_head_names(tmp_path: Path, fake_home):
    from aegis_core import checkrun

    repo, develop = _gitflow(tmp_path)
    assert gitsafe.resolve_base_ref(repo.root, environ={}) == "origin/develop"

    out = checkrun.record(repo.root)
    assert out.status == "recorded", out.reason
    assert out.row["base"] == develop == gitsafe.merge_base(repo.root, "develop")
    assert out.row["protected_changed"] is False  # develop's rule change is not the feature's


def test_the_pull_request_base_still_wins_over_origin_head(tmp_path: Path, fake_home):
    repo, _ = _gitflow(tmp_path)
    assert gitsafe.resolve_base_ref(repo.root, environ={"GITHUB_BASE_REF": "main"}) == "origin/main"


@pytest.mark.parametrize("target", ["refs/remotes/origin/gone", "refs/heads/develop"])
def test_an_origin_head_that_names_no_remote_branch_is_skipped(repo: Path, target: str):
    _git(repo, "branch", "develop")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", target)
    assert gitsafe.resolve_base_ref(repo, environ={}) == "main"


def test_a_master_only_repository_without_a_remote_measures_against_master(tmp_path: Path, fake_home,
                                                                            monkeypatch, capsys):
    import json

    from aegis_cli.cli import main
    from aegis_core import checkrun
    from tests import helpers_verified as hv

    repo = hv.make_project(tmp_path, runner=None)
    repo.git("branch", "-m", "main", "master")
    assert gitsafe.resolve_base_ref(repo.root, environ={}) == "master"

    out = checkrun.record(repo.root)
    assert out.status == "recorded", out.reason

    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    assert main(["approve", "--json"]) == 1
    refusal = json.loads(capsys.readouterr().out)
    assert refusal["code"] == "nothing"  # it got past the base: governance did not change since master


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


def _single_reader_offenders(rel: str, source: str) -> list:
    """A reach into gitsafe's private names, or a ``cat-file --batch``/``--batch-check`` spelled outside
    gitsafe: the one batch reader is ``gitsafe.read_blobs``/``blob_sizes``, which check what git hands back."""
    offenders = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "gitsafe" \
                and node.attr.startswith("_"):
            offenders.append(f"{rel}:{node.lineno} uses gitsafe.{node.attr}")
        if isinstance(node, ast.ImportFrom) and node.module == "aegis_core.gitsafe":
            offenders += [f"{rel}:{node.lineno} imports gitsafe.{a.name}" for a in node.names if a.name.startswith("_")]
        if isinstance(node, ast.Constant) and node.value in ("--batch", "--batch-check"):
            offenders.append(f"{rel}:{node.lineno} names cat-file {node.value}")
    return offenders


def test_no_package_module_reaches_gitsafe_private_names():
    offenders = []
    for pkg in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in sorted((ROOT / pkg).rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if rel not in ("aegis_core/gitsafe.py", "aegis_core/gitsafe_run.py"):
                offenders += _single_reader_offenders(rel, path.read_text(encoding="utf-8"))
    assert offenders == []


def test_the_single_reader_ratchet_flags_a_private_reach_and_a_batch_spelling():
    source = ("from aegis_core import gitsafe\nfrom aegis_core.gitsafe import _blob_id\n"
              "gitsafe._parse_cat_file_batch(b'', [])\ngitsafe.run(['cat-file', '--batch-check'], '.')\n")
    assert _single_reader_offenders("aegis_core/x.py", source) == [
        "aegis_core/x.py:2 imports gitsafe._blob_id", "aegis_core/x.py:3 uses gitsafe._parse_cat_file_batch",
        "aegis_core/x.py:4 names cat-file --batch-check"]
    assert _single_reader_offenders("aegis_core/x.py", "gitsafe.read_blobs('.', [])\n") == []


def test_the_ratchet_flags_a_git_argv_headed_by_a_git_executable_call():
    source = "import subprocess\nfrom aegis_core import gitsafe\nsubprocess.run([gitsafe.git_executable(), 'status'])\n"
    assert _git_spawn_offenders("aegis_core/x.py", source) == ["aegis_core/x.py:3 builds a git argv from git_executable()"]
    assert _git_spawn_offenders("aegis_core/treeid.py", source) == []


# ── The docstring is the list of what gitsafe's git calls write (R-trust-28) ──

_WRITERS = {
    "update-ref", "merge-tree", "read-tree", "checkout-index", "update-index", "write-tree", "commit-tree",
    "mktree", "mktag", "add", "commit", "checkout", "reset", "tag", "branch", "gc", "prune", "repack",
    "pack-refs", "fetch", "pull", "push", "clone", "init", "stash", "apply",
}


def _first_strings(tree: ast.AST) -> list:
    """The first string element of every list literal (the subcommand of an argv list)."""
    return [next((e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)), None)
            for node in ast.walk(tree) if isinstance(node, ast.List)]


def test_the_module_docstring_names_every_git_command_that_writes():
    tree = ast.parse((ROOT / "aegis_core" / "gitsafe.py").read_text(encoding="utf-8"))
    firsts = _first_strings(tree)
    detected = _WRITERS.intersection(firsts)
    assert {"update-ref", "merge-tree", "read-tree", "checkout-index"} <= detected  # the detector sees them
    if "hash-object" in firsts and "-w" in firsts:
        detected.add("hash-object -w")
    doc = gitsafe.__doc__ or ""
    assert sorted(name for name in detected if not re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", doc)) == []


def _repository_state(repo: Path) -> dict:
    work_tree = {p.relative_to(repo).as_posix(): p.read_bytes() for p in sorted(repo.rglob("*"))
                 if p.is_file() and ".git" not in p.relative_to(repo).parts}
    refs = _git(repo, "for-each-ref", "--format=%(refname) %(objectname)")
    return {"work tree": work_tree, "index": (repo / ".git" / "index").read_bytes(), "refs": refs,
            "HEAD": (repo / ".git" / "HEAD").read_bytes()}


def test_export_tree_leaves_the_repository_work_tree_index_and_refs_alone(repo: Path, tmp_path: Path):
    (repo / "a.py").write_bytes(b"a = 2\n")                     # modified, unstaged
    (repo / "staged.py").write_bytes(b"s = 1\n")
    _git(repo, "add", "staged.py")                              # staged
    before = _repository_state(repo)

    gitsafe.export_tree(repo, "HEAD", tmp_path / "plain")
    gitsafe.export_tree(repo, "HEAD", tmp_path / "overlaid", overlay={"b.py": b"b = 9\n"})

    assert _repository_state(repo) == before
    assert (tmp_path / "plain" / "a.py").read_bytes() == b"a = 1\n"
    assert (tmp_path / "overlaid" / "b.py").read_bytes() == b"b = 9\n"


# Read plumbing, the hardened `log`, and the named writers: the signed approval commit
# (human_gate), the Aegis-Check trailer's write-tree (hooks/commitmsg) and add_trailer.
_RUN_ALLOWED = {
    "cat-file", "config", "diff-index", "diff-tree", "for-each-ref", "ls-files", "ls-tree", "merge-base",
    "rev-list", "rev-parse", "symbolic-ref", "check-ref-format", "version", "log", "commit", "interpret-trailers",
    "write-tree",
}
# `aegis sync --pr` (SECURITY.md, the git row) reads its remote's push URLs and the committer
# identity, writes its own aegis/lifecycle-* branch, and pushes that one branch.
_RUN_ALLOWED_IN = {
    "aegis_core/sync.py": {"remote", "var", "update-ref", "push"},
    # GM-1 maps refs/remotes/R/B to target B only through the longest configured remote name,
    # so the approval policy lists remote names (read-only, size-bounded by the caller).
    "aegis_core/approval_policy.py": {"remote"},
}


# This is a spelling/shape guard only. The spawn-boundary runtime classifier
# enforces strict custody; this check deliberately performs no Python dataflow.
_STRICT_RUNNERS = {"run", "run_checked", "_run", "execute", "capture", "checked", "output", "text"}


def _literal_command(argument):
    if not isinstance(argument, (ast.List, ast.Tuple)):
        return None
    elements = argument.elts
    position = 0
    while position < len(elements):
        node = elements[position]
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            return None
        if node.value == "-c":
            position += 2
        elif node.value.startswith("-"):
            position += 1
        else:
            return node.value
    return None


def _run_subcommand_offenders(rel, source):
    tree, offenders = ast.parse(source), []
    if rel == "aegis_core/team_git.py":
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        entry = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_lane_operation"), None)
        wrapper = next((n for n in entry.body if isinstance(n, ast.FunctionDef) and n.name == "wrapped"), None) if entry else None
        store_type = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "GitStore"), None)
        enter = next((n for n in store_type.body if isinstance(n, ast.FunctionDef) and n.name == "__enter__"), None) if store_type else None
        require = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_require_runner"), None)
        allowed = {"gitsafe": {"MERGE_TREE_MIN_VERSION", "GitError"},
                   "gitsafe_run": set()}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in ("aegis_core.gitsafe", "aegis_core.gitsafe_run"):
                offenders.append(f"{rel}:{node.lineno} bare Git import")
            if isinstance(node, ast.Import) and any(a.name in ("aegis_core.gitsafe", "aegis_core.gitsafe_run") for a in node.names):
                offenders.append(f"{rel}:{node.lineno} aliased Git import")
            if isinstance(node, ast.ImportFrom) and node.module == "aegis_core" and any(a.asname for a in node.names if a.name in allowed):
                offenders.append(f"{rel}:{node.lineno} aliased Git import")
            if not isinstance(node, ast.Name) or node.id not in allowed or not isinstance(node.ctx, ast.Load):
                continue
            parent = parents.get(node)
            scope = parent
            scopes = []
            while scope is not None:
                if isinstance(scope, ast.FunctionDef):
                    scopes.append(scope)
                scope = parents.get(scope)
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                offenders.append(f"{rel}:{node.lineno} forwards unrestricted Git module")
                continue
            attribute, context = parent.attr, parents.get(parent)
            factory = (node.id == "gitsafe" and attribute == "lane_runner" and entry in scopes
                       and isinstance(context, ast.Call) and context.func is parent)
            type_check = (node.id == "gitsafe_run" and attribute == "LaneRunner"
                          and isinstance(context, ast.Call) and isinstance(context.func, ast.Name)
                          and context.func.id == "isinstance")
            if attribute not in allowed[node.id] and not factory and not type_check:
                offenders.append(f"{rel}:{node.lineno} unrestricted Git reference")
        protected = {"cas", "paths", "publish", "_run"}
        lane_methods = {"run", "run_checked", "paths", "environment", "read_ref", "cas", "publish",
                        "read_private_object", "read_private_objects", "private_object_headers"}
        for module in ("gitsafe.py", "gitsafe_run.py"):
            protected.update(n.name for n in ast.parse((ROOT / "aegis_core" / module).read_text(encoding="utf-8")).body
                             if isinstance(n, ast.FunctionDef))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in ("runner", "_runner") and isinstance(node.ctx, ast.Load):
                parent = parents.get(node)
                scope = parent
                while scope is not None and not isinstance(scope, ast.FunctionDef):
                    scope = parents.get(scope)
                call = isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                transfer = call and parent.func.id in ("_require_runner", "_current", "_publish", "_snapshot_baselines", "_write_snapshot")
                type_check = call and parent.func.id == "isinstance" and require is not None and scope is require
                retain = isinstance(parent, ast.Assign) and enter is not None and scope is enter and ast.unparse(parent.targets[0]) == "self._lane"
                inject = isinstance(parent, ast.keyword) and parent.arg == "_runner" and wrapper is not None and scope is wrapper
                if not (isinstance(parent, ast.Attribute) and parent.value is node or transfer or type_check or retain or inject):
                    offenders.append(f"{rel}:{node.lineno} unproved lane capability escape")
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id in ("runner", "_runner") and node.attr not in lane_methods):
                offenders.append(f"{rel}:{node.lineno} unissued lane capability access")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "type"
                    and any(isinstance(arg, ast.Name) and arg.id in ("runner", "_runner") for arg in node.args)):
                offenders.append(f"{rel}:{node.lineno} derives lane constructor")
            if isinstance(node, ast.Name) and node.id in ("runner", "_runner") and isinstance(node.ctx, (ast.Store, ast.Del)):
                parent, scope = parents.get(node), parents.get(node)
                while scope is not None and not isinstance(scope, ast.FunctionDef):
                    scope = parents.get(scope)
                factory_binding = (node.id == "runner" and wrapper is not None and scope is wrapper
                    and isinstance(parent, ast.Assign) and isinstance(parent.value, ast.IfExp)
                    and ast.unparse(parent.value.body) == "store._lane"
                    and isinstance(parent.value.orelse, ast.Call)
                    and ast.unparse(parent.value.orelse.func) == "gitsafe.lane_runner")
                if not factory_binding:
                    offenders.append(f"{rel}:{node.lineno} rebinds lane capability")
            if not isinstance(node, ast.Attribute) or node.attr not in protected:
                continue
            if node.attr == "_run" and isinstance(node.value, ast.Name) and node.value.id in ("store", "self"):
                continue  # GitStore's own guarded entry; it never accepts a runner.
            if isinstance(node.value, ast.Name) and node.value.id in allowed:
                continue  # Module references were checked above.
            scope = parents.get(node)
            while scope is not None and not isinstance(scope, ast.FunctionDef):
                scope = parents.get(scope)
            receiver = node.value.id if isinstance(node.value, ast.Name) else None
            body = [] if scope is None else scope.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            proof = body[0].value if body and isinstance(body[0], ast.Expr) else None
            checked = (isinstance(proof, ast.Call) and isinstance(proof.func, ast.Name)
                and proof.func.id == "_require_runner" and len(proof.args) == 1
                and isinstance(proof.args[0], ast.Name) and proof.args[0].id == receiver)
            if receiver not in ("runner", "_runner") or not checked:
                offenders.append(f"{rel}:{node.lineno} unproved runner reference")
            if node.attr == "cas" and (scope is None or scope.name != "cas_fast_forward" or parents.get(scope) is not tree):
                offenders.append(f"{rel}:{node.lineno} CAS outside its lane entry")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) and node.func.id == "replace"
                    or isinstance(node.func, ast.Attribute) and node.func.attr == "replace"
                    and (ast.unparse(node.func.value) in ("dataclasses", "dc")
                         or any(isinstance(arg, ast.Name) and arg.id in ("runner", "_runner") for arg in node.args))):
                offenders.append(f"{rel}:{node.lineno} replaces lane capability")
            if isinstance(node, ast.Call) and any(k.arg in ("_env", "env", "scratch") for k in node.keywords):
                scope = parents.get(node)
                while scope is not None and not isinstance(scope, ast.FunctionDef):
                    scope = parents.get(scope)
                if not (scope and scope.name == "_run" and parents.get(scope) in tree.body
                        and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                        and all(k.arg != "_env" or isinstance(k.value, ast.Name) and k.value.id == "extra_env" for k in node.keywords)):
                    offenders.append(f"{rel}:{node.lineno} caller spawn environment")
        return offenders
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _STRICT_RUNNERS or not isinstance(node.func.value, ast.Name) or node.func.value.id != "gitsafe":
            continue
        argument = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg in ("args", "argv")), None)
        command = _literal_command(argument)
        if command is not None and command not in _RUN_ALLOWED | _RUN_ALLOWED_IN.get(rel, set()):
            offenders.append(f"{rel}:{node.lineno} runs git {command}")
    return offenders


@pytest.mark.parametrize("source", [
    "from dataclasses import replace\ndef operation(_runner):\n _require_runner(_runner)\n replace(_runner, scratch=root).run(['read-tree', '--empty'])",
    "import dataclasses as dc\ndef operation(_runner):\n _require_runner(_runner)\n dc.replace(_runner, scratch=root).run(['read-tree', '--empty'])",
    "def outer():\n def cas_fast_forward(_runner):\n  _require_runner(_runner)\n  _runner.cas(ref, new, old)",
    "def operation(_runner):\n _require_runner(_runner)\n _runner.run(['version'], _env={'GIT_TRACE': root})",
    "def operation(_runner):\n _require_runner(_runner)\n _runner._run(['version'])",
    "def operation(_runner):\n _require_runner(_runner)\n forward(_runner._lane_binding)",
    "def operation(_runner):\n _require_runner(_runner)\n forward(type(_runner)(root,scratch,services,token))",
    "def operation(_runner):\n _require_runner(_runner)\n getattr(_runner, 'cas')(ref,new,old)",
    "def operation(_runner):\n _require_runner(_runner)\n forward(_runner)",
    "def outer():\n def _lane_operation():\n  def wrapped(store):\n   runner = store._lane if store.active else gitsafe.lane_runner(store.repo, store.scratch)\n   return forward(_runner=runner)",
])
def test_lane_guard_refuses_environment_replacement_and_nested_cas(source):
    assert _run_subcommand_offenders("aegis_core/team_git.py", source)


def test_gitsafe_run_callers_use_only_allowed_subcommands():
    offenders = []
    for pkg in ("aegis_core", "aegis_cli", "aegis_mcp"):
        for path in sorted((ROOT / pkg).rglob("*.py")):
            offenders += _run_subcommand_offenders(path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8"))
    assert offenders == []


def test_the_subcommand_ratchet_flags_a_worktree_add():
    source = "gitsafe.run(['worktree', 'add', 'x'], root)\ngitsafe.run(['-c', 'a=b', 'worktree', 'add'], root)\n"
    assert _run_subcommand_offenders("aegis_core/x.py", source) == [
        "aegis_core/x.py:1 runs git worktree", "aegis_core/x.py:2 runs git worktree"]
    assert not _run_subcommand_offenders("aegis_core/sync.py", "gitsafe.run(['push', 'origin'], root)")


@pytest.mark.parametrize("source", ["gitsafe.run(args, root)", "g.run(args=argv, cwd=root)",
    "gitsafe.run_checked(values, root)", "gitsafe_run.execute(argv, root)", "from aegis_core.gitsafe import run"])
def test_strict_structural_guard_refuses_names_without_resolving_bindings(source):
    assert _run_subcommand_offenders("aegis_core/team_git.py", source)


def test_exemption_carrier_is_private_to_central_writer():
    owner = {"aegis_core/gitsafe.py", "aegis_core/gitsafe_run.py"}
    carriers = {"_REF_WRITE", "_STRICT_SERVICES", "_LaneServices", "_strict_services", "_LaneBinding", "_lane_binding", "issue_runner"}
    violations = []
    for package in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in (ROOT / package).rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if rel in owner:
                if rel == "aegis_core/gitsafe.py":
                    assert not any(isinstance(n, ast.keyword) and n.arg == "_grant"
                                   for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))))
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            assert not any((isinstance(n, ast.keyword) and n.arg == "_grant")
                           or (isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "_grant")
                           for n in ast.walk(tree)), rel
            for node in ast.walk(tree):
                if ((isinstance(node, ast.Attribute) and node.attr in carriers)
                        or (isinstance(node, ast.Name) and node.id in carriers)
                        or (isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in carriers)
                        or (isinstance(node, ast.ImportFrom) and any(a.name in carriers for a in node.names))):
                    violations.append((rel, node.lineno))
    assert not violations
    for package in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in (ROOT / package).rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if rel in owner:
                if rel == "aegis_core/gitsafe.py":
                    assert not any(isinstance(n, ast.keyword) and n.arg == "_grant"
                                   for n in ast.walk(ast.parse(path.read_text(encoding="utf-8"))))
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            assert not any((isinstance(n, ast.keyword) and n.arg == "_grant")
                           or (isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value == "_grant")
                           for n in ast.walk(tree)), rel
            if rel == "aegis_core/team_git.py":
                assert not _run_subcommand_offenders(rel, path.read_text(encoding="utf-8"))
                continue
            for node in ast.walk(tree):
                assert not (isinstance(node, ast.Attribute) and node.attr in ("LaneRunner", "lane_runner")), (rel, node.lineno)
                assert not (isinstance(node, ast.ImportFrom) and node.module in ("aegis_core.gitsafe", "aegis_core.gitsafe_run")
                            and any(a.name in ("LaneRunner", "lane_runner") for a in node.names)), (rel, node.lineno)
    tree = ast.parse(Path(gitsafe_run.__file__).read_text(encoding="utf-8"))
    parents = {child: n for n in ast.walk(tree) for child in ast.iter_child_nodes(n)}
    grants, launches = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        scopes, parent = [], parents.get(node)
        while parent is not None:
            if isinstance(parent, ast.FunctionDef):
                scopes.append(parent.name)
            parent = parents.get(parent)
        if any(k.arg == "_grant" for k in node.keywords):
            grants.append("cas" in scopes or scopes == ["publish"])
        if ast.unparse(node.func) == "subprocess.Popen":
            launches.append(scopes[0])
    assert grants == [True, True]
    assert launches == ["capture"]



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


# ── scrubbed(): evidence ignores the caller's local GIT_* variables (R-trust-19) ──

_LOCAL_GIT_ENV = ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                  "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
                  "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
                  "GIT_SHALLOW_FILE", "GIT_COMMON_DIR")
_KEPT_GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Author", "GIT_COMMITTER_EMAIL": "c@example.com",
                 "GIT_SSH_COMMAND": "ssh -o BatchMode=yes", "GIT_SSH": "ssh", "GIT_EXEC_PATH": "/opt/git-core",
                 "GIT_CONFIG_SYSTEM": "/etc/none"}


def _env_spy(monkeypatch):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(gitsafe.subprocess, "run", fake_run)
    return seen


def test_scrubbed_drops_exactly_the_local_variables_git_lists(fake_home, tmp_path, monkeypatch):
    """Given the 15 local variables and the identity, SSH and config-scope ones, when git runs inside
    scrubbed(), then none of the 15 reach it and the rest do unchanged; outside, all of them do."""
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(fake_home / ".gitconfig"))
    for name in _LOCAL_GIT_ENV:
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name, value in _KEPT_GIT_ENV.items():
        monkeypatch.setenv(name, value)
    seen = _env_spy(monkeypatch)
    with gitsafe.scrubbed():
        gitsafe.run(["rev-parse", "HEAD"], tmp_path)
    gitsafe.run(["rev-parse", "HEAD"], tmp_path)
    inside, outside = seen
    assert not {k for k in inside if k in _LOCAL_GIT_ENV} - {"GIT_NO_REPLACE_OBJECTS"}
    assert inside["GIT_NO_REPLACE_OBJECTS"] == "1"  # gitsafe's own setting, not the caller's
    assert {k: inside[k] for k in _KEPT_GIT_ENV} == _KEPT_GIT_ENV
    assert inside["GIT_CONFIG_GLOBAL"] == str(fake_home / ".gitconfig")
    assert all(outside[k] == str(tmp_path / k.lower()) for k in _LOCAL_GIT_ENV if k != "GIT_NO_REPLACE_OBJECTS")
    assert {k: outside[k] for k in _KEPT_GIT_ENV} == _KEPT_GIT_ENV
    assert "scrubbed" in gitsafe.__all__


def test_scrubbed_matches_names_whatever_their_case(fake_home, tmp_path, monkeypatch):
    """Windows environment names are case-insensitive: a lower-case git_dir is still GIT_DIR."""
    monkeypatch.setattr(gitsafe.os, "environ", {"PATH": os.environ["PATH"], "git_dir": str(tmp_path),
                                                "Git_Index_File": "x", "HOME": str(fake_home)})
    seen = _env_spy(monkeypatch)
    with gitsafe.scrubbed():
        gitsafe.run(["rev-parse", "HEAD"], tmp_path)
    assert "git_dir" not in seen[0] and "Git_Index_File" not in seen[0] and seen[0]["HOME"] == str(fake_home)


def test_an_explicit_index_still_wins_inside_scrubbed(repo, fake_home, tmp_path, monkeypatch):
    """export_tree's own GIT_INDEX_FILE beats an ambient one pointing at a missing file."""
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "missing" / "index"))
    dest = tmp_path / "out"
    with gitsafe.scrubbed():
        gitsafe.export_tree(repo, "HEAD", dest)
    assert sorted(p.name for p in dest.iterdir()) == [".gitignore", "a.py", "b.py", "gone.py"]


def test_a_hook_index_is_still_read_outside_scrubbed(repo, fake_home, tmp_path, monkeypatch):
    """GUARD: git hands a hook its index in GIT_INDEX_FILE; the default run keeps it."""
    index = tmp_path / "hook-index"
    shutil.copy2(str(repo / ".git" / "index"), str(index))
    (repo / "staged_only.py").write_bytes(b"x = 1\n")
    subprocess.run(["git", "add", "staged_only.py"], cwd=str(repo), check=True, capture_output=True,
                   env=dict(os.environ, GIT_INDEX_FILE=str(index)))
    monkeypatch.setenv("GIT_INDEX_FILE", str(index))
    seen = []
    real = gitsafe.subprocess.run

    def spy(argv, **kwargs):
        seen.append(kwargs["env"].get("GIT_INDEX_FILE"))
        return real(argv, **kwargs)

    monkeypatch.setattr(gitsafe.subprocess, "run", spy)
    assert gitsafe.changed_files(repo, "staged") == ["staged_only.py"]
    assert str(index) in seen
    monkeypatch.delenv("GIT_INDEX_FILE")
    assert gitsafe.changed_files(repo, "staged") == []


def test_the_scrub_ends_with_its_block_even_on_an_exception_and_nests(fake_home, tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_INDEX_FILE", "ambient")
    seen = _env_spy(monkeypatch)
    with pytest.raises(RuntimeError):
        with gitsafe.scrubbed():
            raise RuntimeError("boom")
    gitsafe.run(["status"], tmp_path)
    with gitsafe.scrubbed():
        with gitsafe.scrubbed():
            pass
        gitsafe.run(["status"], tmp_path)
    gitsafe.run(["status"], tmp_path)
    assert [env.get("GIT_INDEX_FILE") for env in seen] == ["ambient", None, "ambient"]


def test_scrubbed_decorates_a_function(fake_home, tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_DIR", "ambient")
    seen = _env_spy(monkeypatch)

    @gitsafe.scrubbed()
    def evidence():
        gitsafe.run(["status"], tmp_path)

    evidence()
    evidence()
    gitsafe.run(["status"], tmp_path)
    assert [env.get("GIT_DIR") for env in seen] == [None, None, "ambient"]


def test_a_memoized_answer_under_an_ambient_git_dir_is_not_served_to_a_scrubbed_call(fake_home, tmp_path,
                                                                                    monkeypatch):
    a, b = _repo(tmp_path / "a"), _repo(tmp_path / "b")
    monkeypatch.setenv("GIT_DIR", str(b / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(b))
    with gitsafe.memo():
        ambient = gitsafe.toplevel(a)
        with gitsafe.scrubbed():
            scrubbed = gitsafe.toplevel(a)
        again = gitsafe.toplevel(a)
    assert os.path.samefile(ambient, b) and os.path.samefile(again, b)
    assert os.path.samefile(scrubbed, a)


# ── read_blob: a malformed size is git's error, as in blob_sizes and read_blobs (w10 carry) ──

@pytest.mark.parametrize("size", [b"12x", b"1.5", b"-1"], ids=["letters", "fraction", "negative"])
def test_read_blob_refuses_a_cat_file_header_whose_size_is_not_a_number(repo: Path, monkeypatch, size):
    real = gitsafe.subprocess.run

    def bad_header(argv, **kwargs):
        res = real(argv, **kwargs)
        if "cat-file" in argv and res.returncode == 0:
            oid = res.stdout.split(b" ", 1)[0]
            return subprocess.CompletedProcess(argv, 0, oid + b" blob " + size + b"\nx", b"")
        return res

    monkeypatch.setattr(gitsafe.subprocess, "run", bad_header)
    with pytest.raises(gitsafe.GitError):
        gitsafe.read_blob(repo, "HEAD", "a.py")


def test_read_blob_still_reads_a_blob_and_answers_none_for_a_missing_path(repo: Path):
    assert gitsafe.read_blob(repo, "HEAD", "a.py") == b"a = 1\n"
    assert gitsafe.read_blob(repo, "HEAD", "missing.py") is None
@pytest.mark.parametrize("kind, revision", [("blob", "HEAD:a.py"), ("commit", "HEAD")])
def test_declared_object_kind_batches_with_size_and_hash_checks(repo, kind, revision):
    oid = _git(repo, "rev-parse", revision).strip()
    expected = subprocess.run(["git", "cat-file", kind, oid], cwd=repo,
                              capture_output=True, check=True).stdout
    assert gitsafe.blob_sizes(repo, [oid], kind=kind) == {oid: len(expected)}
    assert gitsafe.read_blobs(repo, [oid, oid], kind=kind) == {oid: expected}


def test_commit_iterator_sizes_before_chunked_captures_and_deduplicates(repo, monkeypatch):
    commits = [_git(repo, "rev-parse", "HEAD").strip()]
    for index in range(3):
        _git(repo, "commit", "--allow-empty", "-qm", f"commit {index}")
        commits.append(_git(repo, "rev-parse", "HEAD").strip())
    sizes = {oid: int(_git(repo, "cat-file", "-s", oid)) for oid in commits}
    budget = max(sizes.values()) * 2
    calls = []
    real = gitsafe.run

    def counted(args, *a, **kw):
        if args[0] == "cat-file":
            requested = kw["stdin"].decode("ascii").splitlines()
            calls.append((args[1], requested))
            if args[1] == "--batch":
                assert calls[0] == ("--batch-check", commits)
                assert sum(sizes[oid] for oid in requested) <= budget or len(requested) == 1
        return real(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", counted)
    objects = dict(gitsafe.iter_objects(repo, commits + commits, kind="commit", byte_budget=budget))
    assert list(objects) == commits
    assert {oid: len(data) for oid, data in objects.items()} == sizes
    assert len(calls) == 3


@pytest.mark.parametrize("header", ["{oid} blob 3", "{oid} commit -1", "{oid} commit 6x",
                                    "{oid} missing", "{other} commit 3", "{oid} commit " + "9" * 5000],
                         ids=["wrong-kind", "negative", "nondigit", "missing", "wrong-oid", "huge-decimal"])
def test_commit_iterator_refuses_bad_preflight_before_content(repo, monkeypatch, header):
    oid = _git(repo, "rev-parse", "HEAD").strip()
    calls = []

    def forged(args, *a, **kw):
        calls.append(args)
        reply = header.format(oid=oid, other="1" * 40).encode("ascii") + b"\n"
        return subprocess.CompletedProcess(args, 0, reply, b"")

    monkeypatch.setattr(gitsafe, "run", forged)
    with pytest.raises(gitsafe.GitError, match=f"^git cannot read object {oid}$"):
        list(gitsafe.iter_objects(repo, [oid], kind="commit"))
    assert calls == [["cat-file", "--batch-check"]]


@pytest.mark.parametrize("malformation", ["wrong-kind", "wrong-oid", "wrong-size", "hash", "delimiter", "trailing", "short"])
def test_declared_commit_reader_refuses_corrupt_frames(repo, monkeypatch, malformation):
    oid = _git(repo, "rev-parse", "HEAD").strip()
    data = subprocess.run(["git", "cat-file", "commit", oid], cwd=repo,
                          capture_output=True, check=True).stdout
    header = f"{oid} commit {len(data)}\n".encode("ascii")
    frame = header + data + b"\n"
    if malformation == "wrong-kind":
        frame = frame.replace(b" commit ", b" blob ", 1)
    elif malformation == "wrong-oid":
        frame = b"1" * len(oid) + frame[len(oid):]
    elif malformation == "wrong-size":
        frame = f"{oid} commit {len(data) + 1}\n".encode("ascii") + data + b"\n"
    elif malformation == "hash":
        frame = header + b"X" + data[1:] + b"\n"
    elif malformation == "delimiter":
        frame = frame[:-1] + b"X"
    elif malformation == "trailing":
        frame += b"untrusted extra frame"
    else:
        frame = frame[:-2]
    _answering(monkeypatch, frame)
    with pytest.raises(gitsafe.GitError, match="^git (cannot read object|returned content for)"):
        gitsafe.read_blobs(repo, [oid], kind="commit")


@pytest.mark.parametrize("bad_oid", ["HEAD", "-x", "a\nprivate-input", "\N{SNOWMAN}", 123, []])
def test_batch_reader_refuses_invalid_request_without_spawning(repo, monkeypatch, bad_oid):
    def forbidden(*a, **kw):
        pytest.fail("invalid request reached git")

    monkeypatch.setattr(gitsafe, "run", forbidden)
    for read in (gitsafe.read_blobs, gitsafe.blob_sizes):
        with pytest.raises(gitsafe.GitError, match="^invalid object id$"):
            read(repo, [bad_oid])


def test_commit_iterator_reads_lone_object_above_budget_and_releases_capture(repo, monkeypatch):
    oid = _git(repo, "rev-parse", "HEAD").strip()
    captured = []
    real = gitsafe.run

    def counted(args, *a, **kw):
        if args[:2] == ["cat-file", "--batch"]:
            captured.append(kw["stdin"])
        return real(args, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", counted)
    objects = list(gitsafe.iter_objects(repo, [oid], kind="commit", byte_budget=1))
    assert len(objects) == 1 and objects[0][0] == oid and len(objects[0][1]) > 1
    assert captured == [oid.encode("ascii") + b"\n"]


@pytest.mark.parametrize("budget", [0, -1, True, 1.5, "private-budget"])
def test_commit_iterator_refuses_invalid_budget_before_git(repo, monkeypatch, budget):
    def forbidden(*a, **kw):
        pytest.fail("invalid budget reached git")

    monkeypatch.setattr(gitsafe, "run", forbidden)
    with pytest.raises(gitsafe.GitError, match="^byte budget must be a positive integer$"):
        list(gitsafe.iter_objects(repo, [], byte_budget=budget))


def test_commit_iterator_verifies_sha256_objects_when_git_supports_them(tmp_path, monkeypatch):
    repo = tmp_path / "sha256"
    repo.mkdir()
    initialized = subprocess.run(["git", "init", "-q", "--object-format=sha256"], cwd=repo, capture_output=True)
    if b"unknown option" in initialized.stderr or b"unknown hash algorithm" in initialized.stderr:
        pytest.skip("git does not support SHA-256 repositories")
    assert initialized.returncode == 0, initialized.stderr
    _git(repo, "commit", "--allow-empty", "-qm", "SHA-256 commit")
    oid = _git(repo, "rev-parse", "HEAD").strip()
    assert len(oid) == 64
    expected = subprocess.run(["git", "cat-file", "commit", oid], cwd=repo, capture_output=True, check=True).stdout
    assert list(gitsafe.iter_objects(repo, [oid], kind="commit")) == [(oid, expected)]
    forged = f"{oid} commit {len(expected)}\n".encode("ascii") + b"X" + expected[1:] + b"\n"
    _answering(monkeypatch, forged)
    with pytest.raises(gitsafe.GitError, match=f"^git returned content for {oid} that does not match the object id$"):
        gitsafe.read_blobs(repo, [oid], kind="commit")
@pytest.mark.parametrize("extra_record", [True, False], ids=["extra-record", "missing-terminator"])
def test_commit_iterator_refuses_malformed_preflight_framing_before_capture(repo, monkeypatch, extra_record):
    oid = _git(repo, "rev-parse", "HEAD").strip()
    size = int(_git(repo, "cat-file", "-s", oid))
    header = f"{oid} commit {size}".encode("ascii")
    calls = []

    def forged(args, *a, **kw):
        calls.append(args)
        assert args == ["cat-file", "--batch-check"], "malformed preflight reached content capture"
        out = (header + b"\n") * 2 if extra_record else header
        return subprocess.CompletedProcess(args, 0, out, b"")

    monkeypatch.setattr(gitsafe, "run", forged)
    with pytest.raises(gitsafe.GitError, match=f"^git cannot read object {oid}$"):
        list(gitsafe.iter_objects(repo, [oid], kind="commit"))
    assert len(calls) == 1


@pytest.mark.parametrize("payload", [None, b"payload"], ids=["devnull", "input"])
def test_transport_extraction_preserves_legacy_default_argv_and_kwargs(repo, monkeypatch, payload):
    from types import SimpleNamespace
    seen = []
    def record(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 7, b"out\n", b"err\n")
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(
        run=record, DEVNULL=-321, TimeoutExpired=subprocess.TimeoutExpired))
    result = gitsafe.run(["version"], repo, timeout=2.5, stdin=payload)
    assert (result.returncode, result.stdout, result.stderr) == (7, b"out\n", b"err\n")
    argv, kwargs = seen[0]
    assert argv == [gitsafe.git_executable(), *gitsafe._HARDENING, "version"]
    assert {key: value for key, value in kwargs.items() if key != "env"} == {
        "cwd": str(repo), "input": payload, "stdin": -321 if payload is None else None,
        "capture_output": True, "timeout": 2.5, "check": False}
    expected = dict(os.environ)
    expected.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1",
                    GIT_ALLOW_PROTOCOL="", GIT_NO_LAZY_FETCH="1", LC_ALL="C")
    assert kwargs["env"] == expected


def test_legacy_facade_keeps_its_process_namespace_timeout_type(repo, monkeypatch):
    from types import SimpleNamespace
    class NamespaceTimeout(Exception):
        pass
    def timeout(*args, **kwargs):
        raise NamespaceTimeout()
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(
        run=timeout, DEVNULL=subprocess.DEVNULL, TimeoutExpired=NamespaceTimeout))
    with pytest.raises(gitsafe.GitError, match="^git version timed out after 2.5s$"):
        gitsafe.run(["version"], repo, timeout=2.5)


@pytest.mark.parametrize("extra", [0, 1], ids=["exact-ceiling", "overflow"])
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_custody_capture_ceiling_on_each_stream(repo, tmp_path, extra, stream):
    # hash-object --stdin emits a fixed-size OID; config's unknown key emits no
    # output, so use a real controlled process at the subprocess boundary.
    payload = b"x" * (128 + extra)
    code = "import os; os.write(" + ("1" if stream == "stdout" else "2") + ", " + repr(payload) + ")"
    with gitsafe.custody(scratch=tmp_path, stdout_limit=128, stderr_limit=128):
        if extra:
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe_run.capture([sys.executable, "-c", code], cwd=repo, env=dict(os.environ),
                                    stdin=None, timeout=2, error=gitsafe.GitError)
            assert caught.value.code == "git_output_limit"
        else:
            result = gitsafe_run.capture([sys.executable, "-c", code], cwd=repo, env=dict(os.environ),
                                        stdin=None, timeout=2, error=gitsafe.GitError)
            assert (result.stdout if stream == "stdout" else result.stderr) == payload


def test_custody_timeout_has_fixed_code_and_context_restores(repo, tmp_path):
    with gitsafe.custody(scratch=tmp_path):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe_run.capture([sys.executable, "-c", "import time; time.sleep(5)"], cwd=repo,
                                env=dict(os.environ), stdin=None, timeout=0.1, error=gitsafe.GitError)
        assert caught.value.code == "git_timeout"
        assert str(caught.value) == "git custody timed out"
    assert not gitsafe_run.custody_active()
    assert gitsafe.run(["version"], repo).stdout.startswith(b"git version")


@pytest.mark.parametrize("case", ["success", "overflow", "timeout"])
def test_windows_pipe_capture_uses_blocking_reads_and_keeps_limits(repo, tmp_path, monkeypatch, case):
    from types import SimpleNamespace
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    def fixed_poll(*args):
        pytest.fail("custody used fixed pipe polling")
    monkeypatch.setattr(gitsafe_run, "time", SimpleNamespace(**{**vars(time), "sleep": fixed_poll}))
    code = "import os; os.write(1, b'x' * " + ("129" if case == "overflow" else "128") + ")"
    if case == "timeout":
        code = "import time; time.sleep(5)"
    with gitsafe.custody(scratch=tmp_path, stdout_limit=128):
        if case == "success":
            result = gitsafe_run.capture([sys.executable, "-c", code], cwd=repo, env=dict(os.environ),
                                        stdin=None, timeout=2, error=gitsafe.GitError)
            assert result.stdout == b"x" * 128
        else:
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe_run.capture([sys.executable, "-c", code], cwd=repo, env=dict(os.environ),
                                    stdin=None, timeout=0.1 if case == "timeout" else 2, error=gitsafe.GitError)
            assert caught.value.code == ("git_timeout" if case == "timeout" else "git_output_limit")


def test_windows_pipe_reader_start_failure_is_typed_and_input_free(repo, tmp_path, monkeypatch):
    from types import SimpleNamespace
    class UnavailableThread:
        def __init__(self, **kwargs):
            pass
        def start(self):
            raise RuntimeError("hostile-payload")
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))
    monkeypatch.setattr(gitsafe_run, "Thread", UnavailableThread)
    with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo)
    assert caught.value.code == "git_failed"
    assert "hostile-payload" not in str(caught.value)


@pytest.mark.parametrize("kind", ["blob", "tree", "commit"])
def test_private_object_reader_keeps_objects_private_and_enforces_size(repo, tmp_path, kind):
    scratch = tmp_path / "private"
    scratch.mkdir(mode=0o700)
    objects = scratch / "objects"
    objects.mkdir(mode=0o700)
    env = {"GIT_OBJECT_DIRECTORY": str(objects),
           "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repo / ".git/objects")}
    blob = gitsafe.run(["hash-object", "-w", "--stdin"], repo, stdin=b"private tree child", _env=env).stdout.decode().strip()
    data = {"blob": b"private", "tree": b"100644 child\0" + bytes.fromhex(blob), "commit": (
        b"tree " + _git(repo, "rev-parse", "HEAD^{tree}").strip().encode() +
        b"\nauthor A <a@example.com> 1700000000 +0000\ncommitter A <a@example.com> 1700000000 +0000\n\nprivate\n")}[kind]
    oid = gitsafe.run(["hash-object", "-w", "-t", kind, "--stdin"], repo, stdin=data, _env=env).stdout.decode().strip()
    assert gitsafe.read_private_object(repo, oid, kind=kind, max_bytes=len(data), env=env, scratch=scratch) == data
    if data:
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.read_private_object(repo, oid, kind=kind, max_bytes=len(data)-1, env=env, scratch=scratch)
        assert caught.value.code == "git_object_limit"
    absent = gitsafe.run(["cat-file", "-e", oid], repo)
    assert absent.returncode != 0


def test_private_batch_reads_mixed_objects_and_preflights_aggregate_limit(repo, tmp_path, monkeypatch):
    oids = [_git(repo, "rev-parse", rev).strip() for rev in ("HEAD", "HEAD^{tree}", "HEAD:a.py")]
    expected = {oid: (kind, gitsafe.read_private_object(repo, oid, kind=kind, max_bytes=10000,
                env={}, scratch=tmp_path)) for oid, kind in zip(oids, ("commit", "tree", "blob"))}
    total = sum(len(data) for kind, data in expected.values())
    calls, real = [], gitsafe.run
    def record(args, *rest, **kwargs):
        calls.append(args)
        return real(args, *rest, **kwargs)
    monkeypatch.setattr(gitsafe, "run", record)
    assert gitsafe.read_private_objects(repo, oids, max_bytes=total, max_object_bytes=10000,
                                        env={}, scratch=tmp_path) == expected
    assert calls == [["cat-file", "--batch-check"], ["cat-file", "--batch"]]
    calls.clear()
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.read_private_objects(repo, oids, max_bytes=total - 1, max_object_bytes=10000,
                                     env={}, scratch=tmp_path)
    assert caught.value.code == "git_object_limit"
    assert calls == [["cat-file", "--batch-check"]]


@pytest.mark.parametrize("failure", ["large-size", "wrong-kind", "missing", "trailing", "hash"])
def test_private_batch_refuses_malformed_frames_without_echo(repo, tmp_path, monkeypatch, failure):
    oid = _git(repo, "rev-parse", "HEAD:a.py").strip()
    real = gitsafe.run
    calls = []
    def corrupt(args, *rest, **kwargs):
        calls.append(args)
        result = real(args, *rest, **kwargs)
        if args == ["cat-file", "--batch-check"]:
            if failure == "large-size":
                result.stdout = oid.encode() + b" blob " + b"9" * 21 + b"\n"
            elif failure == "wrong-kind":
                result.stdout = oid.encode() + b" hostile-payload 1\n"
            elif failure == "missing":
                result.stdout = oid.encode() + b" missing\n"
        elif args == ["cat-file", "--batch"]:
            result.stdout = result.stdout + b"hostile-payload" if failure == "trailing" else result.stdout.replace(b"a = 1", b"a = 2")
        return result
    monkeypatch.setattr(gitsafe, "run", corrupt)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.read_private_objects(repo, [oid], max_bytes=10000, max_object_bytes=10000,
                                     env={}, scratch=tmp_path)
    assert caught.value.code == "invalid_object"
    assert str(caught.value) == "invalid private object"
    if failure in ("large-size", "wrong-kind", "missing"):
        assert calls == [["cat-file", "--batch-check"]]


def test_single_attempt_ref_update_and_legacy_defaults(repo, tmp_path, monkeypatch):
    real_run = gitsafe.run
    oid = _git(repo, "rev-parse", "HEAD").strip()
    attempts = []
    def unknown(args, cwd, **kwargs):
        if "update-ref" in args:
            attempts.append(args)
            raise gitsafe.GitError("git custody timed out", code="git_timeout")
        return real_run(args, cwd, **kwargs)
    monkeypatch.setattr(gitsafe, "run", unknown)
    with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
        gitsafe.update_ref(repo, "refs/aegis/once", oid, None, single_attempt=True)
    assert caught.value.code == "ref_update_unknown" and len(attempts) == 1
    monkeypatch.setattr(gitsafe, "run", real_run)
    assert gitsafe.update_ref(repo, "refs/aegis/legacy", oid, None) is None
    assert gitsafe.read_ref(repo, "refs/aegis/legacy") == oid


def test_custody_queries_preserve_refusals_and_legacy_fallback(repo, tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise gitsafe.GitError("never echo this input", code="privacy_refused")
    monkeypatch.setattr(gitsafe, "run", refuse)
    for query in (gitsafe.common_dir, gitsafe.toplevel, gitsafe.git_version):
        with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
            query(repo)
        assert caught.value.code == "privacy_refused"
        assert query(repo) is None


def test_expired_input_preparation_never_starts_a_process(repo, tmp_path, monkeypatch):
    from types import SimpleNamespace
    ticks = iter((0, 1, 1, 1, 1))
    def unexpected(*args, **kwargs):
        pytest.fail("expired request started a process")
    monkeypatch.setattr(gitsafe_run, "time", SimpleNamespace(**{**vars(time), "monotonic": lambda: next(ticks)}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.capture([sys.executable], cwd=repo, env=dict(os.environ), stdin=b"input", timeout=0.1,
                            error=gitsafe.GitError)
    assert caught.value.code == "git_timeout"


def test_capture_closes_both_pipes_even_when_one_close_raises(repo, tmp_path, monkeypatch):
    from types import SimpleNamespace
    events, streams = [], []
    class Pipe:
        def __init__(self, name):
            self.name = name
            self.fd, write = os.pipe()
            os.close(write)
            self.closed = False
        def fileno(self):
            return self.fd
        def close(self):
            if not self.closed:
                self.closed = True
                events.append(self.name)
                os.close(self.fd)
                if self.name == "stdout":
                    raise OSError("must not echo cleanup input")
    class Child:
        def __init__(self, *args, **kwargs):
            self.stdout, self.stderr = Pipe("stdout"), Pipe("stderr")
            streams.extend((self.stdout, self.stderr))
            self.returncode = 0
        def wait(self, **kwargs):
            return 0
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": Child}))
    try:
        with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
            gitsafe_run.capture([sys.executable], cwd=repo, env=dict(os.environ), stdin=None, timeout=2,
                                error=gitsafe.GitError)
        observed = tuple(events)
        assert caught.value.code == "git_cleanup_failed"
        assert observed == ("stdout", "stderr")
        assert "input" not in str(caught.value)
    finally:
        for stream in streams:
            if not stream.closed:
                stream.close()


def test_custody_checked_bridge_cannot_downgrade_or_echo_a_refusal(repo, tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise gitsafe.GitError("private input never displayed", code="privacy_refused")
    monkeypatch.setattr(gitsafe, "run", refuse)
    with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run_checked(["version"], repo, error=ValueError)
    assert caught.value.code == "privacy_refused"
    # Outside custody, the same explicitly requested legacy conversion remains.
    with pytest.raises(ValueError, match="^private input never displayed$"):
        gitsafe.run_checked(["version"], repo, error=ValueError)


# GM-4c: effect custody is explicit and the caller retains ownership of its fd.
@pytest.fixture
def effect_lock(tmp_path):
    if not gitops_fds.descriptor_supported():
        pytest.skip("effect custody requires Linux child subreaper support")
    import fcntl
    with (tmp_path / "effect.lock").open("w+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        yield stream.fileno()


def _effect_call(site, repo, scratch, fd, *, payload=b"", options=None):
    """Exercise every facade/runner entry, without mocking a process boundary."""
    kw = {"effect_fds": (fd,)}
    if options:
        kw.update(options)
    if site == "run":
        return gitsafe.run(["version"], repo, stdin=payload, **kw, worktree_root=repo)
    if site == "execute":
        return gitsafe_run.execute(["version"], repo, executable=gitsafe.git_executable,
            legacy_runner=gitsafe.subprocess.run, error=gitsafe.GitError, environ=os.environ,
            timeout=5, stdin=payload, hardening=gitsafe._HARDENING, env=None, tty=False, **kw, worktree_root=repo)
    if site == "capture":
        with gitsafe.custody(scratch=scratch, worktree_root=repo):
            return gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo,
                env=dict(os.environ), stdin=payload, timeout=5, error=gitsafe.GitError, **kw, worktree_root=repo)
    lane = gitsafe.lane_runner(repo, scratch, effect_fds=kw["effect_fds"], worktree_root=repo)
    if site == "publish":
        (scratch / "objects").mkdir(exist_ok=True)
        return lane.publish(payload, **kw)
    return lane.run(["version"], **kw)


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX descriptor inheritance validation")
@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
@pytest.mark.parametrize("bad", ["closed", "pipe", "negative", "bool", "many"])
def test_effect_descriptor_refused_before_any_spawn(repo, tmp_path, monkeypatch, site, bad):
    from types import SimpleNamespace
    import contextlib
    with contextlib.ExitStack() as stack:
        stream = stack.enter_context((tmp_path / "lock").open("w+b"))
        fd = stream.fileno()
        os.set_inheritable(fd, bad != "noninheritable")
        fds = (fd,)
        if bad == "closed":
            stream.close()
        elif bad == "pipe":
            read, write = os.pipe()
            stack.callback(os.close, read)
            stack.callback(os.close, write)
            os.set_inheritable(read, True)
            fds = (read,)
        elif bad == "negative":
            fds = (-1,)
        elif bad == "bool":
            fds = (True,)
        elif bad == "many":
            fds = (fd, fd)
        def unexpected(*args, **kwargs):
            pytest.fail("invalid descriptor reached a subprocess")
        monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": unexpected}))
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
        with pytest.raises(gitsafe.GitError) as caught:
            _effect_call(site, repo, tmp_path, fd, options={"effect_fds": fds})
        assert caught.value.code == "invalid_effect_descriptor"
        assert str(caught.value) == "Git operation effect descriptor refused."
        assert caught.value.next_action and caught.value.process_started is False


@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
def test_effect_unsupported_platform_is_a_pre_spawn_refusal(repo, tmp_path, monkeypatch, site):
    monkeypatch.setattr(gitops_fds, "descriptor_supported", lambda: False)
    with pytest.raises(gitsafe.GitError) as caught:
        _effect_call(site, repo, tmp_path, 17)
    assert caught.value.code == "unsupported_effect_platform"
    assert caught.value.process_started is False and caught.value.next_action


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
def test_effect_pipes_and_receipt_ownership_survive_retry(repo, tmp_path, effect_lock, site):
    import struct
    import hashlib
    payload = b"PACK" + struct.pack("!II", 2, 0)
    payload += hashlib.sha1(payload).digest()
    for _ in range(2):
        result = _effect_call(site, repo, tmp_path, effect_lock, payload=payload if site == "publish" else b"input")
        assert result.returncode == 0
        assert result.stderr == b""
        if site != "publish":
            assert result.stdout.startswith(b"git version ")
        os.fstat(effect_lock)
        assert not os.get_inheritable(effect_lock)


def _effect_survivor_program():
    """Trusted shim launches real Git; named pipes supply readiness and stdin."""
    return '''import os, stat, subprocess
ready = os.open(os.environ["GM4_READY"], os.O_WRONLY)
source = os.open(os.environ["GM4_INPUT"], os.O_RDONLY)
fd = int(os.environ["GM4_FD"])
try:
    inherited = (fd,) if stat.S_ISREG(os.fstat(fd).st_mode) else ()
except OSError:
    inherited = ()
if os.environ.get("GM4_REAL_REMOTE"):
    from pathlib import Path
    Path(os.environ["GM4_PARENT_FILE"]).write_text(str(os.getppid()), encoding="ascii")
def launch(source):
    return subprocess.Popen([os.environ["GM4_GIT"], "cat-file", "--batch"],
        cwd=os.environ["GM4_REPO"], stdin=source, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, pass_fds=inherited,
        env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")})
p = launch(source)
from pathlib import Path
Path(os.environ["GM4_WORKER_FILE"]).write_text(str(p.pid), encoding="ascii")
os.write(ready, b"R")
p.wait(timeout=20)
'''


def _child_readiness_failure(child, reason):
    """Snapshot bounded stderr without waiting for an exited or stalled child."""
    status = child.poll()
    raw = bytearray()
    if child.stderr is not None:
        fd = child.stderr.fileno()
        blocking = os.get_blocking(fd)
        try:
            os.set_blocking(fd, False)
            while len(raw) < 65536:
                try:
                    chunk = os.read(fd, min(4096, 65536 - len(raw)))
                except BlockingIOError:
                    break
                if not chunk:
                    break
                raw.extend(chunk)
        finally:
            os.set_blocking(fd, blocking)
    stderr = gitsafe_run.sanitize_display(gitsafe_run.redact_insight_text(
        gitsafe_run.sanitize_display(raw.decode("utf-8", "replace"), max_len=None), max_len=65536), max_len=4096)
    return f"{reason}; owner exit status={status if status is not None else 'running'}; stderr={stderr or '<empty>'}"


def _wait_for_child_ready(child, ready_fd, timeout, reason):
    """Report an early child exit immediately, or a bounded readiness timeout."""
    import select
    deadline = time.monotonic() + timeout
    while True:
        if child.poll() is not None:
            pytest.fail(_child_readiness_failure(child, reason))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail(_child_readiness_failure(child, reason))
        if select.select([ready_fd], [], [], min(remaining, 0.1))[0]:
            return


@pytest.mark.skipif(os.name != "posix", reason="POSIX nonblocking pipe readiness")
@pytest.mark.parametrize("state", ["exited", "stalled"])
def test_owner_readiness_reports_status_and_available_stderr(tmp_path, state):
    import select
    read, write = os.pipe()
    child = None
    try:
        code = "import os,sys;os.write(2,b'fixture failure\\n');os.write(1,b'R');" + (
            "sys.exit(23)" if state == "exited" else "sys.stdin.buffer.read(1)")
        child = subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert select.select([child.stdout], [], [], 5)[0], _child_readiness_failure(child, "diagnostic fixture did not start")
        assert os.read(child.stdout.fileno(), 1) == b"R"
        if state == "exited":
            child.wait(timeout=5)
        status = "23" if state == "exited" else "running"
        with pytest.raises(pytest.fail.Exception, match="owner exit status=" + status + "; stderr=fixture failure"):
            _wait_for_child_ready(child, read, 0, "fixture readiness failed")
        assert os.get_blocking(child.stderr.fileno())
    finally:
        os.close(read)
        os.close(write)
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="POSIX nonblocking stderr descriptor")
def test_owner_readiness_stderr_is_bounded_canonicalized_and_redacted(tmp_path):
    from types import SimpleNamespace
    token = "ghp_" + "A" * 36
    with (tmp_path / "stderr").open("w+b") as stream:
        child = subprocess.run([sys.executable, "-I", "-c", "import os;os.write(2," + repr(
            ("gh\x1b[31mp_" + "A" * 36 + "\x1b[0m\n" + "x" * 100000).encode()) + ");raise SystemExit(23)"],
            stderr=stream, timeout=5, check=False)
        stream.seek(0)
        message = _child_readiness_failure(SimpleNamespace(poll=lambda: child.returncode, stderr=stream), "fixture failed")
        assert "owner exit status=23" in message and "redacted" in message.lower()
        assert token not in message and "\x1b" not in message and "\n" not in message
        assert message.endswith("...") and len(message) <= 4200
        assert stream.tell() == 65536 and os.get_blocking(stream.fileno())


def test_owner_native_fixture_without_a_compiler_skips_before_child(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(gitsafe_run, "_program_supported", lambda: True)
    which = shutil.which
    monkeypatch.setattr("tests.unit.core.test_gitsafe.shutil", SimpleNamespace(**{**vars(shutil),
        "which": lambda name: None if name == "cc" else which(name)}))
    def forbidden(*args, **kwargs):
        pytest.fail("missing fixture compiler started an owner child")
    monkeypatch.setattr("tests.unit.core.test_gitsafe.subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    with pytest.raises(pytest.skip.Exception, match="native strict-effect fixture needs an installed C compiler"):
        _assert_effect_survives_owner(tmp_path, tmp_path, "run")


def _owner_test_environment(tmp_path, *, ambient=None, **values):
    """Readiness fixtures supply their own environment, including an empty HOME."""
    home = tmp_path / "owner-home"
    home.mkdir(exist_ok=True)
    source = os.environ if ambient is None else ambient
    return {"PATH": source.get("PATH", os.defpath), "HOME": str(home),
            "TMPDIR": str(tmp_path), "LC_ALL": "C", **values}


def _assert_effect_survives_owner(tmp_path, repo, site, *, reconciliation=None, cleanup_event=None, environ=None):
    """No sleeps: pipe readiness, process exit and a blocking flock supply all latches."""
    strict_program_guard(native_fixture=site != "remote_git")
    from aegis_core import team_gitops
    if not team_gitops.descriptor_supported() or not gitops_fds.descriptor_supported():
        pytest.skip("descriptor-relative journal requires POSIX no-follow operations")
    import select
    if site == "remote_git" and not hasattr(os, "pidfd_open"):
        pytest.skip("remote-helper death latch requires Linux pidfds")
    from threading import Event, Thread
    import fcntl
    template = tmp_path / "native-template"
    if site != "remote_git":
        _native_program(template, "#!/bin/sh\nexit 0\n")
    script = tmp_path / "effect-child"
    script.write_text("#!" + sys.executable + "\n" + _effect_survivor_program(), encoding="utf-8")
    script.chmod(0o700)
    ready_path, input_path = tmp_path / "ready.fifo", tmp_path / "input.fifo"
    os.mkfifo(ready_path)
    os.mkfifo(input_path)
    common = tmp_path / "common"
    common.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    import hashlib
    lock = common / "aegis" / ("gitops-effect-" + hashlib.sha256(b"request-1").hexdigest() + ".lock")
    owner_code = 'import inspect, os, sys\nsys.path.insert(0, sys.argv[1])\nfrom aegis_core import gitsafe, gitsafe_run, ghcli\nfrom tests.unit.core.test_gitsafe import _native_program\nimport fcntl\nrepo, scratch, script, site, lock = sys.argv[2:]\nfrom aegis_core.team_gitops import GitOpsJournal\nfrom pathlib import Path\nreceipt = GitOpsJournal(Path(lock).parent.parent).record_intent(op="push", lane="lane-1", request_id="request-1",\n    actor="session-1", expected_old="a" * 40, expected_new="b" * 40)\nfd, = receipt.inheritable_fds()\nos.set_inheritable(fd, False)\nos.environ["GM4_FD"] = str(fd)\nfrom pathlib import Path\nshim = Path(script)\nbody = shim.read_text(encoding="utf-8")\nfixed = {k: v for k, v in os.environ.items() if k.startswith("GM4_")}\nshim.write_text(body.split("\\n", 1)[0] + "\\nimport os\\nos.environ.update(" + repr(fixed) + ")\\n" + body.split("\\n", 1)[1], encoding="utf-8")\nkw = {"effect_fds": (fd,)} if "effect_fds" in inspect.signature(gitsafe.run).parameters else {}\nif site == "remote_git":\n    helper = Path(script).with_name("git-remote-aegisguard")\n    helper.write_text(shim.read_text(encoding="utf-8"), encoding="utf-8")\n    helper.chmod(0o700)\n    os.environ["PATH"] = str(helper.parent) + os.pathsep + os.environ["PATH"]\n    gitsafe.run(["-c", "protocol.aegisguard.allow=always", "push", "aegisguard::target", "HEAD:refs/heads/test"],\n        repo, _environ=dict(os.environ), _env={"GIT_ALLOW_PROTOCOL": "aegisguard"}, **kw, worktree_root=repo)\nelif site in ("gh", "gh_injected"):\n    _native_program(Path(script).with_name("gh"), shim.read_text(encoding="utf-8"))\n    runner = ghcli.default_gh_runner\n    if site == "gh_injected" and kw:\n        runner = ghcli.effect_runner(runner, kw["effect_fds"], worktree_root=repo)\n        kw = {}\n    runner(["api", "user"], env={**os.environ, "GH_TOKEN": "fixture-public-token"}, **kw, worktree_root=repo)\nelif site == "run":\n    git = Path(script).with_name("git")\n    _native_program(git, shim.read_text())\n    git.chmod(0o700)\n    os.environ["PATH"] = str(git.parent) + os.pathsep + os.environ["PATH"]\n    gitsafe.run(["version"], repo, **kw, worktree_root=repo)\nelif site == "execute":\n    source = shim.read_text(encoding="utf-8")\n    _native_program(shim, source)\n    git = Path(script).with_name("git")\n    _native_program(git, source)\n    git.chmod(0o700)\n    os.environ["PATH"] = str(git.parent) + os.pathsep + os.environ["PATH"]\n    gitsafe_run.execute(["version"], repo, executable=lambda **kwargs: script, legacy_runner=__import__("subprocess").run,\n        error=gitsafe.GitError, environ=os.environ, timeout=20, stdin=None,\n        hardening=gitsafe._HARDENING, env=None, tty=False, **kw, worktree_root=repo)\nelif site == "capture":\n    _native_program(shim, shim.read_text(encoding="utf-8"))\n    with gitsafe.custody(scratch=__import__("pathlib").Path(scratch), worktree_root=repo):\n        gitsafe_run.capture([script, "version"], cwd=repo, env=dict(os.environ), stdin=None,\n            timeout=20, error=gitsafe.GitError, **kw, worktree_root=repo)\nelse:\n    _native_program(shim, shim.read_text(encoding="utf-8"))\n    if site == "lane_runner":\n        gitsafe.custody_program = lambda cwd, **kwargs: script\n    gitsafe.git_executable = lambda **kwargs: script\n    lane = gitsafe.lane_runner(repo, scratch, **(kw if site == "lane_runner" else {}), worktree_root=repo)\n    if site == "publish":\n        lane.publish(b"", **kw)\n    else:\n        lane.run(["version"], **kw)\n'
    owner_code = owner_code.replace("from tests.unit.core.test_gitsafe import _native_program\n",
        "from tests.unit.core.test_gitsafe import _native_program, _NATIVE_STUB\n"
        "from pathlib import Path\n_NATIVE_STUB['binary'] = Path(sys.argv.pop())\n")
    env = _owner_test_environment(tmp_path, ambient=environ, GM4_READY=str(ready_path), GM4_INPUT=str(input_path),
        GM4_GIT=gitsafe.git_executable(), GM4_REPO=str(repo), GM4_WORKER_FILE=str(tmp_path / "worker.pid"))
    if site == "remote_git":
        env.update(GM4_REAL_REMOTE="1", GM4_PARENT_FILE=str(tmp_path / "effect-parent.pid"))
    if site in ("gh", "gh_injected"):
        gh = tmp_path / "gh"
        gh.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
        gh.chmod(0o700)
        env["PATH"] = str(tmp_path) + os.pathsep + env["PATH"]
    ready_fd = os.open(ready_path, os.O_RDONLY | os.O_NONBLOCK)
    ready_writer = os.open(ready_path, os.O_WRONLY)
    input_fd = os.open(input_path, os.O_RDWR)
    owner = subprocess.Popen([sys.executable, "-I", "-c", owner_code, str(ROOT), str(repo),
        str(scratch), str(script), site, str(lock), str(template)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    worker_fd = None
    try:
        ready = b""
        while len(ready) < 1:
            _wait_for_child_ready(owner, ready_fd, 10, "effect child did not signal readiness")
            ready += os.read(ready_fd, 2)
        assert b"R" in ready
        if site == "remote_git":
            worker_fd = os.pidfd_open(int((tmp_path / "worker.pid").read_text()))
        os.close(ready_writer)
        ready_writer = None
        from aegis_core import team_gitops
        store = team_gitops.GitOpsJournal(common)
        observe = store.reconcile if reconciliation is None else lambda *args: reconciliation(store, *args)
        assert observe("lane-1", lambda _: pytest.fail("live child was observed")) == []
        owner.kill()
        owner.wait(timeout=10)
        if site == "remote_git":
            import signal
            os.kill(int((tmp_path / "effect-parent.pid").read_text(encoding="ascii")), signal.SIGKILL)
            if cleanup_event is not None:
                cleanup_event(worker_fd, lock)
        with lock.open("r+b") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                assert worker_fd is not None and select.select([worker_fd], [], [], 0)[0], "custody freed before descendant exit"
                fcntl.flock(probe, fcntl.LOCK_UN)
            released = Event()
            def acquire():
                fcntl.flock(probe, fcntl.LOCK_EX)
                released.set()
            waiter = Thread(target=acquire, daemon=True)
            waiter.start()
            os.close(input_fd)
            input_fd = None
            assert released.wait(10), "effect/descendant exited but lock remained held"
            waiter.join(timeout=1)
        observed = observe("lane-1", lambda _: team_gitops.Observation("a" * 40))
        assert [row["status"] for row in observed] == ["not_applied"]
        assert observe("lane-1", lambda _: pytest.fail("terminal intent observed twice")) == []
    finally:
        if worker_fd is not None:
            os.close(worker_fd)
        if input_fd is not None:
            os.close(input_fd)
        if ready_writer is not None:
            os.close(ready_writer)
        os.close(ready_fd)
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=10)


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX descriptor locks, fork and FIFO latch")
@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
def test_effect_lock_covers_owner_death(repo, tmp_path, site):
    ambient = {**os.environ, "GIT_EDITOR": "fixture-host-program", "GIT_PAGER": "fixture-host-program",
               "PAGER": "fixture-host-program", "GH_PAGER": "fixture-host-program"}
    _assert_effect_survives_owner(tmp_path, repo, site, environ=ambient)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
@pytest.mark.parametrize("failure", ["enoent", "emfile"])
def test_effect_failed_spawn_retains_descriptor_and_leaks_nothing(repo, tmp_path, effect_lock, monkeypatch, site, failure):
    import errno
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo) if site in ("lane_run", "publish") else None
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").is_dir() else None
    calls = []
    def fail(*args, **kwargs):
        calls.append(kwargs)
        assert kwargs["pass_fds"][0] == effect_lock and len(kwargs["pass_fds"]) == 5
        raise OSError(errno.ENOENT if failure == "enoent" else errno.EMFILE, "secret-input")
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": fail}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": fail}))
    for _ in range(2):
        with pytest.raises(gitsafe.GitError) as caught:
            if site == "lane_run":
                lane.run(["version"], stdin=b"input", effect_fds=(effect_lock,))
            elif site == "publish":
                lane.publish(b"input", effect_fds=(effect_lock,))
            else:
                _effect_call(site, repo, tmp_path, effect_lock, payload=b"input")
        assert caught.value.code == "git_failed" and caught.value.process_started is False
        assert "secret-input" not in str(caught.value)
        assert not os.get_inheritable(effect_lock)
        os.fstat(effect_lock)
        if before is not None:
            assert set(os.listdir("/proc/self/fd")) == before
    assert len(calls) == 2


@pytest.mark.parametrize("effect", [False, True], ids=["legacy", "effect"])
@pytest.mark.parametrize("site", ["capture", "lane_run", "publish", "lane_runner"])
def test_effect_capture_spawn_golden_and_exactly_one_extra_fd(repo, tmp_path, monkeypatch, effect, site):
    from types import SimpleNamespace
    import struct
    import hashlib
    if effect or site != "capture":
        strict_program_guard()
    if (effect or site != "capture") and not gitops_fds.descriptor_supported():
        pytest.skip("strict and effect transport require descriptor-bound executables")
    calls = []
    def launch(argv, **kwargs):
        calls.append((argv, kwargs.copy()))
        return subprocess.Popen(argv, **kwargs)
    with (tmp_path / "lock").open("w+b") as stream:
        if effect:
            gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
        kw = {"effect_fds": (stream.fileno(),)} if effect else {}
        if site == "capture":
            with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                result = gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo,
                    env=dict(os.environ), stdin=b"hello", timeout=5, **kw, worktree_root=repo)
            assert result.returncode == 0
        else:
            lane = gitsafe.lane_runner(repo, tmp_path, **kw, worktree_root=repo)
            if site == "publish":
                (tmp_path / "objects").mkdir()
                payload = b"PACK" + struct.pack("!II", 2, 0)
                payload += hashlib.sha1(payload).digest()
                assert lane.publish(payload, **kw).returncode == 0
            else:
                assert lane.run(["version"], **kw).returncode == 0
        for argv, kwargs in calls:
            expected_keys = {"cwd", "env", "stdin", "stdout", "stderr", "start_new_session"}
            assert set(kwargs) == expected_keys | ({"executable"} if effect or site != "capture" else set()) | ({"pass_fds"} if effect else set())
            if effect:
                assert kwargs["pass_fds"][0] == stream.fileno() and len(kwargs["pass_fds"]) == 5
            assert kwargs["stdout"] == subprocess.PIPE and kwargs["stderr"] == subprocess.PIPE
            assert kwargs["start_new_session"] == (os.name == "posix")
            if kwargs["stdin"] != subprocess.DEVNULL:
                assert kwargs["stdin"].closed
            if not effect and site == "capture":
                assert argv == [gitsafe.git_executable(), "version"]
                assert kwargs["env"] == dict(os.environ)
        assert len(calls) == (1 if site == "capture" else 5)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX effect descriptor inheritance")
def test_effect_git_config_queries_preserve_owner_programs_and_disable_automatic_maintenance(repo, tmp_path, effect_lock):
    # Queries do not execute the named program. Owner selection is permitted;
    # transport-specific daemon refusal is covered through real push/fetch.
    for name, attempted, expected in [
        ("credential.helper", "cache --timeout=999", b"cache --timeout=999\n"),
        ("core.sshCommand", "ssh -oControlPersist=yes", b"ssh -oControlPersist=yes\n"),
        ("gc.auto", "1", b"0\n"),
        ("gc.autoDetach", "true", b"false\n"),
        ("maintenance.auto", "true", b"false\n"),
    ]:
        result = gitsafe.run(["-c", name + "=" + attempted, "config", "--get", name], repo,
                             effect_fds=(effect_lock,), worktree_root=repo)
        assert result.returncode == 0 and result.stdout == expected
    for command in (["gc"], ["maintenance", "start"], ["credential-cache", "--daemon"], ["untrusted-alias"]):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.run(command, repo, effect_fds=(effect_lock,), worktree_root=repo)
        assert caught.value.code == "effect_command_refused"
        assert caught.value.process_started is False


@pytest.mark.usefixtures("strict_program")
def test_effect_receipt_export_is_usable_without_changing_descriptor_ownership(tmp_path):
    from aegis_core import team_gitops
    _repo(tmp_path)
    if not team_gitops.descriptor_supported() or not gitops_fds.descriptor_supported():
        pytest.skip("descriptor-relative journal requires POSIX no-follow operations")
    root = tmp_path / "common"
    root.mkdir()
    store = team_gitops.GitOpsJournal(root)
    with store.record_intent(op="push", lane="lane-1", request_id="request-1", actor="session-1",
                             expected_old="a" * 40, expected_new="b" * 40) as receipt:
        fds = receipt.inheritable_fds()
        assert len(fds) == 1 and not os.get_inheritable(fds[0])
        assert receipt.inheritable_fds() == fds
        before = os.fstat(fds[0])
        result = gitsafe.run(["version"], tmp_path, effect_fds=fds, worktree_root=tmp_path)
        assert result.returncode == 0 and os.fstat(fds[0]) == before
        assert store.reconcile("lane-1", lambda _: pytest.fail("live receipt was observed")) == []
    with pytest.raises(team_gitops.GitOpsError) as caught:
        receipt.inheritable_fds()
    assert caught.value.code == "effect_busy"


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX Git remote-helper descriptor inheritance")
def test_effect_real_git_remote_helper_keeps_lock_after_git_and_owner_die(repo, tmp_path):
    _assert_effect_survives_owner(tmp_path, repo, "remote_git")


@pytest.mark.parametrize("site", ["run", "execute", "capture"])
@pytest.mark.parametrize("bad", ["many_args", "long_arg", "nul_arg", "bad_arg", "bad_stdin", "huge_timeout", "nan_timeout"])
def test_effect_inputs_are_bounded_before_lookup_or_spawn(repo, tmp_path, effect_lock, monkeypatch, site, bad):
    args, data, timeout = ["version"], None, 5
    if bad == "many_args":
        args = ["version"] * 513
    elif bad == "long_arg":
        args = ["version", "x" * 16385]
    elif bad == "nul_arg":
        args = ["version", "x\0y"]
    elif bad == "bad_arg":
        args = ["version", 1]
    elif bad == "bad_stdin":
        data = "untrusted-text"
    elif bad == "huge_timeout":
        timeout = 10 ** 400
    elif bad == "nan_timeout":
        timeout = float("nan")
    def unexpected(*args, **kwargs):
        pytest.fail("invalid effect input reached executable lookup or spawn")
    monkeypatch.setattr(gitsafe, "git_executable", unexpected)
    from types import SimpleNamespace
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    with pytest.raises(gitsafe.GitError) as caught:
        if site == "run":
            gitsafe.run(args, repo, stdin=data, timeout=timeout, effect_fds=(effect_lock,), worktree_root=repo)
        elif site == "capture":
            with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                gitsafe_run.capture(["git", *args], cwd=repo, env=dict(os.environ), stdin=data,
                    timeout=timeout, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            gitsafe_run.execute(args, repo, executable=unexpected, legacy_runner=unexpected,
                error=gitsafe.GitError, environ=os.environ, timeout=timeout, stdin=data,
                hardening=gitsafe._HARDENING, env=None, tty=False, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_command_refused"
    assert caught.value.process_started is False and caught.value.next_action


_IMPORT_PROBE = '\nimport importlib, json, os, subprocess, sys\nfrom pathlib import Path\nsys.path.insert(0, sys.argv[1])\nmodule, operation, root = sys.argv[2], sys.argv[3], Path(sys.argv[4])\nloaded = importlib.import_module(module)\nassert "aegis_core.gitops_fds" not in sys.modules, "effect module imported eagerly"\nif operation == "effect_success":\n    from aegis_core import gitops_fds\n    with (root / "effect.lock").open("w+b") as held:\n        gitops_fds.receipt_fds(held.fileno(), error=gitops_fds.AegisError)\n        effect = {"effect_fds": (held.fileno(),), "worktree_root": root}\n        if module.endswith(("gitsafe", "gitsafe_run")):\n            subprocess.run([sys.argv[5], "init", "-q", str(root)], check=True, capture_output=True)\n        if module.endswith("gitsafe"):\n            assert loaded.run(["version"], root, **effect).returncode == 0\n        elif module.endswith("gitsafe_run"):\n            from aegis_core import gitsafe, gitops_fds\n            with gitsafe.custody(scratch=root, worktree_root=root):\n                assert loaded.capture([gitsafe.git_executable(), "version"], cwd=root,\n                    env=dict(os.environ), stdin=None, timeout=5, error=gitsafe.GitError, **effect).returncode == 0\n        elif module.endswith("ghcli"):\n            stub = root / "gh"\n            from tests.unit.core.test_gitsafe import _native_program\n            _native_program(stub, "#!" + sys.executable + "\\nprint(\'{}\')\\n", compiler=sys.argv[6])\n            stub.chmod(0o700)\n            (root / "checkout").mkdir()\n            subprocess.run([sys.argv[5], "init", "-q", str(root / "checkout")], check=True, capture_output=True)\n            os.chdir(root / "checkout")\n            effect["worktree_root"] = root / "checkout"\n            assert loaded.default_gh_runner(["api", "user"], env={"PATH": str(root), "TMPDIR": str(root), "GH_TOKEN": "fixture-public-token"}, **effect).returncode == 0\n        else:\n            if not loaded.descriptor_supported():\n                print(json.dumps({"unsupported": True}))\n                sys.exit(0)\n            common = root / "common"\n            common.mkdir()\n            with loaded.GitOpsJournal(common).record_intent(op="push", lane="lane-1", request_id="request-1",\n                    actor="session-1", expected_old="a" * 40, expected_new="b" * 40) as receipt:\n                assert len(receipt.inheritable_fds()) == 1\n    print(json.dumps({"loaded": "aegis_core.gitops_fds" in sys.modules}))\n    sys.exit(0)\nif module in ("aegis_core.gitsafe", "aegis_core.gitsafe_run"):\n    from aegis_core import gitsafe, gitsafe_run\n    if operation != "import":\n        effect = {"effect_fds": (-1,)} if operation == "effect" else {}\n        try:\n            if module.endswith("gitsafe_run"):\n                with gitsafe.custody(scratch=root, worktree_root=root):\n                    gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=root,\n                        env=dict(os.environ), stdin=None, timeout=5, error=gitsafe.GitError, **effect, worktree_root=root)\n            else:\n                assert gitsafe.run(["version"], root, **effect, worktree_root=root).returncode == 0\n        except gitsafe.GitError as error:\n            assert operation == "effect" and error.code in ("invalid_effect_descriptor", "unsupported_effect_platform")\nelif module.endswith("ghcli"):\n    if operation != "import":\n        effect = {"effect_fds": (-1,)} if operation == "effect" else {}\n        try:\n            loaded.default_gh_runner(["api", "user"], **effect)\n        except Exception as error:\n            assert operation == "effect" and error.code in ("invalid_effect_descriptor", "unsupported_effect_platform")\nelse:\n    if operation != "import":\n        if loaded.descriptor_supported():\n            common = root / "common"\n            common.mkdir()\n            with loaded.GitOpsJournal(common).record_intent(op="push", lane="lane-1", request_id="request-1",\n                    actor="session-1", expected_old="a" * 40, expected_new="b" * 40) as receipt:\n                if operation == "effect":\n                    receipt.inheritable_fds()\n        else:\n            receipt = loaded.IntentReceipt({}, False)\n            if operation == "effect":\n                try:\n                    receipt.inheritable_fds()\n                except loaded.GitOpsError:\n                    pass\nprint(json.dumps({"loaded": "aegis_core.gitops_fds" in sys.modules}))\n'


@pytest.mark.parametrize("module", ["aegis_core.gitsafe", "aegis_core.gitsafe_run", "aegis_core.ghcli", "aegis_core.team_gitops"])
@pytest.mark.parametrize("operation", ["import", "ordinary", "effect", "effect_success"])
def test_effect_support_imports_only_at_explicit_entry(tmp_path, module, operation):
    import json
    if operation == "effect_success" and not module.endswith("team_gitops"):
        strict_program_guard()
    if operation == "effect_success" and module.endswith("ghcli") and shutil.which("cc") is None:
        pytest.skip("native gh fixture needs an installed C compiler")
    if operation in ("effect", "effect_success") and not gitops_fds.descriptor_supported():
        pytest.skip("successful effect descriptor inheritance requires POSIX pass_fds")
    child = subprocess.run([sys.executable, "-I", "-c", _IMPORT_PROBE, str(ROOT), module, operation, str(tmp_path), gitsafe.git_executable(), shutil.which("cc") or ""],
        cwd=tmp_path, env={**os.environ, "PATH": "" if module.endswith("ghcli") else os.environ.get("PATH", "")},
        capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    if result.get("unsupported"):
        pytest.skip("descriptor-relative receipt export requires POSIX no-follow operations")
    assert result == {"loaded": operation.startswith("effect")}


@pytest.mark.usefixtures("strict_program")
def test_effect_receipt_never_widens_parent_inheritance(tmp_path):
    from aegis_core import team_gitops
    _repo(tmp_path)
    if not team_gitops.descriptor_supported() or not gitops_fds.descriptor_supported():
        pytest.skip("descriptor-relative receipt export requires POSIX no-follow operations")
    common = tmp_path / "common"
    common.mkdir()
    journal = team_gitops.GitOpsJournal(common)
    with journal.record_intent(op="push", lane="lane-1", request_id="request-1", actor="session-1",
                              expected_old="a" * 40, expected_new="b" * 40) as receipt:
        fds = receipt.inheritable_fds()
        assert not os.get_inheritable(fds[0])
        before = os.fstat(fds[0])
        assert gitsafe.run(["version"], tmp_path, effect_fds=fds, worktree_root=tmp_path).returncode == 0
        assert not os.get_inheritable(fds[0])
        assert os.fstat(fds[0]) == before


@pytest.mark.usefixtures("strict_program")
def test_effect_cas_accepts_a_per_call_receipt_after_lane_creation(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo)
    oid = gitsafe.head_commit(repo)
    calls = []
    def launch(argv, **kwargs):
        calls.append((argv, kwargs.copy()))
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    assert lane.cas("refs/heads/lane/effect", oid, None, effect_fds=(effect_lock,)) == "updated"
    assert lane.cas("refs/heads/lane/effect", oid, None, effect_fds=(effect_lock,)) == "already"
    assert calls and all(kwargs["pass_fds"][0] == effect_lock and len(kwargs["pass_fds"]) == 5 for _, kwargs in calls)
    assert not os.get_inheritable(effect_lock)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX effect descriptor inheritance")
def test_effect_cas_refuses_invalid_per_call_fd_before_spawn(repo, tmp_path, monkeypatch):
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo)
    calls = []
    def unexpected(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("invalid CAS descriptor reached a spawn")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    with pytest.raises(gitsafe.GitError) as caught:
        lane.cas("refs/heads/lane/effect", "a" * 40, None, effect_fds=(-1,))
    assert caught.value.code == "invalid_effect_descriptor"
    assert caught.value.process_started is False and calls == []


@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_git_refuses_credential_subcommand_before_spawn(repo, tmp_path, effect_lock, monkeypatch, site):
    from types import SimpleNamespace
    def unexpected(*args, **kwargs):
        pytest.fail("credential effect reached a spawn")
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": unexpected}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    with pytest.raises(gitsafe.GitError) as caught:
        if site == "run":
            gitsafe.run(["credential", "fill"], repo, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                gitsafe_run.capture([gitsafe.git_executable(), "credential", "fill"], cwd=repo,
                    env=dict(os.environ), stdin=None, timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "execute", "capture", "lane_run", "publish", "lane_runner"])
def test_effect_askpass_disabled_at_every_spawn(repo, tmp_path, effect_lock, monkeypatch, site):
    from types import SimpleNamespace
    import struct
    import hashlib
    _git(repo, "config", "core.askPass", "untrusted-askpass")
    calls = []
    def launch(argv, **kwargs):
        calls.append((list(argv), kwargs.copy()))
        return subprocess.Popen(argv, **kwargs)
    def run(argv, **kwargs):
        calls.append((list(argv), kwargs.copy()))
        return subprocess.run(argv, **kwargs)
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    pack = b"PACK" + struct.pack("!II", 2, 0)
    pack += hashlib.sha1(pack).digest()
    assert _effect_call(site, repo, tmp_path, effect_lock, payload=pack if site == "publish" else b"").returncode == 0
    assert calls
    for argv, kwargs in calls:
        assert "core.askPass=" in argv
        assert kwargs["env"]["GIT_ASKPASS"] == kwargs["env"]["SSH_ASKPASS"] == ""
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"


@pytest.mark.usefixtures("strict_program")
def test_effect_nested_validation_inherits_per_call_fd(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo)
    (tmp_path / "objects").mkdir()
    calls = []
    def launch(argv, **kwargs):
        calls.append((list(argv), kwargs.copy()))
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    result = lane.run(["hash-object", "-w", "--stdin", "--path=claim.txt"], stdin=b"content", effect_fds=(effect_lock,))
    assert result.returncode == 0
    assert any("config" in argv for argv, _ in calls)
    assert all(kwargs["pass_fds"][0] == effect_lock and len(kwargs["pass_fds"]) == 5 for _, kwargs in calls)


@pytest.mark.usefixtures("strict_program")
def test_effect_nested_started_timeout_preserves_metadata(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    from threading import Event
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo)
    (tmp_path / "objects").mkdir()
    started = Event()
    read_status = gitops_fds._HolderProcess.read_status
    def observe(process):
        read_status(process)
        if process.started:
            started.set()
    monkeypatch.setattr(gitops_fds._HolderProcess, "read_status", observe)
    monkeypatch.setattr(gitsafe_run, "time", SimpleNamespace(monotonic=lambda: 2.0 if started.is_set() else 0.0))
    with pytest.raises(gitsafe.GitError) as caught:
        lane.run(["hash-object", "-w", "--stdin", "--path=claim.txt"], stdin=b"content", timeout=1, effect_fds=(effect_lock,))
    assert started.is_set()
    assert caught.value.code == "git_timeout"
    assert caught.value.process_started is True


@pytest.mark.parametrize("key", ["command", "cmd"])
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_trailer_background_holder_refused_and_reconcile_unblocked(repo, tmp_path, key, site):
    from aegis_core import team_gitops
    if not team_gitops.descriptor_supported() or not gitops_fds.descriptor_supported():
        pytest.skip("descriptor-relative receipt export requires POSIX no-follow operations")
    import fcntl
    fifo = tmp_path / "holder.fifo"
    os.mkfifo(fifo)
    control = os.open(fifo, os.O_RDWR)
    marker = tmp_path / "holder-started"
    helper = tmp_path / "trailer-helper"
    helper.write_text("#!" + sys.executable + "\nimport os\nfrom pathlib import Path\nr,w=os.pipe()\np=os.fork()\n"
        + "if p==0:\n os.close(r)\n with open(os.devnull,'r+b',buffering=0) as d:\n  for fd in (0,1,2): os.dup2(d.fileno(),fd)\n"
        + " s=os.open(" + repr(str(fifo)) + ",os.O_RDONLY)\n os.write(w,b'R')\n os.close(w)\n os.read(s,1)\n os.close(s)\n os._exit(0)\n"
        + "os.close(w)\nos.read(r,1)\nos.close(r)\nPath(" + repr(str(marker)) + ").write_text('started')\nprint('fixture')\n", encoding="utf-8")
    helper.chmod(0o700)
    _git(repo, "config", "trailer.probe." + key, str(helper))
    common = tmp_path / "common"
    common.mkdir()
    journal = team_gitops.GitOpsJournal(common)
    try:
        with journal.record_intent(op="commit", lane="lane-1", request_id="request-1", actor="session-1",
                                  expected_old="a" * 40, expected_new="b" * 40) as receipt:
            fds = receipt.inheritable_fds()
            with pytest.raises(gitsafe.GitError) as caught:
                if site == "run":
                    gitsafe.run(["interpret-trailers", "--trailer", "probe:x"], repo, stdin=b"subject\n\n", effect_fds=fds, worktree_root=repo)
                else:
                    with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                        gitsafe_run.capture([gitsafe.git_executable(), "interpret-trailers", "--trailer", "probe:x"], cwd=repo,
                            env=dict(os.environ), stdin=b"subject\n\n", timeout=5, error=gitsafe.GitError, effect_fds=fds, worktree_root=repo)
            assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
            assert not marker.exists()
    finally:
        os.write(control, b"E")
        os.close(control)
    results = journal.reconcile("lane-1", lambda _: team_gitops.Observation("a" * 40))
    assert [row["status"] for row in results] == ["not_applied"]


def _network_hardening(*extra):
    return ("-c", "protocol.allow=always", "-c", "core.hooksPath=" + os.devnull,
            "-c", "core.fsmonitor=false", *extra)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("operation", ["push", "fetch"])
@pytest.mark.parametrize("source", ["caller", "owner", "default"])
def test_effect_real_git_ssh_forces_nonpersistent_options(repo, tmp_path, effect_lock, operation, source):
    import json
    import shlex
    if shutil.which("ssh") is None:
        pytest.skip("needs an installed SSH client")
    marker, ssh = tmp_path / "ssh.json", tmp_path / "ssh"
    _native_program(ssh, "#!" + sys.executable + "\nimport json, os, sys\nfrom pathlib import Path\n"
        + "Path(" + repr(str(marker)) + ").write_text(json.dumps({'argv':sys.argv[1:],'held':os.path.exists('/proc/self/fd/"
        + str(effect_lock) + "')}))\nsys.exit(1)\n")
    ssh.chmod(0o700)
    command = shlex.quote(str(ssh)) + " -oControlPersist=yes -oControlMaster=yes -oControlPath=owner-socket"
    hardening = _network_hardening()
    if source == "caller":
        hardening += ("-c", "core.sshCommand=" + command)
    elif source == "owner":
        _git(repo, "config", "core.sshCommand", command)
    result = gitsafe.run([operation, "git@fixture.invalid:repository", "HEAD"], repo,
        _hardening=hardening, _env={"GIT_ALLOW_PROTOCOL": "ssh"},
        _environ={"PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "HOME": str(tmp_path)},
        effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode != 0 and marker.exists()
    record = json.loads(marker.read_text())
    assert not record["held"]
    argv = record["argv"]
    assert argv[:8] == ["-o", "IgnoreUnknown=ForkAfterAuthentication", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"]
    assert "ForkAfterAuthentication=no" in argv and "BatchMode=yes" in argv
    if source != "default":
        assert "-oControlPersist=yes" in argv  # retained after the forced first values
    assert not (repo / "owner-socket").exists() and not os.get_inheritable(effect_lock)


def _credential_remote(repo, tmp_path, fd):
    import shlex
    marker, remote = tmp_path / "remote-started", tmp_path / "remote"
    remote.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nprintf 'protocol=https\\nhost=fixture.invalid\\n\\n' | "
        + shlex.quote(gitsafe.git_executable()) + " credential fill >/dev/null\nexit 1\n", encoding="utf-8")
    remote.chmod(0o700)
    _git(repo, "config", "remote.fixture.url", "ext::" + shlex.quote(str(remote)))
    helper_marker, helper = tmp_path / "credential.json", tmp_path / "helper"
    helper.write_text("#!" + sys.executable + "\nimport json, os, sys\nfrom pathlib import Path\n"
        + "Path(" + repr(str(helper_marker)) + ").write_text(json.dumps({'held':os.path.exists('/proc/self/fd/"
        + str(fd) + "'),'operation':sys.argv[-1]}))\n"
        + "sys.stdin.read()\nprint('username=fixture\\npassword=fixture\\n')\n", encoding="utf-8")
    helper.chmod(0o700)
    return marker, helper_marker, shlex.quote(str(helper))


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("operation", ["push", "fetch"])
@pytest.mark.parametrize("source", ["owner_helper", "owner_cache", "caller_cache", "scoped_cache", "reset_cache", "missing"])
def test_effect_real_git_credentials_keep_helper_or_refuse_cache(repo, tmp_path, effect_lock, operation, source):
    import json
    if "not a git command" in subprocess.run([gitsafe.git_executable(), "credential-cache", "-h"], capture_output=True, text=True).stderr:
        pytest.skip("Git credential-cache is not installed")
    remote, marker, helper = _credential_remote(repo, tmp_path, effect_lock)
    cache = "cache --timeout=60 --socket=" + str(tmp_path / "cache" / "socket")
    hardening = _network_hardening()
    if source == "owner_helper":
        _git(repo, "config", "credential.helper", helper)
    elif source in ("owner_cache", "reset_cache"):
        _git(repo, "config", "credential.helper", cache)
        if source == "reset_cache":
            hardening += ("-c", "credential.helper=", "-c", "credential.helper=" + helper)
    elif source == "caller_cache":
        hardening += ("-c", "credential.helper=" + cache)
    elif source == "scoped_cache":
        _git(repo, "config", "credential.https://fixture.invalid.helper", cache)
    for _ in range(2):
        if source in ("owner_cache", "caller_cache", "scoped_cache"):
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run([operation, "fixture", "HEAD"], repo, _hardening=hardening,
                    _env={"GIT_ALLOW_PROTOCOL": "ext"}, effect_fds=(effect_lock,), worktree_root=repo)
            assert caught.value.code == "effect_credential_cache_refused"
            assert caught.value.effect_process_started is False and caught.value.next_action
            assert not remote.exists() and not marker.exists()
        else:
            result = gitsafe.run([operation, "fixture", "HEAD"], repo, _hardening=hardening,
                _env={"GIT_ALLOW_PROTOCOL": "ext"}, effect_fds=(effect_lock,), worktree_root=repo)
            assert result.returncode != 0 and remote.exists()
            if source == "missing":
                assert result.stderr == b"Git operation missing HTTPS credentials; prompts disabled."
                assert not marker.exists()
            else:
                record = json.loads(marker.read_text())
                assert not record["held"] and record["operation"] == "get"
        assert not (tmp_path / "cache").exists() and not os.get_inheritable(effect_lock)


@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_environment_removes_program_selectors(repo, tmp_path, effect_lock, monkeypatch, site):
    from types import SimpleNamespace
    injected = {name: "fixture-injection" for name in (
        "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_SSH",
        "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS",
        "GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS")}
    injected.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="remote.origin.url", GIT_CONFIG_VALUE_0="injected")
    source = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), **injected}
    calls = []
    def launch(argv, **kwargs):
        calls.append(kwargs["env"].copy())
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    with gitsafe.custody(scratch=tmp_path, worktree_root=repo), pytest.raises(gitsafe.GitError) as caught:
        if site == "run":
            gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env=source,
                stdin=None, timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "ambient_git_environment" and caught.value.process_started is False
    assert caught.value.next_action and not calls
    assert source["GIT_SSH_COMMAND"] == "fixture-injection"  # caller dictionary untouched


@pytest.mark.usefixtures("strict_program")
def test_effect_real_gc_auto_disables_detach_and_threshold(repo, tmp_path, effect_lock):
    import hashlib
    import json
    payloads = []
    for index in range(10000):
        data = str(index).encode("ascii")
        if hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest().startswith("17"):
            payloads.append(data)
            if len(payloads) == 3:
                break
    assert len(payloads) == 3
    for data in payloads:
        subprocess.run([gitsafe.git_executable(), "hash-object", "-w", "--stdin"], cwd=repo, input=data, check=True, capture_output=True)
    _git(repo, "config", "gc.auto", "1")
    _git(repo, "config", "gc.autoDetach", "true")
    before = set((repo / ".git" / "objects" / "pack").glob("*.pack"))
    result = gitsafe.run(["gc", "--auto"], repo, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0 and b"Auto packing" not in result.stdout + result.stderr
    assert set((repo / ".git" / "objects" / "pack").glob("*.pack")) == before
    assert not (repo / ".git" / "gc.pid").exists()
    control = subprocess.run([gitsafe.git_executable(), "-c", "core.hooksPath=" + os.devnull,
        "-c", "gc.autoDetach=false", "gc", "--auto"], cwd=repo, capture_output=True, timeout=10)
    assert control.returncode == 0 and b"Auto packing" in control.stdout + control.stderr
    for key, expected in (("gc.auto", b"0\n"), ("gc.autoDetach", b"false\n"), ("maintenance.auto", b"false\n")):
        assert gitsafe.run(["config", "--get", key], repo, effect_fds=(effect_lock,), worktree_root=repo).stdout == expected


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("failed_call", [2])
def test_effect_preflight_spawn_failure_keeps_started_metadata_and_fd(repo, tmp_path, effect_lock, monkeypatch, site, failed_call):
    import errno
    from types import SimpleNamespace
    count = []
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").is_dir() else None
    def launch(argv, **kwargs):
        count.append(argv)
        if len(count) == failed_call:
            raise OSError(errno.EMFILE, "secret-failure-input")
        return subprocess.Popen(argv, **kwargs)
    def fail(*args, **kwargs):
        raise OSError(errno.EMFILE, "secret-failure-input")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    if site == "run" and failed_call == 4:
        monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": fail}))
    with pytest.raises(gitsafe.GitError) as caught:
        if site == "run":
            gitsafe.run(["push", "git@fixture.invalid:repository", "HEAD"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
        else:
            with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                gitsafe_run.capture([gitsafe.git_executable(), "push", "git@fixture.invalid:repository", "HEAD"], cwd=repo,
                    env=dict(os.environ), stdin=None, timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_failed" and caught.value.process_started is True
    assert caught.value.effect_process_started is False
    assert "secret-failure-input" not in str(caught.value)
    assert not os.get_inheritable(effect_lock)
    if before is not None:
        assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("helper,code", [("x" * 16385, "effect_configuration_unavailable"), ("x" * 65537, "git_output_limit")], ids=["helper-size", "capture-size"])
def test_effect_owner_configuration_limits_refuse_before_effect(repo, tmp_path, effect_lock, helper, code):
    _git(repo, "config", "credential.helper", helper)
    marker, _, _ = _credential_remote(repo, tmp_path, effect_lock)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["push", "fixture", "HEAD"], repo, _hardening=_network_hardening(),
                    _env={"GIT_ALLOW_PROTOCOL": "ext"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == code and caught.value.process_started is True
    assert not marker.exists() and helper not in str(caught.value)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("command", ["ssh; fixture", "ssh 'unterminated", "ssh\nfixture", "", "ssh -f", "ssh -M", "ssh -S owner-socket", "ssh -nMf"])
def test_effect_ssh_command_refusal_has_fixed_diagnostic(repo, tmp_path, effect_lock, command):
    _git(repo, "config", "core.sshCommand", command)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", "git@fixture.invalid:repository", "HEAD"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused"
    assert caught.value.effect_process_started is False
    assert str(caught.value) == "Git effect SSH command cannot be confined."


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="POSIX effect descriptors")
def test_effect_env_argument_replaces_ambient_repository_and_program_selection(repo, tmp_path):
    _git(repo, "config", "remote.origin.url", "https://github.com/real/repository.git")
    other = _repo(tmp_path / "other")
    _git(other, "config", "remote.origin.url", "https://github.com/injected/repository.git")
    code = "\nimport os, sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nwith open(sys.argv[3],'w+b') as held:\n    gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    result=gitsafe.run(['config','--get','remote.origin.url'],sys.argv[2],effect_fds=(held.fileno(),),\n                       _environ={'PATH':sys.argv[4],'HOME':sys.argv[5]}, worktree_root=sys.argv[2])\n    assert result.returncode==0\n    assert result.stdout==b'https://github.com/real/repository.git\\n'\n"
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(tmp_path / "held"), os.environ["PATH"], str(tmp_path)],
        env={**os.environ, "GIT_DIR": str(other / ".git"), "GIT_SSH_COMMAND": "untrusted-program",
             "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.url", "GIT_CONFIG_VALUE_0": "injected"},
        capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr


@pytest.mark.parametrize("cwd", [None, 7, "x\0y", "x" * 16385], ids=["none", "integer", "nul", "size"])
def test_effect_cwd_refuses_before_configuration_parsing(tmp_path, effect_lock, cwd):
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["push", "fixture", "HEAD"], cwd, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=tmp_path)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False


@pytest.mark.usefixtures("strict_program")
def test_effect_failure_classification_does_not_parse_oversized_diagnostics(repo, tmp_path, effect_lock):
    _credential_remote(repo, tmp_path, effect_lock)
    (tmp_path / "remote").write_text("#!" + sys.executable + "\nimport sys\nsys.stderr.buffer.write(b'x'*65537+b'terminal prompts disabled')\nraise SystemExit(1)\n", encoding="utf-8")
    result = gitsafe.run(["push", "fixture", "HEAD"], repo, _hardening=_network_hardening(),
                        _env={"GIT_ALLOW_PROTOCOL": "ext"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode != 0 and result.stdout == b""
    assert result.stderr == b"Git operation effect command failed; observe before recovery."


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("daemonize", [False, True], ids=["closefrom", "double-fork"])
def test_effect_holder_reaps_fd_closing_descendant_after_owner_and_git_die(repo, tmp_path, effect_lock, site, daemonize):
    import fcntl
    import select
    import signal
    if not hasattr(os, "pidfd_open"):
        pytest.skip("owner/git death latch requires Linux pidfds")
    control, ready = tmp_path / "holder-control", tmp_path / "holder-ready"
    os.mkfifo(control)
    os.mkfifo(ready)
    control_fd = os.open(control, os.O_RDWR | os.O_NONBLOCK)
    ready_fd = os.open(ready, os.O_RDWR | os.O_NONBLOCK)
    shim = tmp_path / "ssh"
    # Real Git starts this transport. It closes all inherited descriptors, just
    # like OpenSSH, and optionally double-forks into a separate session.
    _native_program(shim, "#!" + sys.executable + "\n" + f'''
import os, resource, sys
from pathlib import Path
ancestors, pid = [], os.getppid()
while pid > 1 and Path('/proc/'+str(pid)+'/comm').read_text().strip() in ('git', 'sh', 'bash', 'dash'):
    ancestors.append(str(pid))
    pid = int(Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')', 1)[1].split()[1])
Path({str(tmp_path / 'git.pid')!r}).write_text(' '.join(ancestors))
os.closerange(3, min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 1048576))
if {daemonize!r}:
    if os.fork(): os._exit(0)
    os.setsid()
    if os.fork(): os._exit(0)
f = os.open({str(control)!r}, os.O_RDONLY)
r = os.open({str(ready)!r}, os.O_WRONLY)
Path({str(tmp_path / "worker.pid")!r}).write_text(str(os.getpid()))
os.write(r, b'R')
os.close(r)
os.read(f, 1)
os.close(f)
''')
    shim.chmod(0o700)
    code = "\nimport os, sys\nfrom pathlib import Path\nsys.path.insert(0, sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nroot, scratch, shim, lock, site = sys.argv[2:]\nwith open(lock, 'r+b') as held:\n    import fcntl\n    fcntl.flock(held, fcntl.LOCK_SH)\n    gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    kw = dict(effect_fds=(held.fileno(),), timeout=12, _env={'GIT_ALLOW_PROTOCOL':'ssh'},\n        _hardening=('-c', 'protocol.allow=always', '-c', 'core.sshCommand='+shim))\n    if site == 'capture':\n        with gitsafe.custody(scratch=Path(scratch), worktree_root=root):\n            gitsafe.run(['push','git@fixture.invalid:repository','HEAD'],root,**kw, worktree_root=root)\n    else:\n        gitsafe.run(['push','git@fixture.invalid:repository','HEAD'],root,**kw, worktree_root=root)\n"
    capture_scratch = tmp_path / "capture-scratch"
    capture_scratch.mkdir()
    owner = subprocess.Popen([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(capture_scratch), str(shim), str(tmp_path / "effect.lock"), site], env=_owner_test_environment(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    worker_fd = None
    try:
        _wait_for_child_ready(owner, ready_fd, 8, "fd-closing SSH did not start")
        assert os.read(ready_fd, 1) == b"R"
        worker_fd = os.pidfd_open(int((tmp_path / "worker.pid").read_text()))
        owner.kill()
        owner.wait(timeout=3)
        for pid in (tmp_path / "git.pid").read_text().split():
            try:
                process_fd = os.pidfd_open(int(pid))
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    assert select.select([process_fd], [], [], 3)[0], "Git ancestor did not exit"
                finally:
                    os.close(process_fd)
            except ProcessLookupError:
                pass  # double-fork transport already let real Git exit
        # Release only the fixture's shared lock; the killed owner exported its own.
        fcntl.flock(effect_lock, fcntl.LOCK_UN)
        with (tmp_path / "effect.lock").open("rb") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                assert select.select([worker_fd], [], [], 0)[0], "custody freed before the final descendant exited"
            os.write(control_fd, b"E")
            from threading import Event, Thread
            free = Event()
            waiter = Thread(target=lambda: (fcntl.flock(probe, fcntl.LOCK_EX), free.set()), daemon=True)
            waiter.start()
            assert free.wait(8), "holder failed to reap the final descendant"
            waiter.join(timeout=1)
            assert select.select([worker_fd], [], [], 0)[0], "lock freed before descendant exit"
    finally:
        os.write(control_fd, b"E")
        if worker_fd is not None:
            os.close(worker_fd)
        os.close(control_fd)
        os.close(ready_fd)
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=15)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_lookup_uses_supplied_path_outside_checkout(repo, tmp_path, effect_lock, site):
    hostile = repo / "bin"
    hostile.mkdir()
    marker = tmp_path / "hostile-git-ran"
    fake = hostile / "git"
    fake.write_text("#!/bin/sh\n: > '" + str(marker) + "'\nexit 0\n", encoding="utf-8")
    fake.chmod(0o700)
    safe = {"PATH": os.path.dirname(gitsafe.git_executable()), "HOME": str(tmp_path)}
    code = "\nimport os, sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nroot, lock, safe_path, site = sys.argv[2:]\n# Warm the ordinary ambient cache with the checkout's fake executable.\ngitsafe.git_executable()\nwith open(lock,'r+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    def run(path):\n        return gitsafe.run(['version'],root,_environ={'PATH':path},effect_fds=fds, worktree_root=root)\n    if site == 'capture':\n        with gitsafe.custody(scratch=Path(root).parent, worktree_root=root):\n            assert run(safe_path).stdout.startswith(b'git version ')\n    else:\n        assert run(safe_path).stdout.startswith(b'git version ')\n    assert run(os.environ['PATH']).stdout.startswith(b'git version ')\n"
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(tmp_path / "effect.lock"), safe["PATH"], site],
        env={**os.environ, "PATH": str(hostile) + os.pathsep + safe["PATH"]}, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert not marker.exists()


def test_strict_executable_platform_probe_has_its_own_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(gitsafe_run, "_program_supported", lambda: False)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.custody_program(tmp_path, environ={"PATH": os.path.dirname(gitsafe.git_executable())})
    assert caught.value.code == "unsupported_effect_platform"
    assert caught.value.process_started is False and caught.value.effect_process_started is False
    assert caught.value.next_action
    # Ordinary owner calls retain their cross-platform process behavior.
    assert gitsafe.run(["version"], tmp_path, _environ={}).returncode == 0


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("failure", ["open", "spawn"])
def test_executable_descriptors_close_on_every_failure(repo, tmp_path, effect_lock, monkeypatch, failure):
    from types import SimpleNamespace
    import errno
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    lane = gitsafe.lane_runner(repo, scratch, environ={"PATH": os.path.dirname(gitsafe.git_executable())}, worktree_root=repo)
    opened = []
    def open_program(*args, **kwargs):
        if failure == "open": raise OSError(errno.EACCES, "UNTRUSTED_DETAIL")
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail_spawn(*args, **kwargs):
        raise OSError(errno.EACCES, "UNTRUSTED_DETAIL")
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "open": open_program}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": fail_spawn}))
    with pytest.raises(gitsafe.GitError) as caught:
        lane.run(["version"])
    assert caught.value.code == ("effect_command_refused" if failure == "open" else "git_failed")
    assert caught.value.process_started is False and "UNTRUSTED_DETAIL" not in str(caught.value)
    for fd in opened:
        with pytest.raises(OSError) as closed: os.fstat(fd)
        assert closed.value.errno == errno.EBADF



@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("command", ["env ssh", "exec ssh", "~/bin/ssh", "ssh -i $HOME/key"])
def test_effect_nonplain_ssh_refuses_only_ssh_remote(repo, tmp_path, effect_lock, command):
    _git(repo, "config", "core.sshCommand", command)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", "git@fixture.invalid:repository", "HEAD"], repo,
                    _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused"
    assert caught.value.effect_process_started is False and caught.value.next_action
    result = gitsafe.run(["fetch", str(repo), "HEAD"], repo,
                        _hardening=_network_hardening(), _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0


def test_effect_receipt_refuses_reused_descriptor_identity(repo, tmp_path, effect_lock):
    original = (tmp_path / "original-lock").open("w+b")
    fd = original.fileno()
    exported = gitops_fds.receipt_fds(fd, error=gitsafe.GitError)
    original.close()
    with (tmp_path / "replacement-lock").open("w+b") as replacement:
        reused = replacement.fileno() != fd
        if reused:
            os.dup2(replacement.fileno(), fd)
        try:
            gitops_fds.receipt_fds(fd, error=gitsafe.GitError)
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run(["version"], repo, effect_fds=exported, worktree_root=repo)
            assert caught.value.code == "invalid_effect_descriptor"
            assert caught.value.process_started is False
        finally:
            if reused:
                os.close(fd)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_timeout_kills_and_reaps_detached_group(repo, tmp_path, effect_lock, site):
    import signal
    shim, marker = tmp_path / "ssh", tmp_path / "descendant.pid"
    _native_program(shim, "#!" + sys.executable + "\n" + f'''
import os, signal, time
from pathlib import Path
if os.fork(): os._exit(0)
os.setsid()
if os.fork(): os._exit(0)
os.closerange(3, 1048576)
Path({str(marker)!r}).write_text(str(os.getpid()))
signal.pause()
''')
    shim.chmod(0o700)
    import contextlib
    capture_scratch = tmp_path / "capture-scratch"
    capture_scratch.mkdir()
    context = gitsafe.custody(scratch=capture_scratch, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["push", "git@fixture.invalid:repository", "HEAD"], repo,
            _hardening=_network_hardening("-c", "core.sshCommand=" + str(shim)),
            _env={"GIT_ALLOW_PROTOCOL": "ssh"}, timeout=1, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_timeout" and caught.value.process_started
    assert marker.exists(), "timeout fixture never started its detached child"
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)
    # The public operation returned only after the holder reaped the daemon.
    import fcntl
    fcntl.flock(effect_lock, fcntl.LOCK_UN)
    with (tmp_path / "effect.lock").open("rb") as probe:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)


@pytest.mark.usefixtures("strict_program")
def test_effect_ambient_home_keeps_owner_global_helper(repo, tmp_path, effect_lock):
    import shlex
    owner_home = tmp_path / "owner-home"
    owner_home.mkdir()
    _, helper_marker, helper = _credential_remote(repo, tmp_path, effect_lock)
    # Only the owner HOME config defines this helper; repository config does not.
    (owner_home / ".gitconfig").write_text('[credential]\n\thelper = ' + helper + '\n', encoding="utf-8")
    bare = tmp_path / "bare"
    _git(repo, "init", "--bare", str(bare))
    remote = tmp_path / "remote"
    remote.write_text("#!/bin/sh\nprintf 'protocol=https\\nhost=fixture.invalid\\n\\n' | "
        + shlex.quote(gitsafe.git_executable()) + " credential fill >/dev/null || exit 1\nexec "
        + shlex.quote(gitsafe.git_executable()) + " receive-pack " + shlex.quote(str(bare)) + "\n", encoding="utf-8")
    code = "\nimport os, sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nwith open(sys.argv[3], 'r+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    result=gitsafe.run(['push','fixture','HEAD:refs/heads/main'],sys.argv[2],\n        _hardening=('-c','protocol.allow=always'),_env={'GIT_ALLOW_PROTOCOL':'ext'},effect_fds=fds, worktree_root=sys.argv[2])\n    assert result.returncode==0, result.stderr\n"
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(tmp_path / "effect.lock")],
        env={**os.environ, "HOME": str(owner_home)}, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0 and helper_marker.exists(), child.stderr
    assert _git(bare, "rev-parse", "refs/heads/main") == _git(repo, "rev-parse", "HEAD")


@pytest.mark.usefixtures("strict_program")
def test_effect_real_openssh_closes_receipt_but_holder_keeps_custody(repo, tmp_path, effect_lock):
    import fcntl
    import select
    import shlex
    import signal
    if not hasattr(os, "pidfd_open"):
        pytest.skip("OpenSSH lifetime latch requires Linux pidfds")
    ssh = shutil.which("ssh")
    if ssh is None:
        pytest.skip("real OpenSSH binary is not installed")
    latch, ready = tmp_path / "ssh-input", tmp_path / "ssh-ready"
    os.mkfifo(latch)
    os.mkfifo(ready)
    latch_fd = os.open(latch, os.O_RDWR | os.O_NONBLOCK)
    ready_fd = os.open(ready, os.O_RDWR | os.O_NONBLOCK)
    proxy = tmp_path / "proxy"
    proxy.write_text("#!" + sys.executable + "\n" + f'''
import os
from pathlib import Path
Path({str(tmp_path / 'proxy.pid')!r}).write_text(str(os.getpid()))
f = os.open({str(latch)!r}, os.O_RDONLY)
r = os.open({str(ready)!r}, os.O_WRONLY)
os.write(r, b'R')
os.read(f, 1)
''', encoding="utf-8")
    proxy.chmod(0o700)
    command = shlex.join([ssh, "-F", os.devnull, "-o", "ProxyCommand=" + str(proxy)])
    code = "\nimport os, sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nwith open(sys.argv[3],'r+b') as held:\n    import fcntl\n    fcntl.flock(held,fcntl.LOCK_SH)\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    gitsafe.run(['push','git@fixture.invalid:repository','HEAD'],sys.argv[2],timeout=10,\n        _hardening=('-c','protocol.allow=always','-c','core.sshCommand='+sys.argv[4]),\n        _env={'GIT_ALLOW_PROTOCOL':'ssh'},effect_fds=fds, worktree_root=sys.argv[2])\n"
    owner = subprocess.Popen([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(tmp_path / "effect.lock"), command], env=_owner_test_environment(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process_fd = None
    try:
        _wait_for_child_ready(owner, ready_fd, 6, "real OpenSSH did not start its local proxy")
        assert os.read(ready_fd, 1) == b"R"
        proxy_pid = int((tmp_path / "proxy.pid").read_text())
        process_fd = os.pidfd_open(proxy_pid)
        # Locate the real SSH ancestor through the local proxy's shell.
        pid = proxy_pid
        ssh_identity = os.stat(ssh)
        while (Path('/proc/' + str(pid) + '/exe').stat().st_dev, Path('/proc/' + str(pid) + '/exe').stat().st_ino) != (ssh_identity.st_dev, ssh_identity.st_ino):
            pid = int(Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[1])
            assert pid > 1
        receipt_identity = os.fstat(effect_lock)
        for entry in Path('/proc/' + str(pid) + '/fd').iterdir():
            try:
                info = entry.stat()
            except FileNotFoundError:
                continue
            assert (info.st_dev, info.st_ino) != (receipt_identity.st_dev, receipt_identity.st_ino)
        git_pid = int(Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[1])
        owner.kill()
        owner.wait(timeout=3)
        # Kill the Git ancestor (a shell may sit between git and ssh).
        git_identity = os.stat(gitsafe.git_executable())
        while (Path('/proc/' + str(git_pid) + '/exe').stat().st_dev, Path('/proc/' + str(git_pid) + '/exe').stat().st_ino) != (git_identity.st_dev, git_identity.st_ino):
            git_pid = int(Path('/proc/' + str(git_pid) + '/stat').read_text().rsplit(')', 1)[1].split()[1])
            assert git_pid > 1
        os.kill(git_pid, signal.SIGKILL)
        fcntl.flock(effect_lock, fcntl.LOCK_UN)
        with (tmp_path / "effect.lock").open("rb") as probe:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                assert select.select([process_fd], [], [], 0)[0], "custody freed before OpenSSH's proxy exited"
            os.write(latch_fd, b"E")
            from threading import Event, Thread
            free = Event()
            waiter = Thread(target=lambda: (fcntl.flock(probe, fcntl.LOCK_EX), free.set()), daemon=True)
            waiter.start()
            assert free.wait(6), "real SSH descendants exited without releasing custody"
            waiter.join(timeout=1)
        assert select.select([process_fd], [], [], 0)[0]
    finally:
        os.write(latch_fd, b"E")
        if process_fd is not None:
            os.close(process_fd)
        os.close(latch_fd)
        os.close(ready_fd)
        if owner.poll() is None:
            owner.kill()
        owner.communicate(timeout=12)


@pytest.mark.usefixtures("strict_program")
def test_effect_policy_uses_one_config_read_and_one_deadline(repo, tmp_path, effect_lock):
    script, marker = tmp_path / "git", tmp_path / "configuration-reads"
    _native_program(script, "#!" + sys.executable + "\n" + f'''
import os, sys, time
from pathlib import Path
if 'config' in sys.argv:
    with open({str(marker)!r}, 'a') as stream: stream.write('config\\n')
    time.sleep(0.65)
    raise SystemExit(1)
time.sleep(0.65)
raise SystemExit(0)
''')
    script.chmod(0o700)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["push", str(repo), "HEAD"], repo, timeout=1,
            _environ={"PATH": str(tmp_path)}, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_timeout" and caught.value.process_started
    assert marker.read_text().splitlines() == ["config"]


@pytest.mark.usefixtures("strict_program")
def test_effect_default_file_remote_ignores_unrelated_ssh_policy(repo, tmp_path, effect_lock):
    _git(repo, "config", "core.sshCommand", "env ssh")
    _git(repo, "config", "remote.fixture.url", str(repo))
    _git(repo, "config", "branch.main.remote", "fixture")
    result = gitsafe.run(["fetch"], repo, _hardening=_network_hardening(),
        _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0


@pytest.mark.usefixtures("strict_program")
def test_effect_ssh_policy_handles_option_values_and_owner_url_rewrites(repo, tmp_path, effect_lock):
    _git(repo, "config", "core.sshCommand", "env ssh")
    _git(repo, "config", "url.git@fixture.invalid:.insteadOf", "https://fixture.invalid/")
    for remote in ("git@fixture.invalid:repository", "https://fixture.invalid/repository"):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.run(["fetch", "--depth", "1", remote, "HEAD"], repo,
                _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
        assert caught.value.code == "effect_ssh_command_refused" and caught.value.effect_process_started is False


@pytest.mark.parametrize("key", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE"])
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_supplied_repository_selectors_cannot_redirect(repo, tmp_path, effect_lock, monkeypatch, key, site):
    from types import SimpleNamespace
    program = gitsafe.git_executable()
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail("selector reached executable lookup or spawn")
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=forbidden))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    source = {"PATH": os.path.dirname(program), key: "UNTRUSTED_REPOSITORY"}
    with gitsafe.custody(scratch=tmp_path), pytest.raises(gitsafe.GitError) as caught:
        if site == "capture":
            gitsafe_run.capture([program, "version"], cwd=repo, env=source, stdin=None, timeout=5,
                error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "ambient_git_environment" and caught.value.process_started is False
    assert caught.value.next_action and "UNTRUSTED_REPOSITORY" not in str(caught.value) + caught.value.next_action
    assert calls == []



@pytest.mark.parametrize("cwd", [".", "../repository", "/tmp/parent/../repository"])
def test_effect_noncanonical_cwd_has_typed_prespawn_refusal(tmp_path, effect_lock, cwd):
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["push", "fixture", "HEAD"], cwd, effect_fds=(effect_lock,), worktree_root=tmp_path)
    assert caught.value.code == "invalid_effect_cwd"
    assert caught.value.process_started is False and caught.value.next_action


@pytest.mark.parametrize("args,code", [(None, "effect_command_refused"), (["credential", "fill"], "effect_command_refused"), (["version"], "git_failed")])
def test_effect_command_validation_precedes_missing_executable(repo, tmp_path, effect_lock, args, code):
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(args, repo, _environ={"PATH": ""}, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == code
    assert caught.value.process_started is False and caught.value.next_action


def test_effect_final_environment_limit_precedes_executable_lookup(repo, tmp_path, effect_lock):
    source = {"PATH": "", **{"REQUEST_" + str(i): "fixture" for i in range(511)}}
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_environment_limit"
    assert caught.value.process_started is False and caught.value.next_action


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("location", ["checkout", "extra-root"])
def test_effect_path_fences_checkout_ssh_and_every_declared_write_root(repo, tmp_path, effect_lock, site, location):
    import contextlib
    write_root = repo if location == "checkout" else tmp_path / "other-model"
    hostile, host = write_root / "bin", tmp_path / "host"
    hostile.mkdir(parents=True)
    host.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    bad, good = tmp_path / "hostile-ssh", tmp_path / "trusted-ssh"
    for directory, marker in ((hostile, bad), (host, good)):
        script = directory / "ssh"
        _native_program(script, "#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nraise SystemExit(1)\n")
        script.chmod(0o700)
    source = {"PATH": os.pathsep.join((str(hostile), str(host), os.path.dirname(gitsafe.git_executable()))), "GIT_ALLOW_PROTOCOL": "ssh"}
    context = gitsafe.custody(scratch=scratch, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context:
        if site == "capture":
            result = gitsafe_run.capture([gitsafe.git_executable(), *_network_hardening(), "push", "git@fixture.invalid:repository", "HEAD"],
                cwd=repo, env=source, stdin=None, timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), write_roots=(write_root,), worktree_root=repo)
        else:
            result = gitsafe.run(["push", "git@fixture.invalid:repository", "HEAD"], repo,
                _hardening=_network_hardening(), _environ=source, _env={"GIT_ALLOW_PROTOCOL": "ssh"}, effect_fds=(effect_lock,), write_roots=(write_root,), worktree_root=repo)
    assert result.returncode != 0 and good.exists() and not bad.exists()


@pytest.mark.usefixtures("strict_program")
def test_effect_strict_facade_uses_supplied_environment_before_discovery(repo, tmp_path, effect_lock):
    hostile = repo / "bin"
    hostile.mkdir()
    source_dir, scratch = repo / "src", tmp_path / "scratch"
    source_dir.mkdir()
    scratch.mkdir()
    marker = tmp_path / "ambient-git"
    fake = hostile / "git"
    real = gitsafe.git_executable()
    _native_program(fake, "#!/bin/sh\n: > '" + str(marker) + "'\nexec '" + real + "' \"$@\"\n")
    fake.chmod(0o700)
    code = "\nimport sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nwith open(sys.argv[4],'w+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    with gitsafe.custody(scratch=Path(sys.argv[3]),strict_lane=True, worktree_root=Path(sys.argv[2]).parent):\n        result=gitsafe.run(['version'],sys.argv[2],_environ={'PATH':sys.argv[5]},effect_fds=fds, worktree_root=Path(sys.argv[2]).parent)\n    assert result.returncode==0 and result.stdout.startswith(b'git version ')\n"
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(source_dir), str(scratch), str(tmp_path / "strict-lock"), os.path.dirname(real)],
        env={**os.environ, "PATH": str(hostile) + os.pathsep + os.environ["PATH"]}, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("operation", ["push", "fetch"])
@pytest.mark.parametrize("command", ["/usr/bin/env ssh", "/bin/sh -c ssh", "/opt/wrapper -v", "/usr/bin/plink -v", "ssh destination", "ssh -Z", "ssh -o"],
                         ids=["absolute-env", "shell", "wrapper", "other-client", "positional", "unknown-option", "missing-value"])
def test_effect_ssh_positive_grammar_refuses_siblings(repo, tmp_path, effect_lock, site, operation, command):
    import contextlib
    context = gitsafe.custody(scratch=tmp_path, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run([operation, "git@fixture.invalid:repository", "HEAD"], repo,
            _hardening=_network_hardening("-c", "core.sshCommand=" + command), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused"
    assert caught.value.effect_process_started is False and caught.value.next_action


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("form", ["repo-equals", "repo-spaced", "multiple", "all", "group", "legacy-remotes", "legacy-branches"])
def test_effect_remote_unsupported_forms_refuse(repo, tmp_path, effect_lock, site, form):
    import contextlib
    command = ["fetch", "fixture", "HEAD"]
    _git(repo, "config", "remote.origin.url", "https://fixture.invalid/repo")
    _git(repo, "config", "core.sshCommand", "env ssh")
    if form == "repo-equals":
        command = ["push", "--repo=git@fixture.invalid:repository", "HEAD"]
    elif form == "repo-spaced":
        command = ["push", "--repo", "https://fixture.invalid/repo", "git@fixture.invalid:repository", "HEAD"]
    elif form == "multiple":
        command = ["fetch", "--multiple", "fixture"]
    elif form == "all":
        command = ["fetch", "--all"]
    elif form == "group":
        _git(repo, "config", "remotes.fixture", "origin other")
    else:
        parent = repo / ".git" / ("remotes" if form == "legacy-remotes" else "branches")
        parent.mkdir(exist_ok=True)
        (parent / "fixture").write_text("URL: ssh://fixture.invalid/repository\n", encoding="utf-8")
    context = gitsafe.custody(scratch=tmp_path, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(command, repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "unsupported_remote_form"
    assert caught.value.effect_process_started is False and caught.value.next_action


@pytest.mark.usefixtures("strict_program")
def test_effect_fetch_policy_uses_first_configured_url(repo, tmp_path, effect_lock):
    _git(repo, "config", "remote.fixture.url", str(repo))
    _git(repo, "config", "--add", "remote.fixture.url", "ssh://fixture.invalid/repository")
    _git(repo, "config", "core.sshCommand", "/usr/bin/env ssh")
    result = gitsafe.run(["fetch", "fixture", "HEAD"], repo, _hardening=_network_hardening(),
        _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0


def test_effect_functions_do_not_read_ambient_environment():
    """All recipe inputs and executable candidates cross the two shared boundaries."""
    names = ("gitsafe", "gitsafe_run", "gitops_fds", "ghcli", "team_gitops")
    sources = {name: (ROOT / "aegis_core" / (name + ".py")).read_text(encoding="utf-8") for name in names}
    # Allowed sinks and callbacks retain existing custody/platform behavior.
    sinks = {("gitsafe_run", "capture", "subprocess.Popen"): "bounded capture or isolated holder",
             ("gitsafe_run", "execute", "legacy_runner"): "ordinary compatibility runner",
             ("ghcli", "default_gh_runner", "subprocess.run"): "ordinary gh compatibility",
             ("ghcli", "default_gh_runner", "subprocess.Popen"): "isolated gh holder"}
    lookups = {("gitsafe", "git_executable"): "facade-owned cached ordinary or strict Git lookup",
               ("gitsafe", "custody_program"): "facade-owned discovery callback",
               ("ghcli", "default_gh_runner"): "gh callback to the sole resolver",
               ("gitops_fds", "_ssh_policy"): "positive SSH grammar then the sole resolver"}
    # Binding maps and bounded input snapshots are data, not child environments.
    recipe_functions = {"resolve_base_ref", "issue_runner", "capture", "execute", "environment",
                        "default_gh_runner", "_gh_command", "prepare_capture", "holder_recipe"}
    recipe_calls = {"request_environment", "gitsafe_run.request_environment", "transport.environment",
                    "effect_environment", "gitops_fds.effect_environment", "gitops_fds.prepare_capture",
                    "gitops_fds.capture_recipe", "_gh_command", "_lane.environment", "_environment_layer"}
    def census(texts):
        readers, seen_sinks, seen_lookups, errors = set(), set(), set(), []
        for module, source in texts.items():
            tree = ast.parse(source)
            parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
            for node in ast.walk(tree):
                current, function = node, None
                while current in parents:
                    current = parents[current]
                    if isinstance(current, ast.FunctionDef):
                        function = current
                        break
                if isinstance(node, ast.Assign) and function is not None and function.name in recipe_functions:
                    targets = {x.id for target in node.targets if isinstance(target, (ast.Name, ast.Tuple, ast.List)) for x in ast.walk(target) if isinstance(x, ast.Name)}
                    tracked = {"env"} if (module, function.name) == ("gitsafe", "resolve_base_ref") else {"env", "environ", "effective", "base", "prepared"}
                    if targets & tracked:
                        value = node.value
                        variants = (value.body, value.orelse) if isinstance(value, ast.IfExp) else (value,)
                        for variant in variants:
                            valid = isinstance(variant, ast.Call) and ast.unparse(variant.func) in recipe_calls
                            valid |= isinstance(variant, (ast.Name, ast.Tuple)) and isinstance(value, ast.IfExp)
                            valid |= function.name == "environment" and isinstance(variant, ast.DictComp) and any(isinstance(x, ast.Name) and x.id == "_LOCATION_ENV" for x in ast.walk(variant))
                            if not valid:
                                errors.append((module, function.name, "environment recipe bypass"))
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr in ("environ", "environb", "getenv"):
                    # Module-level type(os.environ) stores a type, never request values.
                    if function is None and isinstance(parents.get(node), ast.Call) and ast.unparse(parents[node].func) == "type":
                        continue
                    readers.add((module, function.name if function else None))
                if not isinstance(node, ast.Call):
                    continue
                call = ast.unparse(node.func)
                if call == "pathlookup.which":
                    site = (module, function.name if function else None)
                    seen_lookups.add(site)
                    ancestor = node
                    while ancestor in parents and not (isinstance(ancestor, ast.Call) and ast.unparse(ancestor.func).endswith(("find_executable", "transport.resolve"))):
                        ancestor = parents[ancestor]
                    if site not in lookups or not isinstance(ancestor, ast.Call) or not ast.unparse(ancestor.func).endswith(("find_executable", "transport.resolve")):
                        errors.append((module, "lookup bypass"))
                if call not in ("subprocess.run", "subprocess.Popen", "legacy_runner"):
                    continue
                site = (module, function.name if function else None, call)
                seen_sinks.add(site)
                if site not in sinks or function is None:
                    errors.append((module, "spawn bypass"))
                    continue
                calls = {ast.unparse(x.func) for x in ast.walk(function) if isinstance(x, ast.Call)}
                if "request_environment" not in calls:
                    errors.append((module, "environment bypass"))
                env = next((kw.value for kw in node.keywords if kw.arg == "env"), None)
                if call != "subprocess.Popen" and (not isinstance(env, ast.Name) or env.id not in ("env", "effective")):
                    errors.append((module, "unconstructed environment"))
                if call == "subprocess.Popen" and not any(kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id == "options" for kw in node.keywords):
                    errors.append((module, "holder options bypass"))
        if readers != {("gitsafe_run", "request_environment")}:
            errors.append(("readers", sorted(readers)))
        if seen_sinks != set(sinks) or seen_lookups != set(lookups):
            errors.append(("sites", seen_sinks, seen_lookups))
        return errors
    assert census(sources) == []
    transport = ast.parse(sources["gitsafe_run"])
    constructors = [n for n in transport.body if isinstance(n, ast.FunctionDef) and n.name == "request_environment"]
    resolvers = [n for n in transport.body if isinstance(n, ast.FunctionDef) and n.name == "find_executable"]
    assert len(constructors) == len(resolvers) == 1
    services = next(n for n in transport.body if isinstance(n, ast.FunctionDef) and n.name == "transport_services")
    assert ast.unparse(services.body[0].value) == "_TransportServices(request_environment, find_executable, Environment, merge_inputs)"
    leaf = ast.parse(sources["gitops_fds"])
    binder = next(n for n in leaf.body if isinstance(n, ast.FunctionDef) and n.name == "effect_environment")
    returns = [n for n in ast.walk(binder) if isinstance(n, ast.Return)]
    assert len(returns) == 1 and ast.unparse(returns[0].value.func) == "transport.environment"
    profiles = next(n for n in ast.walk(constructors[0]) if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id == "profile")
    assert ast.literal_eval(profiles.comparators[0]) == ("ordinary", "strict/effect")
    holder = ast.parse(gitops_fds._HOLDER_SOURCE)
    spawns = [n for n in ast.walk(holder) if isinstance(n, ast.Call) and ast.unparse(n.func) == "subprocess.Popen"]
    assert len(spawns) == 1 and not any(kw.arg == "env" for kw in spawns[0].keywords), "holder inherits the constructed environment; only its directory-fd bindings change"
    assert not any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "os" and n.attr in ("environ", "getenv") for n in ast.walk(holder))
    extra_reader = {**sources, "ghcli": sources["ghcli"] + "\ndef alternate(): return os.environ\n"}
    extra_spawn = {**sources, "ghcli": sources["ghcli"] + "\ndef bypass(): subprocess.run(['gh'], env={})\n"}
    extra_constructor = {**sources, "gitsafe_run": sources["gitsafe_run"].replace("effective = request_environment(", "effective = dict(", 1)}
    assert census(extra_reader) and census(extra_spawn) and census(extra_constructor)


@pytest.mark.usefixtures("strict_program")
def test_effect_strict_discovery_and_spawn_share_one_validated_source(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    source_dir, scratch = repo / "src", tmp_path / "scratch"
    source_dir.mkdir()
    scratch.mkdir()
    observed = []
    def launch(argv, **kwargs):
        observed.append(kwargs["env"])
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    clean = {"PATH": os.path.dirname(gitsafe.git_executable()), "REQUEST_MARKER": "one-request"}
    with gitsafe.custody(scratch=scratch, strict_lane=True, worktree_root=repo):
        result = gitsafe.run(["version"], source_dir, _environ=clean, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0 and len(observed) == 5
    assert len({id(env.origin) for env in observed}) == 1
    assert all(env["REQUEST_MARKER"] == "one-request" and env["PATH"] == clean["PATH"] for env in observed)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("operation", ["push", "fetch"])
@pytest.mark.parametrize("absolute", [False, True], ids=["bare-ssh", "absolute-ssh"])
def test_effect_ssh_positive_grammar_keeps_allowed_options(repo, tmp_path, effect_lock, site, operation, absolute):
    import contextlib
    import json
    import shlex
    host, scratch = tmp_path / "host", tmp_path / "scratch"
    host.mkdir()
    scratch.mkdir()
    marker, ssh = host / "argv.json", host / "ssh"
    _native_program(ssh, "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\nPath(" + repr(str(marker))
        + ").write_text(json.dumps(sys.argv[1:]))\nraise SystemExit(1)\n")
    ssh.chmod(0o700)
    command = shlex.join([str(ssh) if absolute else "ssh", "-vv", "-p", "2222", "-o", "LogLevel=ERROR"])
    context = gitsafe.custody(scratch=scratch, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context:
        result = gitsafe.run([operation, "git@fixture.invalid:repository", "HEAD"], repo,
            _environ={"PATH": str(host) + os.pathsep + os.path.dirname(gitsafe.git_executable())},
            _env={"GIT_ALLOW_PROTOCOL": "ssh"}, _hardening=_network_hardening("-c", "core.sshCommand=" + command), effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode != 0 and marker.exists()
    argv = json.loads(marker.read_text())
    assert argv[:4] == ["-o", "IgnoreUnknown=ForkAfterAuthentication", "-o", "ControlMaster=no"]
    assert "ControlPath=none" in argv and "ControlPersist=no" in argv
    assert ["-vv", "-p", "2222", "-o", "LogLevel=ERROR"] == argv[12:17]


@pytest.mark.usefixtures("strict_program")
def test_effect_default_single_remote_matches_git(repo, tmp_path, effect_lock):
    _git(repo, "config", "remote.only.url", str(repo))
    _git(repo, "config", "core.sshCommand", "/usr/bin/env ssh")
    result = gitsafe.run(["fetch"], repo, _hardening=_network_hardening(),
        _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0


@pytest.mark.usefixtures("strict_program")
def test_effect_holder_spawn_failure_is_definite(repo, tmp_path, effect_lock):
    before = set(os.listdir("/proc/self/fd"))
    with gitsafe.custody(scratch=tmp_path, worktree_root=repo), pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.capture(["/nonexistent-claim-check-git", "version"], cwd=repo, env={"PATH": os.path.dirname(gitsafe.git_executable())},
            stdin=None, timeout=3, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_failed"
    assert caught.value.process_started is False and caught.value.effect_process_started is False
    assert caught.value.next_action
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.usefixtures("strict_program")
def test_effect_holder_spawn_failure_keeps_cas_definite(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, worktree_root=repo)
    commit = _git(repo, "rev-parse", "HEAD").strip()
    failed = []
    def launch(argv, **kwargs):
        if "update-ref" in argv[9:]:
            argv = list(argv)
            argv[9] = "/nonexistent-claim-check-git"
            failed.append(True)
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    with pytest.raises(gitsafe.GitError) as caught:
        lane.cas("refs/heads/lane/definite", commit, None, effect_fds=(effect_lock,))
    assert failed == [True]
    assert caught.value.code == "ref_update_failed"
    assert _git(repo, "for-each-ref", "--format=%(refname)", "refs/heads/lane/definite") == ""


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("location", ["checkout", "extra-root"])
def test_effect_tmpdir_fenced_in_same_context_as_path(repo, tmp_path, effect_lock, site, location):
    import json
    write_root = repo if location == "checkout" else tmp_path / "other-model"
    write_root.mkdir(exist_ok=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    stub = tmp_path / "git"
    _native_program(stub, "#!" + sys.executable + "\nimport json, os\nprint(json.dumps(os.environ.get('TMPDIR')))\n")
    stub.chmod(0o700)
    source = {"PATH": str(tmp_path), "TMPDIR": str(write_root)}
    if site == "capture":
        with gitsafe.custody(scratch=scratch, worktree_root=repo):
            result = gitsafe_run.capture([str(stub), "version"], cwd=repo, env=source,
                stdin=None, timeout=3, error=gitsafe.GitError, effect_fds=(effect_lock,), write_roots=(write_root,), worktree_root=repo)
    else:
        result = gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), write_roots=(write_root,), worktree_root=repo)
    assert result.returncode == 0 and json.loads(result.stdout) is None


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("issued_with_effect", [False, True])
def test_effect_nested_validation_shares_request_environment(repo, tmp_path, effect_lock, monkeypatch, issued_with_effect):
    from types import SimpleNamespace
    lane = gitsafe.lane_runner(repo, tmp_path, effect_fds=(effect_lock,) if issued_with_effect else None, worktree_root=repo)
    (tmp_path / "objects").mkdir()
    observed = []
    def launch(argv, **kwargs):
        observed.append(kwargs["env"])
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    result = lane.run(["hash-object", "-w", "--stdin", "--path=claim.txt"], stdin=b"content", effect_fds=(effect_lock,))
    assert result.returncode == 0 and len(observed) == 2
    assert len({id(env.origin) for env in observed}) == 1


@pytest.mark.usefixtures("strict_program")
def test_effect_environment_fences_model_owned_alias_before_it_can_be_replaced(repo, tmp_path, effect_lock):
    import json
    from conftest import symlink_or_skip
    host = tmp_path / "host"
    host.mkdir()
    alias = repo / "alias"
    symlink_or_skip(host, alias, target_is_directory=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    stub = tmp_path / "git"
    _native_program(stub, "#!" + sys.executable + "\nimport json, os\nprint(json.dumps([os.environ['PATH'], os.environ.get('TMPDIR')]))\n")
    stub.chmod(0o700)
    with gitsafe.custody(scratch=scratch, worktree_root=repo):
        result = gitsafe_run.capture([str(stub), "version"], cwd=repo,
            env={"PATH": str(alias), "TMPDIR": str(alias)}, stdin=None, timeout=3,
            error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0 and json.loads(result.stdout) == ["", None]


@pytest.mark.parametrize("site", ["run", "capture", "lane_runner"])
@pytest.mark.parametrize("roots", [None, 7, "/untrusted-root", (None,) * 17], ids=["none", "integer", "string", "many"])
def test_effect_write_roots_refuse_before_expansion(repo, tmp_path, effect_lock, site, roots):
    with pytest.raises(gitsafe.GitError) as caught:
        if site == "lane_runner":
            gitsafe.lane_runner(repo, tmp_path, effect_fds=(effect_lock,), write_roots=roots, worktree_root=repo)
        elif site == "capture":
            with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
                gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env={}, stdin=None,
                    timeout=3, error=gitsafe.GitError, effect_fds=(effect_lock,), write_roots=roots, worktree_root=repo)
        else:
            gitsafe.run(["version"], repo, effect_fds=(effect_lock,), write_roots=roots, worktree_root=repo)
    assert caught.value.code == "effect_environment_unavailable"
    assert caught.value.process_started is False and caught.value.next_action


def test_ordinary_capture_failure_keeps_legacy_start_metadata(repo, tmp_path):
    with gitsafe.custody(scratch=tmp_path, stdout_limit=1), pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env=dict(os.environ), stdin=None,
            timeout=3, error=gitsafe.GitError)
    assert caught.value.code == "git_output_limit" and caught.value.process_started is True
    assert getattr(caught.value, "effect_process_started", None) is None


@pytest.mark.usefixtures("strict_program")
def test_effect_holder_lost_start_acknowledgment_is_unknown_and_closes_fds(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    import select
    def fail(*args, **kwargs):
        raise OSError("untrusted status-boundary input")
    monkeypatch.setattr(gitops_fds, "select", SimpleNamespace(**{**vars(select), "select": fail}))
    before = set(os.listdir("/proc/self/fd"))
    with gitsafe.custody(scratch=tmp_path, worktree_root=repo), pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env={}, stdin=None,
            timeout=3, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_failed"
    assert caught.value.process_started is True and caught.value.effect_process_started is True
    assert caught.value.next_action.startswith("Observe") and "untrusted" not in str(caught.value)
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("form", ["local", "pushurl"])
def test_effect_remote_supported_owner_destinations(repo, tmp_path, effect_lock, site, form):
    import contextlib
    destination = repo / "destination.git" if form == "local" else tmp_path / "destination.git"
    _git(repo, "init", "--bare", str(destination))
    if form == "pushurl":
        _git(repo, "config", "remote.upload.pushurl", str(destination))
    target = "destination.git" if form == "local" else "upload"
    context = gitsafe.custody(scratch=tmp_path, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context:
        result = gitsafe.run(["push", target, "HEAD:refs/heads/result"], repo, _hardening=_network_hardening(),
            _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0
    assert _git(destination, "rev-parse", "refs/heads/result").strip() == _git(repo, "rev-parse", "HEAD").strip()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("record", ["remotes", "branches"])
def test_effect_legacy_record_precedes_literal_helper_syntax(repo, tmp_path, effect_lock, site, record):
    import contextlib
    directory = repo / ".git" / record
    directory.mkdir(exist_ok=True)
    (directory / "fixture::record").write_text("URL: git@fixture.invalid:repository\n", encoding="utf-8")
    context = gitsafe.custody(scratch=tmp_path, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", "fixture::record", "HEAD"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "unsupported_remote_form" and caught.value.effect_process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("operation,key", [("fetch", "remote"), ("push", "pushRemote")])
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_default_remote_uses_full_branch_ref_with_colliding_tag(repo, tmp_path, effect_lock, operation, key, site):
    import contextlib
    _git(repo, "tag", "main")
    _git(repo, "config", "remote.origin.url", str(repo))
    _git(repo, "config", "remote.selected.url", "git@fixture.invalid:repository")
    _git(repo, "config", "branch.main." + key, "selected")
    _git(repo, "config", "core.sshCommand", "env ssh")
    context = gitsafe.custody(scratch=tmp_path, worktree_root=repo) if site == "capture" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run([operation], repo, _hardening=_network_hardening(), _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused" and caught.value.effect_process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("form", ["flag", "yes", "on-demand"])
@pytest.mark.parametrize("operation", ["push", "fetch"])
def test_effect_explicit_recursion_refuses_before_effect(repo, tmp_path, effect_lock, form, operation):
    _git(repo, "config", "remote.origin.url", str(repo))
    options = ["--recurse-submodules" + ("=" + form if form != "flag" else "")]
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run([operation, *options, "origin"], repo, _hardening=_network_hardening(),
            _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "unsupported_remote_form" and caught.value.effect_process_started is False


@pytest.mark.usefixtures("strict_program")
def test_effect_custody_scope_environment_and_call_precedence(repo, tmp_path, effect_lock):
    scoped = {"GIT_ALLOW_PROTOCOL": "file", "GIT_AUTHOR_NAME": "Scope", "GIT_AUTHOR_EMAIL": "scope@example.invalid",
        "GIT_COMMITTER_NAME": "Scope", "GIT_COMMITTER_EMAIL": "scope@example.invalid"}
    with gitsafe.custody(scratch=tmp_path, env=scoped, worktree_root=repo):
        result = gitsafe.run(["fetch", str(repo), "HEAD"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
        assert result.returncode == 0
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        result = gitsafe.run(["commit-tree", tree], repo, stdin=b"scoped identity\n",
            _env={"GIT_AUTHOR_NAME": "Call"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0
    body = _git(repo, "cat-file", "-p", result.stdout.decode().strip())
    assert "author Call <scope@example.invalid>" in body and "committer Scope <scope@example.invalid>" in body


@pytest.mark.skipif(not gitops_fds.descriptor_supported() or not hasattr(os, "pidfd_open"), reason="race latch requires Linux subreaper and pidfds")
def test_effect_reconcile_cleanup_race_is_terminal(repo, tmp_path):
    import fcntl
    import select
    import signal
    from threading import Event
    if not hasattr(signal, "pidfd_send_signal"):
        pytest.skip("cleanup-event injection requires pidfd signalling")
    reconciled, held = Event(), []
    def release():
        while held:
            held.pop().close()
    def reconcile(journal, *args):
        reconciled.set()
        release()
        return journal.reconcile(*args)
    def cleanup(worker_fd, lock):
        try:
            signal.pidfd_send_signal(worker_fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        assert select.select([worker_fd], [], [], 6)[0], "descendant exit was not observed"
        if not reconciled.is_set():
            stream = lock.open("r+b")
            held.append(stream)
            fcntl.flock(stream, fcntl.LOCK_EX)
    try:
        _assert_effect_survives_owner(tmp_path, repo, "remote_git", reconciliation=reconcile, cleanup_event=cleanup)
    finally:
        release()


@pytest.mark.usefixtures("strict_program")
def test_effect_strict_direct_capture_uses_its_command_environment(repo, tmp_path, effect_lock):
    argv = [gitsafe.git_executable(), *gitsafe._HARDENING, *gitsafe_run._LANE_OPTIONS, "version"]
    with gitsafe.custody(scratch=tmp_path, strict_lane=True, worktree_root=repo):
        result = gitsafe_run.capture(argv, cwd=repo, env={"PATH": os.path.dirname(argv[0])}, stdin=None,
            timeout=3, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0 and result.stdout.startswith(b"git version ")


@pytest.mark.parametrize("form", ["tty", "hardening"])
def test_effect_strict_refusal_precedes_any_discovery(repo, tmp_path, effect_lock, monkeypatch, form):
    from types import SimpleNamespace
    calls = []
    def launch(argv, **kwargs):
        calls.append(argv)
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    arguments = {"tty": True} if form == "tty" else {"_hardening": gitsafe_run.HARDENING_KEEP_HOOKS_PATH}
    with gitsafe.custody(scratch=tmp_path, strict_lane=True, worktree_root=repo), pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo, effect_fds=(effect_lock,), **arguments, worktree_root=repo)
    assert caught.value.code == "git_custody_refused" and calls == []


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("url", ["git@fixture.invalid:org/repo::sub", "fixture.invalid:repo::sub", "ssh://fixture.invalid/repo::sub"])
def test_effect_scp_paths_with_double_colon_still_apply_ssh_policy(repo, tmp_path, effect_lock, url):
    _git(repo, "config", "core.sshCommand", "env ssh")
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", url, "HEAD"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused" and caught.value.effect_process_started is False


@pytest.mark.usefixtures("strict_program")
def test_effect_remote_group_normalizes_git_key_case(repo, tmp_path, effect_lock):
    _git(repo, "config", "remote.MyGroup.url", str(repo))
    _git(repo, "config", "remotes.MyGroup", "ssh-remote")
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", "MyGroup"], repo, _hardening=_network_hardening(), effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "unsupported_remote_form" and caught.value.effect_process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("operation", ["run", "publish", "cas"])
def test_effect_existing_lane_resolves_program_at_each_call(repo, tmp_path, effect_lock, operation):
    hostile = repo / "bin"
    hostile.mkdir()
    source = repo / "src"
    source.mkdir()
    scratch = tmp_path / "lane-scratch"
    scratch.mkdir()
    (scratch / "objects").mkdir()
    marker = tmp_path / "hostile-effect-git"
    real = gitsafe.git_executable()
    stub = hostile / "git"
    _native_program(stub, "#!" + sys.executable + "\nimport os, sys\nfrom pathlib import Path\n"
        + "if os.environ.get('GIT_CONFIG_NOSYSTEM')=='1': Path(" + repr(str(marker)) + ").touch()\n"
        + "os.execv(" + repr(real) + ", [" + repr(real) + ", *sys.argv[1:]])\n")
    stub.chmod(0o700)
    oid = _git(repo, "rev-parse", "HEAD").strip()
    code = "\nimport hashlib, os, struct, sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nlane=gitsafe.lane_runner(sys.argv[2],sys.argv[3],environ={'PATH':sys.argv[7]}, worktree_root=Path(sys.argv[2]).parent)\nPath(sys.argv[2],'.git').write_bytes(b'')\nwith open(sys.argv[4],'w+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    if sys.argv[5]=='run': assert lane.run(['version'],effect_fds=fds).returncode==0\n    elif sys.argv[5]=='publish':\n        pack=b'PACK'+struct.pack('!II',2,0)\n        assert lane.publish(pack+hashlib.sha1(pack).digest(),effect_fds=fds).returncode==0\n    else: assert lane.cas('refs/heads/lane/clean',sys.argv[6],None,effect_fds=fds)=='updated'\n"
    result = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(source), str(scratch), str(tmp_path / "lane-lock"), operation, oid, os.path.dirname(real)],
        env={**os.environ, "PATH": str(hostile) + os.pathsep + os.environ["PATH"]}, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), "effect reused the ambient program selected at lane creation"


@pytest.mark.usefixtures("strict_program")
def test_effect_numeric_remote_helper_is_not_scp_ssh(repo, tmp_path, effect_lock):
    marker = tmp_path / "helper-ran"
    helper = tmp_path / "git-remote-1git"
    helper.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
    helper.chmod(0o700)
    _git(repo, "config", "core.sshCommand", "env ssh")
    result = gitsafe.run(["fetch", "1git::target"], repo, _hardening=_network_hardening(),
        _environ={"PATH": str(tmp_path) + os.pathsep + os.path.dirname(gitsafe.git_executable())},
        _env={"GIT_ALLOW_PROTOCOL": "1git"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert marker.exists() and result.returncode != 0


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("override", [False, True])
def test_effect_scoped_home_has_call_precedence_and_filters_programs(repo, tmp_path, effect_lock, override):
    import json
    stub = tmp_path / "git"
    _native_program(stub, "#!" + sys.executable + "\nimport json, os\nprint(json.dumps([os.environ['HOME'], os.environ.get('GIT_SSH_COMMAND')]))\n")
    stub.chmod(0o700)
    source = {"PATH": str(tmp_path), "HOME": str(tmp_path / "base")}
    scoped = {"HOME": str(tmp_path / "owner")}
    call = {"HOME": str(tmp_path / "call")} if override else None
    with gitsafe.custody(scratch=repo, env=scoped, worktree_root=repo):
        result = gitsafe.run(["version"], repo, _environ=source, _env=call, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0
    assert json.loads(result.stdout) == [str(tmp_path / ("call" if override else "owner")), None]


@pytest.mark.parametrize("environment", [[], ["x"], 7, "x"], ids=["empty-list", "list", "integer", "text"])
def test_effect_strict_environment_refuses_before_merge_or_discovery(repo, tmp_path, effect_lock, environment):
    with gitsafe.custody(scratch=tmp_path, strict_lane=True, worktree_root=repo), pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo, _env=environment, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_custody_refused" and caught.value.process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("setting", ["FALSE", "off", "0"])
def test_effect_explicit_nonrecursive_fetch_is_supported(repo, tmp_path, effect_lock, setting):
    _git(repo, "config", "submodule.recurse", setting)
    result = gitsafe.run(["fetch", "--recurse-submodules=no", str(repo), "HEAD"], repo,
        _hardening=_network_hardening(), _env={"GIT_ALLOW_PROTOCOL": "file"}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0


@pytest.mark.usefixtures("strict_program")
def test_effect_nonbranch_symbolic_head_does_not_select_branch_remote(repo, tmp_path, effect_lock):
    _git(repo, "tag", "main")
    _git(repo, "symbolic-ref", "HEAD", "refs/tags/main")
    _git(repo, "config", "remote.origin.url", "git@fixture.invalid:repository")
    _git(repo, "config", "remote.selected.url", str(repo))
    _git(repo, "config", "branch.refs/tags/main.remote", "selected")
    shim = tmp_path / "ssh"
    _native_program(shim, "#!/bin/sh\nexit 1\n")
    shim.chmod(0o700)
    _git(repo, "config", "core.sshCommand", "env ssh")
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch"], repo, _hardening=_network_hardening(),
            _environ={"PATH": str(tmp_path) + os.pathsep + os.path.dirname(gitsafe.git_executable())}, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "effect_ssh_command_refused" and caught.value.effect_process_started is False


@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("form", ["missing", "none", "relative", "nonexistent", "outside", "symlink", "custody-mismatch"])
def test_effect_owner_root_refuses_before_program_lookup(repo, tmp_path, effect_lock, monkeypatch, site, form):
    from conftest import symlink_or_skip
    from types import SimpleNamespace
    root = repo
    if form == "none": root = None
    elif form == "relative": root = Path(".")
    elif form == "nonexistent": root = tmp_path / "absent"
    elif form == "outside": root = _repo(tmp_path / "other")
    elif form == "symlink":
        root = tmp_path / "root-link"
        symlink_or_skip(repo, root, target_is_directory=True)
    command = [gitsafe.git_executable(), "version"]
    observed = []
    def unexpected(*args, **kwargs):
        observed.append(True)
        pytest.fail("invalid root reached lookup or spawn")
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=unexpected))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    kwargs = {} if form == "missing" else {"worktree_root": root}
    with gitsafe.custody(scratch=tmp_path, **({"worktree_root": _repo(tmp_path / "scope-other")} if form == "custody-mismatch" else {})):
        with pytest.raises(gitsafe.GitError) as caught:
            if site == "run":
                gitsafe.run(["version"], repo, effect_fds=(effect_lock,), **kwargs)
            else:
                gitsafe_run.capture(command, cwd=repo, env={}, stdin=None, timeout=3,
                    error=gitsafe.GitError, effect_fds=(effect_lock,), **kwargs)
    assert caught.value.code == "effect_environment_unavailable" and caught.value.process_started is False
    assert caught.value.next_action and observed == []


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
def test_effect_explicit_root_never_trusts_a_subdirectory_marker(repo, tmp_path, effect_lock, site):
    source = repo / "src"
    source.mkdir()
    (source / ".git").write_bytes(b"")
    hostile = repo / "bin"
    hostile.mkdir()
    marker = tmp_path / "model-git-ran"
    program = hostile / "git"
    program.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nprint('git version hostile')\n", encoding="utf-8")
    program.chmod(0o700)
    env = {"PATH": str(hostile) + os.pathsep + os.path.dirname(gitsafe.git_executable()), "TMPDIR": str(repo)}
    with gitsafe.custody(scratch=tmp_path):
        try:
            if site == "run": result = gitsafe.run(["version"], source, _environ=env, worktree_root=repo, effect_fds=(effect_lock,))
            else: result = gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=source, env=env, stdin=None,
                timeout=3, error=gitsafe.GitError, worktree_root=repo, effect_fds=(effect_lock,))
        except gitsafe.GitError as error:
            assert error.code == "effect_environment_unavailable" and error.process_started is False
        else:
            assert result.returncode == 0 and b"hostile" not in result.stdout
    assert not marker.exists()


def test_effect_direct_capture_refuses_program_inside_declared_roots(repo, tmp_path, effect_lock):
    marker = tmp_path / "direct-model-program-ran"
    program = repo / "git"
    program.write_text("#!/bin/sh\n: > '" + str(marker) + "'\nprintf 'git version hostile\\n'\n", encoding="utf-8")
    program.chmod(0o700)
    with gitsafe.custody(scratch=tmp_path, worktree_root=repo):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe_run.capture([str(program), "version"], cwd=repo,
                env={"PATH": os.path.dirname(gitsafe.git_executable())}, stdin=None, timeout=3,
                error=gitsafe.GitError, worktree_root=repo, effect_fds=(effect_lock,))
    assert caught.value.code == "effect_command_refused"
    assert caught.value.process_started is False and caught.value.next_action
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("replacement", ["root", "cwd", "marker"])
def test_effect_spawn_is_bound_before_component_replacement(repo, tmp_path, effect_lock, monkeypatch, replacement):
    from conftest import symlink_or_skip
    from types import SimpleNamespace
    source = repo / "src" / "deep"
    source.mkdir(parents=True)
    other = _repo(tmp_path / "other")
    _git(repo, "config", "aegis.rootProbe", "owner-bound")
    _git(other, "config", "aegis.rootProbe", "foreign")
    changed = []
    original = repo if replacement == "root" else repo / "src"
    displaced = original.with_name(original.name + "-displaced")
    def launch(argv, **options):
        if not changed:
            changed.append(True)
            if replacement == "marker":
                (source / ".git").write_text("gitdir: " + str(other / ".git") + "\n", encoding="utf-8")
            else:
                original.rename(displaced)
                symlink_or_skip(other, original, target_is_directory=True)
        # Record facts while the parent descriptors are still open.
        assert options["pass_fds"][0] == effect_lock
        import stat
        assert [stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in options["pass_fds"]].count(True) == 1
        assert sum(stat.S_ISDIR(os.fstat(fd).st_mode) for fd in options["pass_fds"]) == 2
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    try:
        result = gitsafe.run(["config", "--get", "aegis.rootProbe"], source,
            effect_fds=(effect_lock,), worktree_root=repo)
        assert result.returncode == 0 and result.stdout == b"owner-bound\n"
        assert changed == [True]
    finally:
        if replacement != "marker" and displaced.exists():
            if original.is_symlink(): original.unlink()
            displaced.rename(original)


@pytest.mark.parametrize("stage", ["ancestor", "cwd", "gitdir", "record"])
def test_effect_root_open_failure_is_typed_and_closes_descriptors(repo, tmp_path, effect_lock, monkeypatch, stage):
    import errno
    from contextlib import contextmanager
    from aegis_core import storage_confined
    from types import SimpleNamespace
    source = repo / "src"
    source.mkdir()
    before = set(os.listdir("/proc/self/fd"))
    target = {"ancestor": repo.name, "cwd": "src", "gitdir": ".git", "record": "HEAD"}[stage]
    def fail(path, *args, **kwargs):
        if path == target: raise OSError(errno.EIO, "untrusted-root-input")
        return os.open(path, *args, **kwargs)
    @contextmanager
    def directory(root, parts):
        with storage_confined.confined_file(root, parts) as handle:
            if stage == "ancestor":
                raise storage_confined.ConfinedFileError("io")
            yield handle
    class Record:
        def __init__(self, parent, name):
            self.record = storage_confined.ConfinedFile(parent, name)
        def read_bytes(self, limit):
            if stage == "record":
                raise storage_confined.ConfinedFileError("io")
            return self.record.read_bytes(limit)
    monkeypatch.setattr(gitops_fds, "os", SimpleNamespace(**{**vars(os), "open": fail}))
    monkeypatch.setattr(gitops_fds, "storage_confined", SimpleNamespace(
        confined_file=directory, ConfinedFile=Record, ConfinedFileError=storage_confined.ConfinedFileError))
    for _ in range(2):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.run(["version"], source, worktree_root=repo, effect_fds=(effect_lock,))
        assert caught.value.code == "effect_environment_unavailable" and caught.value.process_started is False
        assert "untrusted-root-input" not in str(caught.value) and caught.value.next_action
        assert set(os.listdir("/proc/self/fd")) == before
        os.fstat(effect_lock)


@pytest.mark.usefixtures("strict_program")
def test_effect_explicit_root_accepts_linked_worktree_and_recorded_lane_root(repo, tmp_path, effect_lock):
    linked = tmp_path / "linked"
    _git(repo, "worktree", "add", "-b", "linked", str(linked))
    source = linked / "src"
    source.mkdir()
    result = gitsafe.run(["rev-parse", "HEAD"], source, worktree_root=linked, effect_fds=(effect_lock,))
    assert result.returncode == 0 and result.stdout.decode().strip() == _git(repo, "rev-parse", "HEAD").strip()
    scratch = tmp_path / "lane-scratch"
    scratch.mkdir()
    lane = gitsafe.lane_runner(source, scratch, worktree_root=linked, effect_fds=(effect_lock,))
    assert lane.paths()[1] == linked and lane.run(["version"]).returncode == 0


@pytest.mark.usefixtures("strict_program")
def test_effect_raw_call_requires_root_even_with_a_previous_environment(repo, effect_lock, monkeypatch):
    from types import SimpleNamespace
    environments = []
    def launch(argv, **options):
        environments.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    assert gitsafe.run(["version"], repo, worktree_root=repo, effect_fds=(effect_lock,)).returncode == 0
    assert len(environments) == 1
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo, _environ=environments[0], effect_fds=(effect_lock,))
    assert caught.value.code == "effect_environment_unavailable" and caught.value.process_started is False
    assert len(environments) == 1


_LANE_UPGRADE_ROOT_PROBE = r'''
import contextlib, hashlib, struct, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitops_fds
repo, cwd, scratch, lock, operation, oid, form, hostile = sys.argv[2:]
roots = [hostile] if form == 'extra-root' else []
options = {} if form.startswith('missing') else {'worktree_root': repo}
lane = gitsafe.lane_runner(cwd, scratch, write_roots=roots, **options)
roots.clear()  # Issuance must retain the caller's original roots independently.
assert lane.run(['version']).returncode == 0
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    context = gitsafe.custody(scratch=Path(scratch), worktree_root=repo) if form == 'missing-scoped' else contextlib.nullcontext()
    with context:
        try:
            if operation == 'run':
                assert lane.run(['version'], effect_fds=fds).returncode == 0
            elif operation == 'publish':
                pack = b'PACK' + struct.pack('!II', 2, 0)
                assert lane.publish(pack + hashlib.sha1(pack).digest(), effect_fds=fds).returncode == 0
            else:
                assert lane.cas('refs/heads/lane/root-proof', oid, None, effect_fds=fds) == 'updated'
        except gitsafe.GitError as exc:
            assert form != 'extra-root', exc.code
            assert exc.code == 'effect_environment_unavailable' and exc.process_started is False and exc.next_action
        else:
            assert form == 'extra-root', 'effect upgrade accepted missing or misleading root provenance'
'''


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("operation", ["run", "publish", "cas"])
@pytest.mark.parametrize("form", ["before-marker", "extra-root", "missing", "missing-scoped"])
def test_effect_lane_retains_custodian_roots_before_issuance(repo, tmp_path, effect_lock, operation, form):
    source = repo / "src"
    source.mkdir()
    if form == "before-marker":
        (source / ".git").write_text("gitdir: " + str(repo / ".git") + "\n", encoding="utf-8")
    hostile = (tmp_path / "extra-model") if form == "extra-root" else repo / "bin"
    hostile.mkdir()
    marker = tmp_path / "model-program-started"
    real = gitsafe.git_executable()
    program = hostile / "git"
    _native_program(program, "#!" + sys.executable + "\nimport os, sys\nfrom pathlib import Path\n"
        + "if os.environ.get('GIT_CONFIG_NOSYSTEM') == '1': Path(" + repr(str(marker)) + ").touch()\n"
        + "os.execv(" + repr(real) + ", [" + repr(real) + ", *sys.argv[1:]])\n")
    program.chmod(0o700)
    scratch = tmp_path / "lane-scratch"
    (scratch / "objects").mkdir(parents=True)
    child = subprocess.run([sys.executable, "-I", "-c", _LANE_UPGRADE_ROOT_PROBE, str(ROOT), str(repo),
        str(source if form == "before-marker" else repo), str(scratch), str(tmp_path / "probe-lock"), operation,
        _git(repo, "rev-parse", "HEAD").strip(), form, str(hostile)],
        env={**os.environ, "PATH": str(hostile) + os.pathsep + os.path.dirname(real)},
        capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert not marker.exists(), "effect executed a program below the custodian's root or write roots"


def _recursive_transport_fixture(tmp_path, setting):
    sub = _repo(tmp_path / "sub-origin")
    (sub / "file").write_text("old\n", encoding="utf-8")
    _commit(sub)
    origin = _repo(tmp_path / "super-origin")
    _git(origin, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "dep")
    _commit(origin)
    consumer = tmp_path / "consumer"
    _git(tmp_path, "-c", "protocol.file.allow=always", "clone", "-q", "--recurse-submodules", str(origin), str(consumer))
    marker = tmp_path / "submodule-ssh.json"
    shim = tmp_path / "ssh"
    _native_program(shim, "#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\nPath("
        + repr(str(marker)) + ").write_text(json.dumps(sys.argv[1:]))\nraise SystemExit(1)\n")
    shim.chmod(0o700)
    _git(consumer / "dep", "config", "remote.origin.url", "ssh://fixture.invalid/dependency")
    _git(consumer / "dep", "config", "core.sshCommand", str(shim))
    if setting == "push-config":
        (consumer / "dep" / "file").write_text("new\n", encoding="utf-8")
        _commit(consumer / "dep")
        _commit(consumer)
        _git(consumer, "config", "push.recurseSubmodules", "on-demand")
        _git(origin, "config", "receive.denyCurrentBranch", "ignore")
    else:
        (sub / "file").write_text("new\n", encoding="utf-8")
        _commit(sub)
        oid = _git(sub, "rev-parse", "HEAD").strip()
        _git(origin / "dep", "fetch", "-q", str(sub), "main")
        _git(origin / "dep", "checkout", "-q", oid)
        _commit(origin)
        if setting == "fetch-config": _git(consumer, "config", "fetch.recurseSubmodules", "true")
        elif setting == "submodule-config": _git(consumer, "config", "submodule.dep.fetchRecurseSubmodules", "true")
        elif setting == "gitmodules": _git(consumer, "config", "-f", ".gitmodules", "submodule.dep.fetchRecurseSubmodules", "true")
        elif setting == "generic-config": _git(consumer, "config", "submodule.recurse", "true")
    return consumer, marker, origin


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("site", ["run", "capture"])
@pytest.mark.parametrize("setting", ["default-fetch", "fetch-config", "submodule-config", "gitmodules", "generic-config", "push-config"])
def test_effect_transports_disable_all_submodule_recursion(tmp_path, effect_lock, setting, site):
    consumer, marker, origin = _recursive_transport_fixture(tmp_path, setting)
    operation = "push" if setting == "push-config" else "fetch"
    args = [operation, "origin", "main"]
    if operation == "push":
        old = _git(origin, "rev-parse", "refs/heads/main")
        control = subprocess.run([gitsafe.git_executable(), "-c", "protocol.allow=always", "push",
            "--recurse-submodules=on-demand", "origin", "main"], cwd=consumer, capture_output=True, timeout=15)
        assert control.returncode != 0 and marker.exists()
        assert _git(origin, "rev-parse", "refs/heads/main") == old
        marker.unlink()
    source = {"PATH": os.path.dirname(gitsafe.git_executable()), "GIT_ALLOW_PROTOCOL": "file:ssh"}
    if site == "capture":
        scratch = tmp_path / "capture"
        scratch.mkdir()
        with gitsafe.custody(scratch=scratch, worktree_root=consumer):
            result = gitsafe_run.capture([gitsafe.git_executable(), *_network_hardening(), *args], cwd=consumer,
                env=source, stdin=None, timeout=15, error=gitsafe.GitError,
                effect_fds=(effect_lock,), worktree_root=consumer)
    else:
        result = gitsafe.run(args, consumer, _hardening=_network_hardening(), _environ=source,
            timeout=15, effect_fds=(effect_lock,), worktree_root=consumer)
    assert not marker.exists(), "effect started the populated SSH submodule transport"
    assert result.returncode == 0, result.stderr
    # Explicit recursion after a nonrecursive fetch confirms the SSH fixture.
    # The push control ran first so tracking-ref updates cannot mask recursion.
    if operation == "fetch":
        control = subprocess.run([gitsafe.git_executable(), "-c", "protocol.allow=always", "fetch",
            "--recurse-submodules=yes", "origin", "main"], cwd=consumer, capture_output=True, timeout=15)
        assert control.returncode != 0 and marker.exists()


@pytest.mark.usefixtures("strict_program")
def test_effect_lane_write_root_alias_remains_fenced_during_replacement(repo, tmp_path, effect_lock):
    from conftest import symlink_or_skip
    old, new = tmp_path / "old-model", tmp_path / "new-model"
    marker = tmp_path / "alias-program-started"
    real = gitsafe.git_executable()
    for root in (old, new):
        (root / "bin").mkdir(parents=True)
        script = root / "bin" / "git"
        _native_program(script, "#!" + sys.executable + "\nimport os, sys\nfrom pathlib import Path\n"
            + "if os.environ.get('GIT_CONFIG_NOSYSTEM') == '1': Path(" + repr(str(marker)) + ").touch()\n"
            + "os.execv(" + repr(real) + ", [" + repr(real) + ", *sys.argv[1:]])\n")
        script.chmod(0o700)
    alias = tmp_path / "model-alias"
    symlink_or_skip(old, alias, target_is_directory=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = r'''
import os, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitops_fds
repo, scratch, alias, replacement, lock = sys.argv[2:]
lane = gitsafe.lane_runner(repo, scratch, worktree_root=repo, write_roots=(alias,))
realpath, changed = os.path.realpath, []
def replace_alias(path, *args, **kwargs):
    result = realpath(path, *args, **kwargs)
    if str(path) == alias and not changed:
        changed.append(True)
        Path(alias).unlink()
        Path(alias).symlink_to(replacement, target_is_directory=True)
    return result
# Isolated OS boundary: neither the real os module nor the pytest process changes.
gitops_fds.os = SimpleNamespace(**{**vars(os), 'path': SimpleNamespace(**{**vars(os.path), 'realpath': replace_alias})})
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    assert lane.run(['version'], effect_fds=fds).returncode == 0
assert changed == [True]
'''
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(scratch), str(alias), str(new),
        str(tmp_path / "alias-lock")], env={**os.environ, "PATH": str(alias / "bin") + os.pathsep + os.path.dirname(real)},
        capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr
    assert not marker.exists(), "replacing a declared write-root alias escaped its fence"


@pytest.mark.usefixtures("strict_program")
def test_effect_lane_issuance_honors_supplied_environment(repo, tmp_path, effect_lock):
    hostile = tmp_path / "ambient-model"
    hostile.mkdir()
    marker = tmp_path / "ambient-program-started"
    real = gitsafe.git_executable()
    script = hostile / "git"
    _native_program(script, "#!" + sys.executable + "\nimport os,sys\nfrom pathlib import Path\nPath("
        + repr(str(marker)) + ").touch()\nos.execv(" + repr(real) + ", [" + repr(real) + ", *sys.argv[1:]])\n")
    script.chmod(0o700)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitops_fds
repo, scratch, hostile, real_path, marker, lock = sys.argv[2:]
lane = gitsafe.lane_runner(repo, scratch, environ={'PATH':real_path}, write_roots=(hostile,), worktree_root=repo)
assert not Path(marker).exists(), 'ordinary issuance ignored its supplied environment'
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    assert lane.run(['version'], effect_fds=fds).returncode == 0
'''
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(scratch), str(hostile),
        os.path.dirname(real), str(marker), str(tmp_path / "lock")],
        env={**os.environ, "PATH": str(hostile) + os.pathsep + os.path.dirname(real)},
        capture_output=True, text=True, timeout=15)
    assert child.returncode == 0 and not marker.exists(), child.stderr


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("layer,strict", [("source", False), ("scope", False), ("call", False),
                                        ("source", True), ("ambient", False), ("ambient", True), ("reuse", False), ("reuse", True)])
def test_effect_base_invariants_override_every_environment_layer(repo, tmp_path, effect_lock, layer, strict):
    import json
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = r'''
import json, os, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitsafe_run, gitops_fds
repo, scratch, lock, layer, strict, real_path = sys.argv[2:]
bad = {'LC_ALL':'fr_FR.UTF-8', 'GIT_NO_REPLACE_OBJECTS':'0', 'GIT_OPTIONAL_LOCKS':'1', 'GIT_NO_LAZY_FETCH':'0', 'GIT_TERMINAL_PROMPT':'1'}
seen, actual = [], []
def launch(argv, **options):
    actual.append(options['env'])
    seen.append({k:options['env'].get(k) for k in gitsafe_run.BASE_ENV})
    return subprocess.Popen(argv, **options)
gitsafe_run.subprocess = SimpleNamespace(**{**vars(subprocess), 'Popen':launch})
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    source = None if layer == 'ambient' else {'PATH':real_path, 'GIT_ALLOW_PROTOCOL':'file', **(bad if layer == 'source' else {})}
    with gitsafe.custody(scratch=Path(scratch), strict_lane=strict == 'True', worktree_root=repo, env=bad if layer == 'scope' else None):
        result = gitsafe.run(['version'], repo, _environ=source, _env=bad if layer == 'call' else None,
                             worktree_root=repo, effect_fds=fds)
        if layer == 'reuse':
            previous = actual[-1]
            previous.update(bad)
            result = gitsafe.run(['version'], repo, _environ=previous, worktree_root=repo, effect_fds=fds)
    assert result.returncode == 0
print(json.dumps(seen))
'''
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(scratch), str(tmp_path / "lock"),
        layer, str(strict), os.path.dirname(gitsafe.git_executable())],
        env={**os.environ, "LC_ALL": "fr_FR.UTF-8"}, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr
    values = json.loads(child.stdout)
    assert values
    fixed = {k: v for k, v in gitsafe_run.BASE_ENV.items() if k != "GIT_ALLOW_PROTOCOL"}
    assert all(all(env.get(k) == v for k, v in fixed.items()) for env in values)
    assert all(env["GIT_ALLOW_PROTOCOL"] == ("" if layer == "ambient" else "file") for env in values)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("stage", ["preissued", "fresh", "reuse", "capture", "run", "publish", "cas", "ssh"])
@pytest.mark.parametrize("form", ["directory-alias", "worktree-file", "write-root-file", "intermediate-file", "intermediate-directory", "intermediate-write-root"])
def test_program_targets_are_fenced_at_every_git_entry(repo, tmp_path, effect_lock, stage, form):
    """A PATH directory outside custody cannot launder a model-owned executable."""
    from conftest import symlink_or_skip
    source, scratch, write_root = repo / "src", tmp_path / "scratch", tmp_path / "write-root"
    source.mkdir()
    scratch.mkdir()
    write_root.mkdir()
    target_root = write_root if form in ("write-root-file", "intermediate-write-root") else repo
    programs = target_root / "programs"
    programs.mkdir()
    external = tmp_path / "external-bin"
    marker = tmp_path / "untrusted-program-ran"
    name = "ssh" if stage == "ssh" else "git"
    real = gitsafe.git_executable()
    target = programs / name
    target.write_text("#!" + sys.executable + "\nimport os, sys\nfrom pathlib import Path\n"
        + "Path(" + repr(str(marker)) + ").touch()\n"
        + ("raise SystemExit(1)\n" if stage == "ssh" else
           "os.execv(" + repr(real) + ", [" + repr(real) + ", *sys.argv[1:]])\n"), encoding="utf-8")
    target.chmod(0o700)
    if form.startswith("intermediate-"):
        trusted = tmp_path / "trusted-programs"
        programs.rename(trusted)
        symlink_or_skip(trusted, programs, target_is_directory=True)
        if form == "intermediate-directory":
            symlink_or_skip(programs, external, target_is_directory=True)
        else:
            external.mkdir()
            symlink_or_skip(programs / name, external / name)
    elif form == "directory-alias":
        symlink_or_skip(programs, external, target_is_directory=True)
    else:
        external.mkdir()
        symlink_or_skip(target, external / name)
    if stage == "ssh":
        _git(repo, "config", "core.sshCommand", "ssh")
    code = r'''
import hashlib, os, struct, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitsafe_run, gitops_fds
repo, source, scratch, write_root, external, lock, stage, real = sys.argv[2:]
clean = {'PATH':os.path.dirname(real)}
untrusted = {'PATH':external + os.pathsep + os.path.dirname(real)}
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    try:
        if stage in ('preissued', 'fresh', 'run', 'publish', 'cas'):
            lane = gitsafe.lane_runner(source, scratch, environ=untrusted, worktree_root=repo,
                write_roots=(write_root,), effect_fds=fds if stage == 'fresh' else None)
            if stage in ('preissued', 'fresh', 'run'): lane.run(['version'], effect_fds=fds)
            elif stage == 'publish':
                pack = b'PACK' + struct.pack('!II', 2, 0)
                lane.publish(pack + hashlib.sha1(pack).digest(), effect_fds=fds)
            else:
                oid = gitsafe.run(['rev-parse', 'HEAD'], repo, _environ=clean).stdout.decode().strip()
                lane.cas('refs/heads/lane/fenced', oid, None, effect_fds=fds)
        elif stage == 'reuse':
            previous = gitops_fds.effect_environment(clean, source, error=gitsafe.GitError,
                worktree_root=repo, roots=(write_root,), base=gitsafe_run.BASE_ENV, transport=gitsafe_run.transport_services())
            previous['PATH'] = untrusted['PATH']
            gitsafe.run(['version'], source, _environ=previous, effect_fds=fds,
                worktree_root=repo, write_roots=(write_root,))
        elif stage == 'capture':
            with gitsafe.custody(scratch=Path(scratch)):
                gitsafe_run.capture([str(Path(external) / 'git'), 'version'], cwd=source,
                    env=untrusted, stdin=None, timeout=5, error=gitsafe.GitError,
                    effect_fds=fds, worktree_root=repo, write_roots=(write_root,))
        else:
            gitsafe.run(['fetch', 'ssh://fixture.invalid/repository', 'HEAD'], source,
                _environ=untrusted, effect_fds=fds, worktree_root=repo, write_roots=(write_root,),
                _hardening=tuple(x for pair in zip(gitsafe_run.DEFAULT_HARDENING[::2], gitsafe_run.DEFAULT_HARDENING[1::2])
                    if pair[1] not in ('core.sshCommand=false', 'credential.helper=') for x in pair),
                _env={'GIT_ALLOW_PROTOCOL':'ssh'}, timeout=5)
    except gitsafe.GitError as exc:
        assert exc.code in ('effect_command_refused', 'git_custody_refused', 'effect_environment_unavailable'), exc.code
        assert exc.next_action and not getattr(exc, 'effect_process_started', False)
        if stage == 'ssh': assert exc.process_started is True
'''
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(source), str(scratch),
        str(write_root), str(external), str(tmp_path / "lock"), stage, real],
        env=os.environ.copy(), capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert not marker.exists(), "a fenced executable target was run at " + stage


@pytest.mark.usefixtures("strict_program")
def test_effect_strict_validation_refuses_reconstructed_invariant_override(repo, tmp_path, effect_lock):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = r'''
import subprocess, sys
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitsafe_run, gitops_fds
repo, scratch, lock, real_path = sys.argv[2:]
commands = []
def launch(argv, **options):
    commands.append(argv)
    return subprocess.Popen(argv, **options)
gitsafe_run.subprocess = SimpleNamespace(**{**vars(subprocess), 'Popen':launch})
ordinary = gitsafe.lane_runner(repo, scratch, worktree_root=repo, environ={'PATH':real_path})
assert ordinary.run(['version']).returncode == 0
argv = commands[-1]
with open(lock, 'w+b') as held:
    fds = gitops_fds.receipt_fds(held.fileno(), error=gitsafe.GitError)
    lane = gitsafe.lane_runner(repo, scratch, worktree_root=repo, effect_fds=fds,
        environ={'PATH':real_path,'LC_ALL':'fr_FR.UTF-8','GIT_NO_REPLACE_OBJECTS':'0'})
    env = lane.environment(args=('version',))
    env['LC_ALL'] = 'fr_FR.UTF-8'
    before = len(commands)
    try: lane.validate(argv, repo, env, None, None, effect_fds=fds)
    except gitsafe.GitError as exc: assert exc.code == 'git_custody_refused' and exc.process_started is False
    else: raise AssertionError('strict comparison accepted a reconstructed invariant override')
    assert len(commands) == before
'''
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(scratch), str(tmp_path / "lock"),
        os.path.dirname(gitsafe.git_executable())], capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr


@pytest.mark.parametrize("entry", ["ambient", "supplied", "scope", "call", "capture", "scope-capture"])
@pytest.mark.parametrize("key", ["GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"])
def test_strict_capture_own_bindings_do_not_admit_injected_locations(repo, tmp_path, entry, key):
    if entry == "capture":
        strict_program_guard()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    code = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core import gitsafe, gitsafe_run
repo, scratch, entry, key, real_path, value = sys.argv[2:]
try:
    if entry in ('ambient', 'supplied'):
        options = {'environ': {'PATH':real_path, key:value}} if entry == 'supplied' else {}
        gitsafe.lane_runner(repo, scratch, **options)
    else:
        with gitsafe.custody(scratch=Path(scratch), strict_lane=True, env={key:value} if entry in ('scope', 'scope-capture') else None):
            if entry in ('capture', 'scope-capture'):
                lane = gitsafe.lane_runner(repo, scratch)
                envelope = lane.environment(args=('version',))
                if entry == 'capture': envelope[key] = value
                argv = [gitsafe.custody_program(repo), *gitsafe_run.DEFAULT_HARDENING, *gitsafe_run._LANE_OPTIONS, 'version']
                gitsafe_run.capture(argv, cwd=repo, env=envelope, stdin=None, timeout=10)
            else:
                gitsafe.run(['version'], repo, _env={key:value} if entry == 'call' else None)
except gitsafe.GitError as exc:
    expected = 'ambient_git_environment' if entry in ('ambient', 'supplied') else 'git_custody_refused'
    assert exc.code == expected, (exc.code, expected)
    assert exc.next_action and value not in str(exc) + exc.next_action
else:
    raise AssertionError('untrusted location was accepted as a runner-owned binding')
'''
    value = "UNTRUSTED_LOCATION_" + key
    env = {**os.environ, **({key: value} if entry == "ambient" else {})}
    child = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT), str(repo), str(scratch), entry, key,
        os.path.dirname(gitsafe.git_executable()), value], env=env, capture_output=True, text=True, timeout=15)
    assert child.returncode == 0, child.stderr


@pytest.mark.parametrize("stage", ["preissued", "fresh", "reuse", "capture", "run", "publish", "cas", "ssh"])
@pytest.mark.parametrize("layer", ["source", "ambient", "scope", "reuse", "replace"])
@pytest.mark.parametrize("key", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_NOSYSTEM", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "BASH_ENV", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "OPENSSL_CONF"])
def test_selector_inputs_refuse_before_git_spawn(repo, tmp_path, effect_lock, monkeypatch, stage, layer, key):
    from types import SimpleNamespace
    import contextlib
    import hashlib
    import struct
    scratch = tmp_path / "lane"
    scratch.mkdir()
    (scratch / "objects").mkdir()
    source = {"PATH": os.path.dirname(gitsafe.git_executable()), "REQUEST_MARKER": "retained"}
    observed = []
    def launch(argv, **options):
        observed.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    bad = {key: "UNTRUSTED_SELECTOR_VALUE"}
    if layer in ("reuse", "replace") or stage == "reuse" or layer in ("ambient", "scope") and stage in ("run", "publish", "cas"):
        strict_program_guard()
    if layer in ("reuse", "replace") or stage == "reuse":
        assert gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo).returncode == 0
        source = observed[-1]
    if layer == "source":
        source = {**source, **bad}
    elif layer == "reuse":
        source.update(bad)
    lane = None
    if layer in ("ambient", "scope") and stage in ("run", "publish", "cas"):
        lane = gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo)
    if layer == "ambient":
        monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": {**os.environ, **bad}}))
        source = None
    observed.clear()
    context = gitsafe.custody(scratch=scratch, env=bad, worktree_root=repo) if layer == "scope" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        if layer == "replace": source = source.with_vars({**source, **bad}, replace=True)
        if lane is not None and layer == "ambient":
            # A transferred capability keeps its supplied request environment;
            # ambient refusal is checked at a fresh facade entry instead.
            gitsafe.lane_runner(repo, scratch, worktree_root=repo, effect_fds=(effect_lock,))
        elif stage in ("preissued", "fresh", "run", "publish", "cas"):
            lane = lane or gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo,
                effect_fds=(effect_lock,) if stage == "fresh" else None)
            if stage == "publish":
                pack = b"PACK" + struct.pack("!II", 2, 0)
                lane.publish(pack + hashlib.sha1(pack).digest(), effect_fds=(effect_lock,))
            elif stage == "cas":
                lane.cas("refs/heads/lane/refused", "a" * 40, None, effect_fds=(effect_lock,))
            else:
                lane.run(["version"], effect_fds=(effect_lock,))
        elif stage == "capture":
            with gitsafe.custody(scratch=scratch, env=bad if layer == "scope" else None, worktree_root=repo):
                gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env=source,
                    stdin=None, timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            gitsafe.run(["fetch", "ssh://fixture.invalid/repository", "HEAD"] if stage == "ssh" else ["version"],
                repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code in ("ambient_git_environment", "git_custody_refused")
    assert caught.value.next_action and not getattr(caught.value, "effect_process_started", False)
    assert "UNTRUSTED_SELECTOR_VALUE" not in str(caught.value) + caught.value.next_action
    assert observed == []


@pytest.mark.parametrize("stage", ["run", "custody", "strict", "lane", "reuse"])
@pytest.mark.parametrize("key", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_NOSYSTEM", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "BASH_ENV", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "OPENSSL_CONF"])
def test_per_call_selectors_refuse_before_effect_spawn(repo, tmp_path, effect_lock, monkeypatch, stage, key):
    if stage in ("lane", "reuse"):
        strict_program_guard()
    from types import SimpleNamespace
    import contextlib
    source = {"PATH": os.path.dirname(gitsafe.git_executable())}
    seen = []
    def launch(argv, **options):
        seen.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    if stage == "reuse":
        gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        source = seen[-1]
    lane = gitsafe.lane_runner(repo, tmp_path, environ=source, worktree_root=repo) if stage == "lane" else None
    seen.clear()
    context = gitsafe.custody(scratch=tmp_path, strict_lane=stage == "strict", worktree_root=repo) if stage in ("custody", "strict") else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        if lane:
            lane.run(["version"], _env={key: "UNTRUSTED_CALL"}, effect_fds=(effect_lock,))
        else:
            gitsafe.run(["version"], repo, _environ=source, _env={key: "UNTRUSTED_CALL"},
                        effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_custody_refused" and not seen
    assert caught.value.next_action and "UNTRUSTED_CALL" not in str(caught.value) + caught.value.next_action


@pytest.mark.usefixtures("strict_program")
def test_reused_preissued_environment_binds_repository_before_lookup(repo, tmp_path, effect_lock, monkeypatch):
    from types import SimpleNamespace
    other = _repo(tmp_path / "other")
    scratch = tmp_path / "lane"
    scratch.mkdir()
    source = gitsafe.lane_runner(repo, scratch, worktree_root=repo).environment(args=("version",))
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail("mismatched issued bindings reached lookup or spawn")
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=forbidden))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], other, _environ=source, effect_fds=(effect_lock,), worktree_root=other)
    assert caught.value.code == "git_custody_refused" and not calls


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("preissued", [False, True])
@pytest.mark.parametrize("binding", ["real-index", "shared", "identity"])
def test_effect_capture_preserves_issued_bindings(repo, tmp_path, effect_lock, binding, preissued):
    import hashlib
    import struct
    scratch = tmp_path / "lane"
    scratch.mkdir()
    (scratch / "objects").mkdir()
    lane = gitsafe.lane_runner(repo, scratch, worktree_root=repo, effect_fds=None if preissued else (effect_lock,))
    identity = {"GIT_" + role + "_" + field: value for role in ("AUTHOR", "COMMITTER")
        for field, value in (("NAME", "Capture Owner"), ("EMAIL", "capture@example.invalid"), ("DATE", "1700000000 +0000"))}
    args = {"real-index": ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
            "shared": ("unpack-objects", "-q", "--strict"),
            "identity": ("commit-tree", _git(repo, "rev-parse", "HEAD^{tree}").strip(), "-p", _git(repo, "rev-parse", "HEAD").strip())}[binding]
    envelope = lane.environment(identity if binding == "identity" else None, args=args,
                                real_index=binding == "real-index", shared=binding == "shared")
    argv = (gitsafe.custody_program(repo, environ=envelope), *gitsafe_run.DEFAULT_HARDENING, *gitsafe_run._LANE_OPTIONS, *args)
    data = b"capture identity\n" if binding == "identity" else None
    shared_oid = None
    if binding == "shared":
        donor = _repo(tmp_path / "donor")
        shared_oid = subprocess.run([gitsafe.git_executable(), "hash-object", "-w", "--stdin"], cwd=donor,
            input=b"shared capture sentinel\n", check=True, capture_output=True).stdout.strip()
        data = subprocess.run([gitsafe.git_executable(), "pack-objects", "--stdout"], cwd=donor,
            input=shared_oid + b"\n", check=True, capture_output=True).stdout
    with gitsafe.custody(scratch=scratch, strict_lane=True, worktree_root=repo):
        result = gitsafe_run.capture(argv, cwd=repo, env=envelope, stdin=data, timeout=10,
            error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo,
            _grant=(argv, str(repo), data) if binding == "shared" else None)
    assert result.returncode == 0
    if binding == "real-index":
        assert result.stdout == subprocess.run([gitsafe.git_executable(), *args], cwd=repo, check=True, capture_output=True).stdout
    elif binding == "identity":
        commit = lane.run(["cat-file", "commit", result.stdout.decode().strip()]).stdout.decode()
        assert "author Capture Owner <capture@example.invalid> 1700000000 +0000" in commit
        assert "committer Capture Owner <capture@example.invalid> 1700000000 +0000" in commit
    if binding == "shared":
        assert envelope["GIT_OBJECT_DIRECTORY"] == str(repo / ".git" / "objects")
        assert gitsafe.run(["cat-file", "blob", shared_oid.decode()], repo).stdout == b"shared capture sentinel\n"
        assert not (scratch / "objects" / shared_oid[:2].decode() / shared_oid[2:].decode()).exists()
    elif binding == "real-index":
        assert envelope["GIT_INDEX_FILE"] == str(repo / ".git" / "index")
    else:
        assert all(envelope[k] == v for k, v in identity.items())


@pytest.mark.parametrize("operation", ["hook", "trailers", "export", "sync"])
def test_ordinary_trusted_caller_environment_goldens(repo, tmp_path, fake_home, monkeypatch, operation):
    from types import SimpleNamespace
    target = repo
    sync_repo = None
    if operation == "sync":
        from tests import helpers_syncpr as hs
        parent = tmp_path / "sync"
        parent.mkdir()
        sync_repo = hs.make(parent)
        target = sync_repo.root
    if operation == "hook":
        index = tmp_path / "hook-index"
        shutil.copy2(repo / ".git" / "index", index)
    snapshot = {**os.environ, "ORDINARY_PROFILE_SENTINEL": "unchanged"}
    if operation == "hook":
        snapshot["GIT_INDEX_FILE"] = str(index)
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": snapshot}))
    lookups, real_which = [], gitsafe.pathlookup.which
    def lookup(name, **options):
        lookups.append((name, options))
        return real_which(name, **options)
    gitsafe._reset_for_tests()
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=lookup))
    observed = []
    def launch(argv, **options):
        observed.append((argv, options.copy()))
        return subprocess.run(argv, **options)
    monkeypatch.setattr(gitsafe, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": launch}))
    if operation == "hook":
        assert gitsafe.changed_files(repo, "staged") == []
    elif operation == "trailers":
        message = tmp_path / "message"
        message.write_text("subject\n", encoding="utf-8")
        assert gitsafe.add_trailer(message, "Signed-off-by: Owner <owner@example.invalid>")
    elif operation == "export":
        gitsafe.export_tree(repo, "HEAD", tmp_path / "export")
        assert (tmp_path / "export" / "a.py").read_bytes() == b"a = 1\n"
    else:
        from aegis_core import sync
        result = sync.sync(target, pr=True, gh_runner=hs.FakeGh(sync_repo.origin))
        assert result.pr["status"] == "opened"
    selected = []
    for argv, options in observed:
        actual = options["env"]
        expected = {**snapshot, **gitsafe_run.BASE_ENV}
        if operation == "trailers":
            expected.update(GIT_DIR=options["cwd"], GIT_COMMON_DIR=options["cwd"])
            selected.append(options)
        elif operation in ("export", "sync") and "GIT_INDEX_FILE" in actual:
            expected["GIT_INDEX_FILE"] = actual["GIT_INDEX_FILE"]
            assert not Path(actual["GIT_INDEX_FILE"]).is_relative_to(target)
            selected.append(options)
        elif operation == "hook":
            selected.append(options)
        if operation == "sync" and "push" in argv:
            expected["GIT_ALLOW_PROTOCOL"] = "https:ssh:file"
        # Keep actual environment values out of pytest's assertion diagnostics.
        identical = actual == expected
        assert identical, "ordinary caller environment bytes changed"
    assert selected and lookups and all(name == "git" and options == {} for name, options in lookups)


def test_strict_resolver_binds_windows_extensions_to_effective_environment(tmp_path, monkeypatch):
    from types import SimpleNamespace
    model = tmp_path / "model"
    model.mkdir()
    source = gitsafe_run.request_environment({"PATH": str(tmp_path), "PATHEXT": ".EXE"},
        profile="strict/effect", root=model)
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "name": "nt", "pathsep": ";"}))
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.find_executable({}, source, lambda env: str(tmp_path / "git.PY"), error=gitsafe.GitError)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("change", ["delete", "replace"])
def test_reused_environment_removes_deleted_input_fields(repo, effect_lock, monkeypatch, change):
    from types import SimpleNamespace
    observed = []
    def launch(argv, **options):
        observed.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    source = {"PATH": os.path.dirname(gitsafe.git_executable()), "REQUEST_MARKER": "remove-me", "GIT_ALLOW_PROTOCOL": "file"}
    assert gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo).returncode == 0
    source = observed[-1]
    if change == "delete":
        del source["REQUEST_MARKER"]
        del source["GIT_ALLOW_PROTOCOL"]
    else:
        source = source.with_vars({"PATH": source["PATH"]}, replace=True)
    assert gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo).returncode == 0
    assert "REQUEST_MARKER" not in observed[-1] and observed[-1]["GIT_ALLOW_PROTOCOL"] == ""


@pytest.mark.usefixtures("strict_program")
def test_effect_environment_repository_provenance_is_immutable(repo, effect_lock, monkeypatch):
    from types import SimpleNamespace, MappingProxyType
    observed = []
    def launch(argv, **options):
        observed.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    gitsafe.run(["version"], repo, _environ={"PATH": os.path.dirname(gitsafe.git_executable())},
                effect_fds=(effect_lock,), worktree_root=repo)
    assert isinstance(observed[-1].repository, MappingProxyType)
    with pytest.raises(TypeError):
        observed[-1].repository["dirs"] = ()
    with pytest.raises(AttributeError):
        observed[-1]._proof = {}


def test_effect_refuses_native_loader_code_before_the_holder_starts(repo, tmp_path, effect_lock):
    import json
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("native loader regression needs an installed C compiler")
    marker = tmp_path / "loader-ran"
    code, library = repo / "loader.c", repo / "loader.so"
    code.write_text('#include <stdio.h>\n__attribute__((constructor)) static void marker(void) {FILE *f=fopen('
        + json.dumps(str(marker)) + ',"w");if(f){fputs("ran",f);fclose(f);}}\n', encoding="utf-8")
    subprocess.run([compiler, "-shared", "-fPIC", str(code), "-o", str(library)], check=True, capture_output=True, timeout=20)
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["version"], repo, _environ={"PATH": os.path.dirname(gitsafe.git_executable()), "LD_PRELOAD": str(library)},
                    effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "ambient_git_environment" and caught.value.process_started is False
    assert not marker.exists(), "model-owned native code ran before the subreaper could take custody"


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="descriptor-bound executable resolution requires Linux procfs")
@pytest.mark.parametrize("entry", ["lookup", "fresh", "capture", "retarget"])
def test_strict_without_receipt_fences_the_recorded_root(repo, tmp_path, entry):
    from conftest import symlink_or_skip
    source, scratch, external = repo / "sub", tmp_path / "scratch", tmp_path / "external"
    source.mkdir()
    scratch.mkdir()
    external.mkdir()
    evil, marker = repo / "evil-git", tmp_path / "executed"
    evil.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    evil.chmod(0o700)
    real = gitsafe.git_executable()
    symlink_or_skip(real if entry == "retarget" else evil, external / "git")
    env = {"PATH": str(external)}
    lane = gitsafe.lane_runner(source, scratch, environ=env, worktree_root=repo) if entry == "retarget" else None
    if lane:
        (external / "git").unlink()
        symlink_or_skip(evil, external / "git")
    with pytest.raises(gitsafe.GitError) as caught:
        if entry == "lookup":
            gitsafe.custody_program(repo, environ=env)
        elif entry == "fresh":
            gitsafe.lane_runner(source, scratch, environ=env, worktree_root=repo)
        elif entry == "retarget":
            lane.run(["version"])
        else:
            with gitsafe.custody(scratch=scratch, strict_lane=True, worktree_root=repo):
                gitsafe_run.capture([str(external / "git"), *gitsafe_run.DEFAULT_HARDENING,
                    *gitsafe_run._LANE_OPTIONS, "version"], cwd=source, env=env, stdin=None, timeout=5)
    assert caught.value.code == "effect_command_refused"
    assert caught.value.process_started is False
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="descriptor-bound executable resolution requires Linux procfs")
@pytest.mark.parametrize("entry", ["lane", "capture"])
@pytest.mark.parametrize("key", ["GIT_DIR", "GIT_PAGER"])
def test_explicit_strict_environment_never_inspects_ambient(repo, tmp_path, monkeypatch, entry, key):
    from types import SimpleNamespace
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = {"PATH": os.path.dirname(gitsafe.git_executable())}
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": {key: "untrusted"}}))
    if entry == "lane":
        lane = gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo)
        result = lane.run(["version"])
    else:
        with gitsafe.custody(scratch=scratch, strict_lane=True, worktree_root=repo):
            result = gitsafe_run.capture([gitsafe.git_executable(), *gitsafe_run.DEFAULT_HARDENING,
                *gitsafe_run._LANE_OPTIONS, "version"], cwd=repo, env=source, stdin=None, timeout=5)
    assert result.returncode == 0 and result.stdout.startswith(b"git version ")


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("key", ["GIT_ASKPASS", "GIT_DIR", "GIT_CONFIG_NOSYSTEM"])
def test_envelope_edits_refuse_even_matching_transport_values(repo, effect_lock, key, replace):
    envelope = gitops_fds.effect_environment({"PATH": os.path.dirname(gitsafe.git_executable())}, repo,
        worktree_root=repo, error=gitsafe.GitError, transport=gitsafe_run.transport_services())
    with pytest.raises(gitsafe.GitError) as caught:
        envelope.with_vars({key: envelope[key]}, replace=replace)
    assert caught.value.code == "git_custody_refused" and caught.value.process_started is False


@pytest.mark.parametrize("source_kind,target_kind", [(a, b) for a in ("git", "lane", "gh") for b in ("git", "lane", "gh") if a != b])
def test_envelope_kind_cannot_cross_a_public_boundary(repo, tmp_path, effect_lock, source_kind, target_kind):
    from aegis_core import ghcli
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = gitsafe_run.request_environment({"PATH": os.path.dirname(gitsafe.git_executable()),
        "GH_TOKEN": "fixture-token"}, profile="strict/effect", root=repo, kind=source_kind)
    with pytest.raises(gitsafe.GitError) as caught:
        if target_kind == "git":
            gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        elif target_kind == "lane":
            gitsafe.lane_runner(repo, scratch, environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        else:
            ghcli._EFFECT_RUNNER(["api", "user"], cwd=repo, env=source, effect_fds=(effect_lock,), worktree_root=repo)
    assert caught.value.code == "git_custody_refused" and caught.value.process_started is False


@pytest.mark.parametrize("source", [None, {}, {"PATH": "/owner/bin"}])
def test_ordinary_git_lookup_retains_plain_environment_fence(tmp_path, monkeypatch, source):
    from types import SimpleNamespace
    seen = []
    def which(name, **options):
        seen.append((name, options))
        return sys.executable
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=which))
    gitsafe._reset_for_tests()
    try:
        assert gitsafe.git_executable(environ=source, cwd=tmp_path) == sys.executable
        assert seen == [("git", {} if source is None else {"path": source.get("PATH", os.defpath), "outside": tmp_path})]
    finally:
        gitsafe._reset_for_tests()


@pytest.mark.usefixtures("strict_program")
@posix_only
@pytest.mark.parametrize("effect", [False, True])
@pytest.mark.parametrize("interpreter", [False, True])
def test_executable_is_pinned_before_the_spawn_boundary(repo, tmp_path, effect_lock, monkeypatch, effect, interpreter):
    from conftest import symlink_or_skip
    from threading import Event, Thread
    from types import SimpleNamespace
    trusted, external, scratch = tmp_path / "trusted", tmp_path / "external", tmp_path / "scratch"
    for directory in (trusted, external, scratch): directory.mkdir()
    real = gitsafe.git_executable()
    symlink_or_skip(real, trusted / "git")
    symlink_or_skip(sys.executable, trusted / "python")
    relay = tmp_path / "relay"
    symlink_or_skip(trusted, relay, target_is_directory=True)
    symlink_or_skip(relay / "git", external / "git")
    symlink_or_skip(relay / "python", external / "python")
    marker, evil = tmp_path / "evil-ran", repo / "evil"
    evil.mkdir()
    (evil / "git").write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    (evil / "git").chmod(0o700)
    (evil / "python").write_bytes((evil / "git").read_bytes())
    (evil / "python").chmod(0o700)
    lane = gitsafe.lane_runner(repo, scratch, environ={"PATH": str(external)}, worktree_root=repo)
    if interpreter: monkeypatch.setattr(gitops_fds, "sys", SimpleNamespace(**{**vars(sys), "executable": str(external / "python")}))
    ready, swapped = Event(), Event()
    def swap():
        if ready.wait(10):
            relay.unlink()
            relay.symlink_to(evil, target_is_directory=True)
            swapped.set()
    worker = Thread(target=swap)
    worker.start()
    def launch(argv, **options):
        ready.set()
        assert swapped.wait(10), "link swap did not complete at the spawn boundary"
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    try:
        result = lane.run(["version"], effect_fds=(effect_lock,) if effect else None)
        assert result.returncode == 0 and result.stdout.startswith(b"git version ")
    finally:
        ready.set()
        worker.join(10)
    assert not worker.is_alive() and not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("entry", ["raw", "capture", "fresh", "run", "publish", "cas"])
def test_holder_interpreter_is_fenced_at_every_git_entry(repo, tmp_path, effect_lock, monkeypatch, entry):
    from types import SimpleNamespace
    import hashlib
    import struct
    interpreter, marker = repo / "python", tmp_path / "holder-code-ran"
    interpreter.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
    interpreter.chmod(0o700)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = {"PATH": os.path.dirname(gitsafe.git_executable())}
    lane = gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo) if entry in ("run", "publish", "cas") else None
    monkeypatch.setattr(gitops_fds, "sys", SimpleNamespace(**{**vars(sys), "executable": str(interpreter)}))
    with pytest.raises(gitsafe.GitError) as caught:
        if entry == "raw":
            gitsafe.run(["version"], repo, _environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        elif entry == "capture":
            with gitsafe.custody(scratch=scratch):
                gitsafe_run.capture([gitsafe.git_executable(), "version"], cwd=repo, env=source, stdin=None,
                    timeout=5, error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
        elif entry == "fresh":
            gitsafe.lane_runner(repo, scratch, environ=source, effect_fds=(effect_lock,), worktree_root=repo)
        elif entry == "run":
            lane.run(["version"], effect_fds=(effect_lock,))
        elif entry == "publish":
            pack = b"PACK" + struct.pack("!II", 2, 0)
            lane.publish(pack + hashlib.sha1(pack).digest(), effect_fds=(effect_lock,))
        else:
            lane.cas("refs/heads/lane/holder", _git(repo, "rev-parse", "HEAD").strip(), None, effect_fds=(effect_lock,))
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
def test_config_read_never_rewrites_a_policy_shaped_ssh_command(repo, tmp_path, effect_lock):
    import shlex
    ssh = tmp_path / "ssh"
    ssh.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    ssh.chmod(0o700)
    command = shlex.join([str(ssh), "-o", "IgnoreUnknown=ForkAfterAuthentication", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "BatchMode=yes"])
    result = gitsafe.run(["config", "--get", "core.sshCommand"], repo,
        _hardening=_network_hardening("-c", "core.sshCommand=" + command),
        _environ={"PATH": os.path.dirname(gitsafe.git_executable())}, effect_fds=(effect_lock,), worktree_root=repo)
    assert result.returncode == 0 and result.stdout == (command + "\n").encode()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("program", ["git", "gh", "ssh"])
@pytest.mark.parametrize("dispatch", ["absolute", "path"])
@pytest.mark.parametrize("lookup", ["absolute", "path"])
def test_strict_resolver_refuses_script_dispatch_before_spawn(repo, tmp_path, monkeypatch, program, dispatch, lookup):
    from types import SimpleNamespace
    host = tmp_path / "host"
    host.mkdir()
    interpreter, marker = repo / "python", tmp_path / "interpreter-ran"
    interpreter.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    interpreter.chmod(0o700)
    script = host / program
    script.write_text(("#!" + str(interpreter) if dispatch == "absolute" else "#!/usr/bin/env python") + "\nunused\n", encoding="utf-8")
    script.chmod(0o700)
    source = gitsafe_run.request_environment({"PATH": str(host)}, profile="strict/effect", root=repo)
    def forbidden(*args, **kwargs):
        pytest.fail("script refusal started a child")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe_run.find_executable({}, source, lambda effective: str(script) if lookup == "absolute" else
            gitsafe.pathlookup.which(program, path=effective["PATH"], outside=repo), error=gitsafe.GitError)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
    assert str(caught.value).startswith("strict effects require a native executable: ")
    assert str(caught.value).endswith(" is a script; configure the real binary")
    assert caught.value.next_action and not marker.exists()


@posix_only
@pytest.mark.parametrize("form", ["dirname", "basename"])
def test_ordinary_git_shims_preserve_script_identity(repo, tmp_path, monkeypatch, form):
    from types import SimpleNamespace
    import shlex
    host = tmp_path / "shim-bin"
    host.mkdir()
    real = gitsafe.git_executable()
    shutil.copy2(real, host / "git.real")
    body = 'exec "$(dirname "$0")/git.real" "$@"' if form == "dirname" else \
        'case "${0##*/}" in git) exec ' + shlex.quote(real) + ' "$@";; *) exit 9;; esac'
    script = host / "git"
    script.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    script.chmod(0o700)
    path = str(host) + os.pathsep + os.defpath
    which = gitsafe.pathlookup.which
    monkeypatch.setattr(gitsafe, "pathlookup", SimpleNamespace(which=lambda name, **options: which(name, path=path)))
    gitsafe._reset_for_tests()
    try:
        result = gitsafe.run(["version"], repo, _environ={"PATH": path})
        assert result.returncode == 0 and result.stdout.startswith(b"git version ")
    finally:
        gitsafe._reset_for_tests()


# Exact AST proofs are reserved for refusals before lookup or mixed variants.
# A changed body invalidates its proof; new construction sites need a guard.
_STRICT_SITE_PROOFS = {
    ('test_gitsafe', 'test_effect_descriptor_refused_before_any_spawn'): ('f440d542ccf05a986720fb51cdadb1b5a38a54c0c776d783a4c8c4f2fa72e07b', 'Invalid receipt descriptors refuse in pass_through before executable lookup.'),
    ('test_gitsafe', 'test_effect_unsupported_platform_is_a_pre_spawn_refusal'): ('4480e3b2ef2f7c06b1c60a74288dd00df9da0584dae64c5a8a765ec7437174ba', 'The effect-platform probe is forced false; pass_through refuses before lookup.'),
    ('test_gitsafe', 'test_effect_write_roots_refuse_before_expansion'): ('f8042b05a19e1caa57c0370d7e57ff2c964a11d522499873180c6f8ad4bada44', 'Invalid or oversized root containers refuse before executable lookup.'),
    ('test_gitsafe', 'test_envelope_kind_cannot_cross_a_public_boundary'): ('dfba2f124365cffe5c6e988b6f86c1109e5f6d2c68c4f33778ef606bbb5d5373', 'Every source kind differs from the target boundary; constructor validation refuses before lookup.'),
    ('test_gitsafe', 'test_strict_executable_platform_probe_has_its_own_refusal'): ('c26c24a220cd30cb3b4c46b1965c9727842f2183fa2d6d84107dc9161da964cb', 'The program capability probe is forced false and its documented refusal is asserted.'),
    ('test_gitsafe', 'test_strict_capture_own_bindings_do_not_admit_injected_locations'): ('ee30e9f8dd120b16ead59aa4265186837103d5bd6999614ce06ce23aa1e56055', 'Only capture issues a clean lane; it calls the shared guard. All other entries inject a forbidden selector before issuance.'),
    ('test_gitsafe', 'test_selector_inputs_refuse_before_git_spawn'): ('68d522bde57ca81d421d5ad7c285e262b99f9c702564f2767cde4ccc5a8a9efb', 'Clean baseline and preissued variants call the shared guard; other variants supply forbidden selectors before lookup.'),
    ('test_gitsafe', 'test_per_call_selectors_refuse_before_effect_spawn'): ('6f690fcf186fa9527f647be96f092e7cf810ccadbd89599ba90643b2ae2d8269', 'Lane and reused-source variants guard clean setup; raw, custody and strict calls reject the per-call selector before lookup.'),
    ('test_team_git', 'test_ambient_environment_disappearing_during_snapshot_has_a_public_refusal'): ('86ad10f3db2ffc01d61d426217487c870ee1a36b4af7096b2e5229387b02b050', 'Input snapshot raises before lookup; successful recovery uses the shared optional guard.'),
    ('test_team_git', 'test_ambient_key_diagnostics_canonicalize_and_redact_before_display'): ('2f58eb082d785f6760aa0d95374aca2202893d87af598e9d9f1cad8d570068f3', 'Forbidden ambient Git selector refuses before lookup.'),
    ('test_team_git', 'test_ambient_lowercase_key_refuses_with_its_real_spelling'): ('6459fb273f706030d8118adecb9f59c3ed4eefa1c7aac758c1e61c93a055a008', 'Forbidden lowercase selector refuses before lookup; helper guard is deliberately bypassed.'),
    ('test_team_git', 'test_ambient_refusal_is_deterministic_and_lists_every_exact_key'): ('54e6f3cb00831ad675cc9fd504e4e5854da4e7494fe09b04219a72f5fcea0c1b', 'Every subprocess environment contains forbidden Git location/trace selectors before lookup.'),
    ('test_team_git', 'test_invalid_root_identity_precedes_git_or_metadata'): ('ac07c7dea4d2f129ea16e005df4c23822b062ca67033e6c0b90f888b9218d503', 'Every supplied root is relative, traversal-bearing or contains NUL; root validation precedes Git.'),
    ('test_team_git', 'test_missing_fenced_git_refuses_before_discovery_and_retries'): ('131c624a9f1423f49752169fd0d0e9deaee99daa81baedea04b0d496f75b872d', 'The resolver callback lacks its required environ argument and refuses before lookup; successful recovery is guarded.'),
    ('test_team_git', 'test_relative_cwd_public_routes_share_the_git_error_hierarchy'): ('7f61255ee0e682c76557f65299ce581e3a3bffe23590b0ee7d36fb0771ea781a', 'Capture guards its valid executable setup; every other route supplies a relative root and refuses before lookup.'),
    ('test_team_git', 'test_runner_ambient_redirect_before_entry_refuses_and_retries'): ('e024521e0b976e766cc6dc6e3d4ec7c79d97c2db1d48274597b4b6a2b36b8f7c', 'Forbidden environment inputs refuse before lookup; only successful recovery is guarded.'),
    ('test_team_git', 'test_store_entry_environment_bounds_have_public_refusal_and_retry'): ('0a8e1a01070e9502eea2409a90283a17323b1d05b99c30289cfbdd00c25fbc29', 'Oversized inputs refuse before lookup; only bounded successful recovery is guarded.'),
    ('test_gitsafe', 'test_effect_capture_spawn_golden_and_exactly_one_extra_fd'): ('c9d7ef0dcb84da70108ec614400efd7926769e8db71079d92d74c6a732fbbd86', 'Only the ordinary capture variant avoids strict lookup; every other variant calls the shared guard first.'),
}


def _strict_proof_digest(tree, name):
    """Bind an early-refusal proof to its body, helpers and embedded programs."""
    import hashlib
    def stable(node):
        if isinstance(node, ast.AST):
            fields = dict(ast.iter_fields(node))
            if hasattr(node, "type_params"):
                fields["type_params"] = node.type_params
            return (type(node).__name__, tuple((field, stable(value)) for field, value in sorted(fields.items())
                if not (field == "type_params" and value == [])))
        if isinstance(node, list):
            return tuple(stable(value) for value in node)
        return node
    definitions = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            definitions[node.name] = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    definitions[target.id] = node
    pending, included = [name], {}
    while pending:
        key = pending.pop()
        if key in included or key not in definitions:
            continue
        node = included[key] = definitions[key]
        pending.extend(n.id for n in ast.walk(node) if isinstance(n, ast.Name))
    return hashlib.sha256(ascii(sorted((key, stable(node)) for key, node in included.items())).encode("ascii")).hexdigest()


def _census_parse_schema(source, schema):
    """Exercise supported AST schemas without changing the shared ast module."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if schema == "py312":
                if not hasattr(node, "type_params"):
                    node.type_params = []
            elif schema == "py39" and getattr(node, "type_params", None) == []:
                del node.type_params
    return tree


def _strict_runner_census(sources, *, parse=ast.parse):
    names = {"lane_runner", "issue_runner", "LaneRunner", "custody_program", "GitStore",
             "strict_request", "new_store", "make_store", "_effect_call", "_assert_effect_survives_owner"}
    functions, trees, calls, sites, aliases = {}, {}, [], [], {}
    def owner(node, parents):
        found = None
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.FunctionDef): found = node
        return found
    def marked(fn):
        return fn is not None and (any(n.arg == "strict_program" for n in fn.args.args) or any(isinstance(n, ast.Call) and ast.unparse(n.func) == "pytest.mark.usefixtures"
            and any(isinstance(a, ast.Constant) and a.value == "strict_program" for a in n.args)
            for n in fn.decorator_list))
    def required(call):
        # native_fixture adds a compiler check; it cannot bypass program support.
        return isinstance(call, ast.Call) and ast.unparse(call.func) == "strict_program_guard" and not call.args and all(k.arg == "native_fixture" or k.arg == "optional" and isinstance(k.value, ast.Constant) and k.value.value is False for k in call.keywords)
    def call_name(module, scope, call):
        name = ast.unparse(call.func).split(".")[-1]
        for _ in range(len(aliases) + 1):
            target = aliases.get((module, scope, name), aliases.get((module, "<module>", name), name))
            if target == name: break
            name = target
        return name
    def static_data(fn):
        allowed = {"_run_subcommand_offenders", "_lane_offenders", "_lane_structure_offenders", "_strict_runner_census", "_strict_proof_digest", "_census_parse_schema", "dict", "len", "set", "any", "all"}
        return fn is not None and all(ast.unparse(n.func) in allowed or ast.unparse(n.func).startswith(("ast.", "sources.", "cases.")) or ast.unparse(n.func).endswith(".read_text") for statement in fn.body for n in ast.walk(statement) if isinstance(n, ast.Call))
    for module, source in sources.items():
        tree = trees[module] = parse(source)
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        for fn in tree.body:
            if isinstance(fn, ast.FunctionDef):
                functions[(module, fn.name)] = fn
        for node in ast.walk(tree):
            fn = owner(node, parents)
            scope = fn.name if fn else "<module>"
            if isinstance(node, ast.ImportFrom):
                aliases.update({(module, scope, a.asname): a.name for a in node.names if a.asname})
            elif isinstance(node, ast.Assign) and isinstance(node.value, (ast.Name, ast.Attribute)):
                aliases.update({(module, scope, n.id): ast.unparse(node.value).split(".")[-1] for n in node.targets if isinstance(n, ast.Name)})
        for node in ast.walk(tree):
            fn = owner(node, parents)
            if isinstance(node, ast.Call):
                calls.append((module, fn.name if fn else "<module>", node, "direct", node.lineno))
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or not any(name in node.value for name in names): continue
            try:
                embedded = parse(node.value)
            except SyntaxError:
                continue
            owners = [fn.name] if fn else []
            if fn is None:
                assignment = parents.get(node)
                while assignment in parents and not isinstance(assignment, ast.Assign): assignment = parents[assignment]
                targets = {x.id for target in assignment.targets for x in ast.walk(target) if isinstance(x, ast.Name)} if isinstance(assignment, ast.Assign) else set()
                owners = sorted({f.name for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in targets and (f := owner(n, parents)) is not None})
            for inner in ast.walk(embedded):
                if isinstance(inner, ast.Call) and call_name(module, fn.name if fn else "<module>", inner) in names:
                    for scope in owners or ["<module>"]:
                        calls.append((module, scope, inner, "static" if static_data(functions.get((module, scope))) else "embedded", node.lineno))
    # Discover construction helpers transitively; a renamed helper stays covered.
    constructing = set(names)
    for _ in range(len(functions) + 1):
        added = {scope for module, scope, node, kind, line in calls if kind != "static" and call_name(module, scope, node) in constructing}
        if added <= constructing: break
        constructing |= added
    for module, scope, node, kind, line in calls:
        if call_name(module, scope, node) in constructing:
            sites.append((module, scope, node, kind, line))
    def proof(key):
        fn = functions.get(key)
        record = _STRICT_SITE_PROOFS.get(key)
        return fn is not None and record is not None and _strict_proof_digest(trees[key[0]], key[1]) == record[0]
    def guarded(key, line, seen=()):
        fn = functions.get(key)
        if fn is None: return False
        if marked(fn) or proof(key): return True
        if any(isinstance(n, ast.Expr) and required(n.value) and n.lineno <= line for n in fn.body): return True
        if fn.name == "new_store":
            defaults = {n.arg: value for n, value in zip(fn.args.kwonlyargs, fn.args.kw_defaults)}
            return isinstance(defaults.get("require_program"), ast.Constant) and defaults["require_program"].value is True and any(isinstance(n, ast.If) and n.lineno <= line and isinstance(n.test, ast.Name) and n.test.id == "require_program" and any(isinstance(x, ast.Expr) and required(x.value) for x in n.body) for n in fn.body)
        if fn.name.startswith("test_") or key in seen: return False
        callers = [(m, s, n, k, l) for m, s, n, k, l in sites if call_name(m, s, n) == fn.name and (m, s) != key]
        return bool(callers) and all(guarded((m, s), l, (*seen, key)) for m, s, n, k, l in callers)
    rows = []
    for module, scope, node, kind, line in sites:
        safe = kind == "static" or guarded((module, scope), line)
        name = ast.unparse(node.func)
        callee = (module, call_name(module, scope, node))
        candidates = [key for key in functions if key[1] == callee[1]]
        if callee not in functions and len(candidates) == 1: callee = candidates[0]
        if callee in functions and not callee[1].startswith("test_"):
            safe |= guarded(callee, functions[callee].end_lineno)
        # Opting a helper out of its setup guard requires its own exact proof.
        if kind != "static" and callee[1] == "new_store" and any(k.arg is None or k.arg == "require_program" and not (isinstance(k.value, ast.Constant) and k.value.value is True) for k in node.keywords):
            safe = proof((module, scope)) or marked(functions.get((module, scope)))
        rows.append({"module": module, "scope": scope, "line": line, "call": name,
                     "kind": kind, "guarded": safe})
    return rows


def test_every_strict_runner_construction_has_a_shared_capability_guard():
    names = ("test_gitsafe", "test_ghcli", "test_team_git")
    sources = {name: (ROOT / "tests/unit/core" / (name + ".py")).read_text(encoding="utf-8") for name in names}
    rows = _strict_runner_census(sources)
    missing = [row for row in rows if not row["guarded"]]
    assert missing == []
    cases = {
        "direct": "def test_new(repo,scratch): gitsafe.lane_runner(repo,scratch)",
        "helper": "def initialize(repo,scratch): return gitsafe.lane_runner(repo,scratch)\ndef test_new(repo,scratch): initialize(repo,scratch)",
        "embedded": "def test_new(repo,scratch):\n code='gitsafe.lane_runner(repo,scratch)'\n subprocess.run(code)",
        "late": "def test_new(repo,scratch):\n gitsafe.lane_runner(repo,scratch)\n strict_program_guard()",
        "conditional": "def test_new(repo,scratch):\n if False: strict_program_guard()\n gitsafe.lane_runner(repo,scratch)",
        "import-alias": "from aegis_core.gitsafe import lane_runner as build\ndef test_new(repo,scratch): build(repo,scratch)",
        "assigned-alias": "def test_new(repo,scratch):\n build=gitsafe.lane_runner\n build(repo,scratch)",
        "optional": "def test_new(repo,scratch):\n strict_program_guard(optional=unknown)\n gitsafe.lane_runner(repo,scratch)",
        "guard-kwargs": "def test_new(repo,scratch):\n strict_program_guard(**options)\n gitsafe.lane_runner(repo,scratch)",
        "late-helper": "def new_store(repo,*,require_program=True):\n tg.GitStore(repo,scratch)\n if require_program: strict_program_guard()\ndef test_new(repo): new_store(repo)",
        "module-opt-out": "new_store(repo,require_program=False)",
    }
    for source in cases.values():
        assert any(not row["guarded"] for row in _strict_runner_census({"control": source}))
    covered = "@pytest.mark.usefixtures('strict_program')\ndef test_new(repo,scratch): gitsafe.lane_runner(repo,scratch)"
    assert all(row["guarded"] for row in _strict_runner_census({"control": covered}))


def test_strict_proof_changes_with_a_helper_or_embedded_program():
    source = "CODE='gitsafe.lane_runner(repo,scratch)'\ndef initialize(): subprocess.run(CODE)\ndef test_new(): initialize()"
    original = _strict_proof_digest(ast.parse(source), "test_new")
    assert original != _strict_proof_digest(ast.parse(source.replace("repo,scratch", "other,scratch")), "test_new")
    assert original != _strict_proof_digest(ast.parse(source.replace("subprocess.run(CODE)", "subprocess.Popen(CODE)")), "test_new")


def test_strict_census_guard_forms_are_schema_independent():
    source = '''
@pytest.mark.usefixtures("strict_program")
def test_marker(repo, scratch):
    gitsafe.lane_runner(repo, scratch)
def test_fixture(repo, scratch, strict_program):
    gitsafe.lane_runner(repo, scratch)
def test_direct(repo, scratch):
    strict_program_guard()
    gitsafe.lane_runner(repo, scratch)
def initialize(repo, scratch):
    strict_program_guard()
    return gitsafe.lane_runner(repo, scratch)
def test_helper(repo, scratch):
    initialize(repo, scratch)
@pytest.mark.usefixtures("strict_program")
def test_embedded(repo, scratch):
    subprocess.run("gitsafe.lane_runner(repo, scratch)")
def test_unguarded(repo, scratch):
    gitsafe.lane_runner(repo, scratch)
def test_optional(repo, scratch):
    strict_program_guard(optional=True)
    gitsafe.lane_runner(repo, scratch)
def test_late(repo, scratch):
    gitsafe.lane_runner(repo, scratch)
    strict_program_guard()
'''
    expected = {("test_marker", True), ("test_fixture", True), ("test_direct", True),
                ("initialize", True), ("test_helper", True), ("test_embedded", True),
                ("test_unguarded", False), ("test_optional", False), ("test_late", False)}
    for schema in ("py39", "py312"):
        rows = _strict_runner_census({"control": source}, parse=lambda text: _census_parse_schema(text, schema))
        assert {(row["scope"], row["guarded"]) for row in rows} == expected


def test_strict_census_repository_set_is_schema_independent():
    sources = {name: (ROOT / "tests/unit/core" / (name + ".py")).read_text(encoding="utf-8")
               for name in ("test_gitsafe", "test_ghcli", "test_team_git")}
    native = _strict_runner_census(sources)
    for schema in ("py39", "py312"):
        rows = _strict_runner_census(sources, parse=lambda text: _census_parse_schema(text, schema))
        assert [row for row in rows if not row["guarded"]] == []
        assert rows == native


def test_strict_proof_normalizes_only_empty_type_parameters():
    source = "def checked():\n class Handler: pass\n async def nested(): return 1\n return 1"
    legacy = _census_parse_schema(source, "py39")
    modern = _census_parse_schema(source, "py312")
    baseline = _strict_proof_digest(legacy, "checked")
    assert baseline == _strict_proof_digest(modern, "checked")
    modern.body[0].type_params = [ast.Name(id="T", ctx=ast.Load())]
    assert baseline != _strict_proof_digest(modern, "checked")


def test_strict_program_guard_has_one_shared_capability_probe():
    sources = {name: ast.parse((ROOT / "tests/unit/core" / (name + ".py")).read_text(encoding="utf-8"))
               for name in ("test_gitsafe", "test_ghcli", "test_team_git")}
    probes = [(name, node.lineno) for name, tree in sources.items() for node in ast.walk(tree)
              if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("._program_supported")]
    assert probes == [("test_gitsafe", strict_program_guard.__code__.co_firstlineno + 2)]
    for name in ("test_ghcli", "test_team_git"):
        assert any(isinstance(node, ast.ImportFrom) and node.module == "tests.unit.core.test_gitsafe"
                   and {"strict_program", "strict_program_guard"} <= {alias.name for alias in node.names}
                   for node in sources[name].body)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("entry", ["discovery", "fresh", "raw", "execute", "capture", "run", "publish", "cas"])
@pytest.mark.parametrize("dispatch", ["absolute", "path"])
def test_script_git_entry_refuses_before_any_child(repo, tmp_path, effect_lock, monkeypatch, entry, dispatch):
    from conftest import symlink_or_skip
    from types import SimpleNamespace
    import hashlib
    import struct
    host, scratch = tmp_path / "host", tmp_path / "scratch"
    host.mkdir()
    scratch.mkdir()
    program, marker = host / "git", tmp_path / "script-ran"
    interpreter = repo / "model-python"
    interpreter.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    interpreter.chmod(0o700)
    source = {"PATH": str(host) + os.pathsep + os.path.dirname(gitsafe.git_executable())}
    lane = None
    if entry in ("run", "publish", "cas"):
        symlink_or_skip(gitsafe.git_executable(), program)
        lane = gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo)
        program.unlink()
    program.write_text(("#!" + str(interpreter) if dispatch == "absolute" else "#!/usr/bin/env model-python") + "\nunused\n", encoding="utf-8")
    program.chmod(0o700)
    def forbidden(*args, **kwargs):
        pytest.fail("script entry started a child")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    with pytest.raises(gitsafe.GitError) as caught:
        if entry in ("discovery", "fresh"):
            gitsafe.lane_runner(repo, scratch, environ=source, worktree_root=repo,
                effect_fds=(effect_lock,) if entry == "fresh" else None)
        elif entry == "raw":
            gitsafe.run(["version"], repo, _environ=source, worktree_root=repo, effect_fds=(effect_lock,))
        elif entry == "execute":
            gitsafe_run.execute(["version"], repo, executable=lambda **options: str(program), legacy_runner=subprocess.run,
                error=gitsafe.GitError, environ=source, timeout=5, stdin=None, hardening=gitsafe_run.DEFAULT_HARDENING,
                env=None, tty=False, effect_fds=(effect_lock,), worktree_root=repo)
        elif entry == "capture":
            with gitsafe.custody(scratch=scratch):
                gitsafe_run.capture([str(program), "version"], cwd=repo, env=source, stdin=None, timeout=5,
                    error=gitsafe.GitError, effect_fds=(effect_lock,), worktree_root=repo)
        elif entry == "run":
            lane.run(["version"])
        elif entry == "publish":
            pack = b"PACK" + struct.pack("!II", 2, 0)
            lane.publish(pack + hashlib.sha1(pack).digest(), effect_fds=(effect_lock,))
        else:
            lane.cas("refs/heads/lane/script", "a" * 40, None, effect_fds=(effect_lock,))
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
    assert str(caught.value).startswith("strict effects require a native executable: ")
    assert str(caught.value).endswith(" is a script; configure the real binary")
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("absolute", [False, True])
@pytest.mark.parametrize("dispatch", ["absolute", "path"])
def test_script_ssh_entry_never_starts_the_transport(repo, tmp_path, effect_lock, monkeypatch, absolute, dispatch):
    from types import SimpleNamespace
    import shlex
    host = tmp_path / "host"
    host.mkdir()
    interpreter, marker = repo / "model-python", tmp_path / "script-ran"
    interpreter.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    interpreter.chmod(0o700)
    script = host / "ssh"
    script.write_text(("#!" + str(interpreter) if dispatch == "absolute" else "#!/usr/bin/env model-python") + "\nunused\n", encoding="utf-8")
    script.chmod(0o700)
    calls = []
    def launch(argv, **options):
        calls.append(list(argv))
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.run(["fetch", "ssh://fixture.invalid/repo", "HEAD"], repo,
            _environ={"PATH": str(host) + os.pathsep + os.path.dirname(gitsafe.git_executable())},
            _hardening=_network_hardening("-c", "core.sshCommand=" + (shlex.quote(str(script)) if absolute else "ssh")),
            _env={"GIT_ALLOW_PROTOCOL": "ssh"}, worktree_root=repo, effect_fds=(effect_lock,))
    assert caught.value.code == "effect_command_refused" and caught.value.effect_process_started is False
    assert caught.value.process_started is True  # Native Git read the owner configuration.
    assert str(caught.value).endswith(" is a script; configure the real binary")
    assert calls and all("fetch" not in argv and "push" not in argv for argv in calls)
    assert not marker.exists()


@pytest.mark.parametrize("args,code,stdout,stderr,expected,unchanged", [
    (["git", "status"], 0, b"status\0\xff", b"notice\xff", (b"status\0\xff", b"notice\xff"), True),
    (["git", "status"], 7, b"out", b"err", (b"out", b"err"), True),
    (["git", "push"], 0, b"pushed", b"notice", (b"pushed", b"notice"), True),
    (["git", "fetch"], 1, b"private output", b"AUTHENTICATION FAILED: fixture", (b"", b"Git operation missing HTTPS credentials; prompts disabled."), False),
    (["git", "push"], 128, b"private output", b"Permission denied (publickey).", (b"", b"Git operation missing SSH credentials; prompts disabled."), False),
    (["git", "push"], 5, b"private output", b"private failure", (b"", b"Git operation effect command failed; observe before recovery."), False),
    (["git", "-c", "core.fsmonitor=false", "fetch"], -15, b"private output", b"private failure", (b"", b"Git operation effect command failed; observe before recovery."), False),
], ids=["success", "query-failure", "push-success", "https", "ssh", "generic", "signal"])
def test_effect_result_preserves_standard_type_fields_and_bytes(args, code, stdout, stderr, expected, unchanged):
    original = subprocess.CompletedProcess(args, code, stdout, stderr)
    result = gitops_fds.git_result(original, result_type=subprocess.CompletedProcess)
    assert type(result) is subprocess.CompletedProcess
    assert result.args is args and result.returncode == code
    assert (result.stdout, result.stderr) == expected
    if unchanged:
        assert result is original


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("query,suffix", [(["--git-common-dir"], b"\n"), (["--git-path", "index"], b"/index\n")])
def test_effect_result_restores_directory_paths_without_changing_its_contract(tmp_path, query, suffix):
    from types import SimpleNamespace
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        args = ["git", "rev-parse", *query]
        original = subprocess.CompletedProcess(args, 0, f"/proc/{os.getpid()}/fd/{fd}".encode("ascii") + suffix, b"notice\xff")
        process = SimpleNamespace(pid=os.getpid(), directories={"fds": (fd,)})
        result = gitops_fds.git_result(original, result_type=subprocess.CompletedProcess, process=process)
        assert type(result) is subprocess.CompletedProcess
        assert result.args is args and result.returncode == 0
        assert result.stdout == os.fsencode(tmp_path) + suffix and result.stderr == b"notice\xff"
        os.fstat(fd)
    finally:
        os.close(fd)


@pytest.mark.skipif(os.name != "posix", reason="holder cleanup uses POSIX SIGUSR1")
@pytest.mark.parametrize("fault", [None, "os-error", "timeout"])
def test_effect_cleanup_keeps_timeout_class_and_closes_every_stream(fault):
    import io
    import signal
    from types import SimpleNamespace
    signals, waits = [], []
    def wait(*, timeout):
        waits.append(timeout)
        if fault == "os-error":
            raise OSError("fixture cleanup failure")
        if fault == "timeout":
            raise subprocess.TimeoutExpired(["fixture-holder"], timeout)
        return 0
    streams = [io.BytesIO() for _ in range(3)]
    process = SimpleNamespace(raw=SimpleNamespace(poll=lambda: None, send_signal=signals.append, wait=wait),
        stdin=streams[0], stdout=streams[1], stderr=streams[2], timeout_error=subprocess.TimeoutExpired)
    try:
        assert gitops_fds.cleanup_holder(process) is (fault is not None)
        assert signals == [signal.SIGUSR1] and waits == [5]
        assert all(stream.closed for stream in streams)
    finally:
        for stream in streams:
            stream.close()
