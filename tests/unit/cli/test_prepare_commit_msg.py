"""The prepare-commit-msg hook adds ``Aegis-Check`` only for a passing check of exactly the staged tree.

These run a real ``git commit`` in a temporary repository with the hook installed there.
"""
from __future__ import annotations

import os
import stat

import pytest

from aegis_cli.hooks import commitmsg
from aegis_core import checkrun, credit
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

HOOK = commitmsg.HOOK_NAME
needs_git = pytest.mark.skipif(not hg.git_ok() or os.name == "nt", reason="needs git and a POSIX shell")


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))


def _project(tmp_path, runner=hv.PASSING):
    repo = hv.make_project(tmp_path, runner=runner)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    assert commitmsg.install(repo.root / ".git" / "hooks") == "installed"
    return repo


def _commit(repo, message="work"):
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", message)
    return repo.git("log", "-1", "--format=%B").strip()


@needs_git
def test_a_passing_check_of_the_staged_tree_adds_the_trailer(tmp_path):
    repo = _project(tmp_path)
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert credit.parse_trailer(body.splitlines()[-1]) == {"tree": row["tree"], "exit": 0}
    assert repo.git("rev-parse", "HEAD^{tree}") == row["tree"]


@needs_git
def test_no_check_row_means_no_trailer(tmp_path):
    assert "Aegis-Check" not in _commit(_project(tmp_path))


@needs_git
def test_a_failing_check_adds_no_trailer(tmp_path):
    repo = _project(tmp_path, runner=hv.FAILING)
    checkrun.record(repo.root, tests=True, base="main")
    assert "Aegis-Check" not in _commit(repo)


@needs_git
def test_a_change_after_the_check_loses_the_trailer(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    repo.write("src/app.py", "def app():\n    return 3\n")
    assert "Aegis-Check" not in _commit(repo)


@needs_git
def test_only_the_staged_tree_counts_not_the_work_tree(tmp_path):
    repo = _project(tmp_path)
    repo.write("extra.txt", "unstaged and untracked\n")
    checkrun.record(repo.root, tests=True, base="main")  # binds the whole work tree, extra.txt too
    repo.git("add", "src/app.py")
    repo.git("commit", "-q", "-m", "partial")  # the commit holds less than what was verified
    assert "Aegis-Check" not in repo.git("log", "-1", "--format=%B")


@needs_git
def test_an_amend_does_not_repeat_the_trailer(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    _commit(repo)
    repo.git("commit", "-q", "--amend", "-m", "reworded")
    assert repo.git("log", "-1", "--format=%B").count("Aegis-Check") == 1


@needs_git
def test_a_broken_ledger_never_blocks_the_commit(tmp_path):
    repo = _project(tmp_path)
    checkrun.record(repo.root, tests=True, base="main")
    hv.ledger_path(repo.root).write_bytes(b"\xff not json\n")
    assert _commit(repo).startswith("work")


def _plant_trailer_program(repo, tmp_path, config):
    """Set the repository config ``config`` names, pointing at a program that records it ran."""
    marker, program = tmp_path / "trailer-ran", tmp_path / "trailer.sh"
    program.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\necho planted\n'.encode())
    program.chmod(0o755)
    for key in config:
        repo.git("config", "--local", key, "Aegis-Check" if key.endswith(".key") else str(program))
    return marker


@needs_git
@pytest.mark.parametrize("config", [
    pytest.param(("trailer.unrelated.command",), id="any-command"),
    pytest.param(("trailer.aegis-check.cmd",), id="alias-cmd"),
    pytest.param(("trailer.x.key", "trailer.x.cmd"), id="key-cmd"),
])
def test_the_hook_runs_no_trailer_program_the_repository_names(tmp_path, config):
    """Given a trailer command in the repository config and a passing check of the staged tree,
    When the hook adds the trailer, Then the program never runs and the trailer is Aegis's."""
    repo = _project(tmp_path)
    marker = _plant_trailer_program(repo, tmp_path, config)
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert not marker.exists(), "the hook ran a program the repository's config names"
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert "planted" not in body


@needs_git
def test_in_a_linked_worktree_the_hook_runs_no_trailer_program_either(tmp_path):
    repo = _project(tmp_path)
    repo.git("commit", "-q", "-am", "start")
    marker = _plant_trailer_program(repo, tmp_path, ("trailer.x.key", "trailer.x.cmd", "trailer.unrelated.command"))
    linked = tmp_path / "linked"
    repo.git("worktree", "add", "-q", "-b", "side", str(linked))
    (linked / "src" / "app.py").write_bytes(b"def app():\n    return 4\n")
    row = checkrun.record(linked, tests=True, base="main").row
    hg.git(linked, "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "add", "-A", env=repo.home.env)
    hg.git(linked, "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "commit", "-q", "-m", "side work",
           env=repo.home.env)
    body = hg.git(linked, "log", "-1", "--format=%B", env=repo.home.env)
    assert not marker.exists()
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0" and "planted" not in body


@needs_git
def test_install_never_overwrites_a_hook_it_does_not_own(tmp_path):
    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    mine = hooks / "prepare-commit-msg"
    mine.write_text("#!/bin/sh\necho mine\n")
    assert commitmsg.install(hooks) == "foreign"
    assert mine.read_text() == "#!/bin/sh\necho mine\n"
    mine.unlink()
    assert commitmsg.install(hooks) == "installed" and commitmsg.install(hooks) == "unchanged"
    assert mine.stat().st_mode & stat.S_IXUSR
    assert commitmsg.uninstall(hooks) == "removed" and not mine.exists()


@needs_git
def test_hook_install_and_uninstall_manage_the_trailer_hook_beside_pre_commit(tmp_path, capsys):
    from aegis_cli import cli

    repo = hv.make_project(tmp_path)
    hooks = repo.root / ".git" / "hooks"
    assert cli.main(["hook", "install", "--workspace", str(repo.root)]) == 0
    assert (hooks / "pre-commit").is_file() and (hooks / HOOK).is_file()
    assert cli.main(["hook", "uninstall", "--workspace", str(repo.root)]) == 0
    assert not (hooks / HOOK).exists()
    capsys.readouterr()


@needs_git
def test_init_installs_both_hooks_and_commit_of_checked_tree_gets_one_trailer(tmp_path, capsys):
    from aegis_cli import cli

    repo = hv.make_project(tmp_path, runner=hv.PASSING)
    hv.use_stub_runner(repo.home.path)
    hooks = repo.root / ".git" / "hooks"
    assert cli.main(["init", "--workspace", str(repo.root), "--yes", "--rules", "minimal"]) == 0
    capsys.readouterr()
    assert (hooks / "pre-commit").is_file() and (hooks / HOOK).is_file()

    repo.write("src/app.py", "def app():\n    return 2\n")
    row = checkrun.record(repo.root, tests=True, base="main").row
    body = _commit(repo)
    assert body.count("Aegis-Check:") == 1
    assert body.splitlines()[-1] == f"Aegis-Check: tree={row['tree']} exit=0"
    assert repo.git("rev-parse", "HEAD^{tree}") == row["tree"]

    assert cli.main(["uninstall", "--workspace", str(repo.root)]) == 0
    capsys.readouterr()
    assert not (hooks / HOOK).exists()

