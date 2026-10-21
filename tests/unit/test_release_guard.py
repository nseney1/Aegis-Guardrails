"""The publish guard: a release runs only from the tag `v` + package version, at that tag's commit.

The script is loaded by path (it is a standalone CI file, not a package module) and run
against throwaway git repositories; nothing here reaches GitHub or PyPI.
"""
import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
SCRIPT = REPO_ROOT / ".github" / "scripts" / "release_guard.py"


def _guard():
    spec = importlib.util.spec_from_file_location("release_guard", str(SCRIPT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key, value in (("HOME", str(home)), ("USERPROFILE", str(home)), ("GIT_CONFIG_NOSYSTEM", "1"),
                       ("GIT_AUTHOR_NAME", "t"), ("GIT_AUTHOR_EMAIL", "t@example.invalid"),
                       ("GIT_COMMITTER_NAME", "t"), ("GIT_COMMITTER_EMAIL", "t@example.invalid")):
        monkeypatch.setenv(key, value)
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GITHUB_REF_TYPE", "GITHUB_REF_NAME", "GITHUB_SHA"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True,
                          text=True).stdout.strip()


def _commit(repo, version, message):
    target = repo / "aegis_core" / "_version.py"
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(f'"""Version."""\n__version__ = "{version}"\n'.encode())
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _repo(tmp_path, version="4.4.0"):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    return repo, _commit(repo, version, "release")


def _run(env, repo, ref_type, ref_name, sha, capsys):
    env.chdir(str(repo))
    env.setenv("GITHUB_REF_TYPE", ref_type)
    env.setenv("GITHUB_REF_NAME", ref_name)
    env.setenv("GITHUB_SHA", sha)
    code = _guard().main()
    return code, capsys.readouterr().err


def test_the_tag_of_the_package_version_at_its_commit_passes(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    _git(repo, "tag", "v4.4.0")
    code, err = _run(env, repo, "tag", "v4.4.0", head, capsys)
    assert (code, err) == (0, "")


def test_an_annotated_tag_peels_to_its_commit(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    _git(repo, "tag", "-a", "v4.4.0", "-m", "release 4.4.0")
    assert _git(repo, "rev-parse", "refs/tags/v4.4.0") != head  # the tag object, not the commit
    assert _run(env, repo, "tag", "v4.4.0", head, capsys) == (0, "")


def test_a_dispatch_from_a_branch_fails(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    code, err = _run(env, repo, "branch", "main", head, capsys)
    assert code == 1
    assert "ref type is 'branch', not 'tag'" in err


def test_a_tag_that_is_not_v_plus_the_version_fails(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    _git(repo, "tag", "v4.4.1")
    code, err = _run(env, repo, "tag", "v4.4.1", head, capsys)
    assert code == 1
    assert "tag 'v4.4.1' is not 'v4.4.0'" in err
    assert "ref type" not in err and "commit" not in err


def test_a_tag_on_an_older_commit_than_the_run_fails(tmp_path, env, capsys):
    repo, old = _repo(tmp_path)
    _git(repo, "tag", "v4.4.0")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "later")
    head = _git(repo, "rev-parse", "HEAD")
    code, err = _run(env, repo, "tag", "v4.4.0", head, capsys)
    assert code == 1
    assert f"tag commit {old} is not the run's commit {head}" in err


def test_no_version_file_cannot_decide(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    _git(repo, "tag", "v4.4.0")
    (repo / "aegis_core" / "_version.py").unlink()
    code, err = _run(env, repo, "tag", "v4.4.0", head, capsys)
    assert code == 2
    assert "_version.py" in err


def test_a_tag_missing_from_the_checkout_cannot_decide(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    code, err = _run(env, repo, "tag", "v4.4.0", head, capsys)
    assert code == 2
    assert "refs/tags/v4.4.0" in err


def test_no_git_on_path_cannot_decide(tmp_path, env, capsys):
    repo, head = _repo(tmp_path)
    _git(repo, "tag", "v4.4.0")
    empty = tmp_path / "empty"
    empty.mkdir()
    env.setenv("PATH", str(empty))
    code, err = _run(env, repo, "tag", "v4.4.0", head, capsys)
    assert code == 2
    assert "git" in err


def test_check_reports_every_failed_check():
    messages = _guard().check("branch", "v9", "a" * 40, "4.4.0", "b" * 40)
    assert len(messages) == 3
    assert _guard().check("tag", "v4.4.0", "a" * 40, "4.4.0", "a" * 40) == []
