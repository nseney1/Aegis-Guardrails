"""The gh transport resolves safe repository identities and isolates every subprocess."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core import human_gate
from aegis_core import ghcli
from aegis_core.ghcli import default_gh_runner as REAL_GH
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_only = pytest.mark.skipif(os.name == "nt", reason="shell stubs")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)



# ── R-cli-28: gh never inspects the repository ───────────────────────────────

PLACEHOLDER = ["api", "--method", "GET", "repos/{owner}/{repo}"]
NO_REPO = "no GitHub repository could be resolved from remote.origin.url"


def _trapped_repo(tmp_path: Path, remote) -> "tuple[hg.Repo, Path]":
    """A repository whose own core.fsmonitor runs a marker script: plain git status there creates it."""
    repo = hg.make_repo(tmp_path)
    marker = tmp_path / "fsmonitor-ran"
    script = tmp_path / "fsmonitor.sh"
    script.write_bytes(f"#!/bin/sh\necho ran >> '{marker}'\nexit 1\n".encode("utf-8"))
    script.chmod(0o755)
    repo.git("config", "core.fsmonitor", str(script))
    if remote is not None:
        repo.git("config", "remote.origin.url", remote)
    hg.run_git(repo.root, "status", env=repo.home.env)
    if not marker.exists():
        pytest.skip("this git does not run a core.fsmonitor hook")
    marker.unlink()
    return repo, marker


@pytest.fixture
def gh_stub(tmp_path, monkeypatch):
    hg.recording_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("LOG", str(tmp_path / "gh.log"))
    monkeypatch.delenv("GH_REPO", raising=False)
    return lambda: hg.gh_log(tmp_path / "gh.log")


@needs_git
@posix_only
def test_gh_runs_in_an_empty_directory_so_the_repositorys_config_runs_nothing(tmp_path, gh_stub):
    """Given a repository whose core.fsmonitor runs a marker script, When the real runner runs a
    placeholder gh api call for it, Then gh ran in an empty directory outside the repository (removed
    afterwards), the marker never appeared, argv is unchanged and GH_REPO names the origin."""
    repo, marker = _trapped_repo(tmp_path, "https://github.com/octo/proj.git")
    assert REAL_GH(PLACEHOLDER, cwd=repo.root) == ghcli.GhResult(0, "{}\n", "")
    [call] = gh_stub()
    assert not marker.exists()
    assert call["ls"] == [] and call["argv"] == PLACEHOLDER and call["GH_REPO"] == "octo/proj"
    assert not os.path.realpath(call["cwd"]).startswith(os.path.realpath(repo.root) + os.sep)
    assert not os.path.exists(call["cwd"])


@needs_git
@posix_only
def test_a_temporary_directory_inside_a_repository_still_finds_no_repository(tmp_path, gh_stub, monkeypatch):
    """Given the temporary directory is inside the booby-trapped repository, When gh runs, Then git
    started there stops at the ceiling and the marker does not appear."""
    import tempfile

    repo, marker = _trapped_repo(tmp_path, "https://github.com/octo/proj.git")
    (repo.root / "scratch").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(repo.root / "scratch"))
    REAL_GH(PLACEHOLDER, cwd=repo.root)
    assert len(gh_stub()) == 1 and not marker.exists()


@needs_git
@posix_only
@pytest.mark.parametrize("url, expected", [
    ("https://github.com/octo/proj.git", "octo/proj"),
    ("https://github.com/octo/proj", "octo/proj"),
    ("https://x-access-token:SECRET@github.com/octo/proj.git", "octo/proj"),
    ("git@github.com:octo/proj.git", "octo/proj"),
    ("ssh://git@github.com/octo/proj.git", "octo/proj"),
    ("https://ghe.example.com/octo/proj.git", "ghe.example.com/octo/proj"),
    ("git@ghe.example.com:octo/proj.git", "ghe.example.com/octo/proj"),
    ("ssh://git@ghe.example.com:2222/octo/proj.git", "ghe.example.com/octo/proj"),
], ids=["https-git", "https", "token", "scp", "ssh", "ghes", "ghes-scp", "ghes-port"])
def test_gh_repo_is_the_origin_resolved_through_gitsafe(tmp_path, gh_stub, url, expected):
    repo, _marker = _trapped_repo(tmp_path, url)
    result = REAL_GH(PLACEHOLDER, cwd=repo.root)
    [call] = gh_stub()
    assert call["GH_REPO"] == expected and ghcli.resolve_repo(repo.root) == expected
    assert "SECRET" not in json.dumps(call) + repr(result)


@needs_git
@pytest.mark.parametrize("url, expected", [
    ("http://github.com/octo/proj.git/", "octo/proj"),
    ("git://github.com/octo/proj.git", "octo/proj"),
    ("github.com:octo/proj", "octo/proj"),
    ("https://GitHub.com/octo/proj", "octo/proj"),
    ("https://gitlab.com/group/sub/proj.git", None),
    ("https://ghe.example.com:8443/octo/proj.git", None),
    ("/srv/git/proj.git", None),
    ("file:///srv/git/octo/proj.git", None),
    ("C:/git/octo/proj", None),
    ("https://github.com/octo/..", None),
    ("https://github.com/octo/pr oj", None),
    ("ext::sh -c x%20octo/proj", None),
], ids=["http-slash", "git-proto", "scp-nouser", "host-case", "subgroup", "https-port", "path", "file", "drive",
        "dotdot", "space", "ext"])
def test_resolve_repo_accepts_only_owner_and_repo_on_a_host(tmp_path, url, expected):
    repo = hg.make_repo(tmp_path)
    repo.git("config", "remote.origin.url", url)
    assert ghcli.resolve_repo(repo.root) == expected


@needs_git
@posix_only
@pytest.mark.parametrize("remote", ["https://gitlab.com/group/sub/proj.git", "/srv/git/proj.git", None, "corrupt"],
                         ids=["subgroup", "path", "no-origin", "bad-config"])
def test_a_placeholder_call_without_a_github_origin_runs_no_gh(tmp_path, gh_stub, remote):
    """Given an origin that names no GitHub repository (or git config cannot answer), When a placeholder
    call is made, Then it returns rc 125 with the reason and the stub never ran."""
    repo, _marker = _trapped_repo(tmp_path, None if remote == "corrupt" else remote)
    if remote == "corrupt":
        with open(repo.root / ".git" / "config", "ab") as handle:
            handle.write(b'[remote "origin"\n')
    assert REAL_GH(PLACEHOLDER, cwd=repo.root) == ghcli.GhResult(125, "", NO_REPO)
    assert ghcli.resolve_repo(repo.root) is None
    assert gh_stub() == []


@needs_git
@posix_only
def test_a_gitlab_origin_is_tier_c_with_the_reason_and_no_gh_call(tmp_path, gh_stub):
    repo, _marker = _trapped_repo(tmp_path, "https://gitlab.com/group/sub/proj.git")
    report = human_gate.detect_tier(repo.root, gh=REAL_GH)
    assert report.tier == "C" and any(NO_REPO in reason for reason in report.reasons), report.reasons
    assert gh_stub() == []


@needs_git
@posix_only
def test_a_call_without_placeholders_runs_without_a_repository(tmp_path, gh_stub, monkeypatch):
    """Given an unresolvable origin, When gh --version runs (with the repository, then with none), Then the
    stub runs in an empty directory with GH_REPO unset; a resolved origin overrides an ambient GH_REPO and an
    unresolved one leaves it alone."""
    repo, _marker = _trapped_repo(tmp_path, "/srv/git/proj.git")
    assert REAL_GH(["--version"], cwd=repo.root).returncode == 0
    assert REAL_GH(["--version"]).returncode == 0
    assert [(c["ls"], c["GH_REPO"], c["argv"]) for c in gh_stub()] == [([], None, ["--version"])] * 2
    monkeypatch.setenv("GH_REPO", "ambient/repo")
    REAL_GH(["--version"], cwd=repo.root)
    repo.git("config", "remote.origin.url", "git@github.com:octo/proj.git")
    REAL_GH(["--version"], cwd=repo.root)
    assert [c["GH_REPO"] for c in gh_stub()[2:]] == ["ambient/repo", "octo/proj"]


@needs_git
@posix_only
def test_the_rest_client_with_a_gitlab_origin_reads_no_ci(tmp_path, gh_stub):
    from aegis_core import credit

    repo, _marker = _trapped_repo(tmp_path, "https://gitlab.com/group/sub/proj.git")
    with pytest.raises(credit.CIUnavailable, match="125"):
        credit.GhRestClient(runner=REAL_GH, cwd=str(repo.root)).runs_for(repo.head())
    assert gh_stub() == []


@needs_git
@posix_only
def test_sync_pr_with_a_gitlab_origin_refuses_before_moving_a_file(tmp_path, gh_stub, monkeypatch):
    """Given a decided promotion whose push URL works but whose origin is not on GitHub, When sync --pr
    runs with the real gh runner, Then it refuses, the rule did not move and gh never ran."""
    from aegis_core import sync as core_sync
    from tests import helpers_syncpr as sp

    repo = sp.make(tmp_path)
    sp.git(repo.root, "config", "remote.origin.pushurl", str(repo.origin))
    sp.git(repo.root, "config", "remote.origin.url", "https://gitlab.com/group/sub/proj.git")
    monkeypatch.setattr(ghcli, "default_gh_runner", REAL_GH)
    before = repo.state()
    result = core_sync.sync(repo.root, pr=True)
    assert result.pr["status"] == "refused" and "origin is not a GitHub repository" in result.pr["reason"]
    assert repo.state() == before and repo.origin_branches() == ["main"] and gh_stub() == []


@pytest.mark.parametrize("failure, expected", [
    (subprocess.TimeoutExpired(["gh", "--version"], 10), (124, "", "gh timed out after 10s")),
    (OSError("launch refused"), (126, "", "cannot run gh: launch refused")),
], ids=["timeout", "os-error"])
def test_transport_failures_keep_their_exact_result_and_remove_scratch(tmp_path, monkeypatch, failure, expected):
    executable = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    executable.write_bytes(b"")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert Path(kwargs["cwd"]).is_dir()
        raise failure

    monkeypatch.setattr(subprocess, "run", run)
    assert REAL_GH(["--version"]) == ghcli.GhResult(*expected)
    [(argv, kwargs)] = calls
    assert argv == [str(executable), "--version"] and kwargs["timeout"] == 10.0
    assert not Path(kwargs["cwd"]).exists()


def test_missing_gh_does_not_start_a_process(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))

    def run(*args, **kwargs):
        pytest.fail("a missing executable must not start a process")

    monkeypatch.setattr(subprocess, "run", run)
    assert REAL_GH(["--version"]) is None


def test_transport_decodes_output_and_preserves_the_exit_code(tmp_path, monkeypatch):
    executable = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    executable.write_bytes(b"")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    def run(argv, **kwargs):
        assert argv == [str(executable), "--version"]
        assert kwargs["input"] == b"input" and kwargs["stdin"] is None
        return subprocess.CompletedProcess(argv, 7, b"out\xff", b"err\xff")

    monkeypatch.setattr(subprocess, "run", run)
    assert REAL_GH(["--version"], stdin=b"input") == ghcli.GhResult(7, "out\ufffd", "err\ufffd")


@pytest.mark.parametrize("result, expected", [
    (None, (None, "gh is not installed")),
    (ghcli.GhResult(4, "", "  access\n refused  "), (None, "gh api endpoint failed: access refused")),
    (ghcli.GhResult(4, "", ""), (None, "gh api endpoint failed: exit 4")),
    (ghcli.GhResult(0, "not JSON", ""), (None, "gh api endpoint did not return JSON")),
    (ghcli.GhResult(0, '{"answer":42}', ""), ({"answer": 42}, None)),
], ids=["missing", "failure", "empty-failure", "malformed", "object"])
def test_gh_json_preserves_get_requests_and_exact_errors(tmp_path, result, expected):
    calls = []

    def run(argv, stdin=None, cwd=None):
        calls.append((argv, stdin, cwd))
        return result

    assert ghcli.gh_json(run, "endpoint", tmp_path) == expected
    assert calls == [(["api", "--method", "GET", "endpoint"], None, tmp_path)]
