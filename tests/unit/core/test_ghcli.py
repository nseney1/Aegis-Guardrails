"""The gh transport resolves safe repository identities and isolates every subprocess."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core import human_gate
from aegis_core import ghcli, gitops_fds, gitsafe_run
from aegis_core import gitsafe as git_transport
from aegis_core.ghcli import default_gh_runner as REAL_GH
from tests import helpers_humangate as hg
from tests.unit.core.test_gitsafe import strict_program, strict_program_guard, _native_program

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_only = pytest.mark.skipif(os.name == "nt", reason="shell stubs")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("LC_ALL", "C")  # Deterministic CLI output, without an input-layer Git selector.
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


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="effect custody requires Linux child subreaper support")
@needs_git
@pytest.mark.parametrize("site", ["gh", "gh_injected"])
def test_effect_gh_lock_survives_killed_owner(tmp_path, site):
    from tests.unit.core.test_gitsafe import _assert_effect_survives_owner, _repo
    ambient = {**os.environ, "GIT_EDITOR": "fixture-host-program", "GIT_PAGER": "fixture-host-program",
               "PAGER": "fixture-host-program", "GH_PAGER": "fixture-host-program"}
    _assert_effect_survives_owner(tmp_path, _repo(tmp_path / "repo"), site, environ=ambient)


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="effect custody requires Linux child subreaper support")
@pytest.mark.parametrize("bad", ["closed", "negative", "many"])
def test_effect_gh_invalid_descriptor_never_spawns(tmp_path, monkeypatch, bad):
    from types import SimpleNamespace
    from aegis_core import gitsafe
    with (tmp_path / "lock").open("w+b") as stream:
        fd = stream.fileno()
        os.set_inheritable(fd, bad != "noninheritable")
        fds = (fd,)
        if bad == "closed":
            stream.close()
        elif bad == "negative":
            fds = (-1,)
        elif bad == "many":
            fds = (fd, fd)
        def unexpected(*args, **kwargs):
            pytest.fail("invalid descriptor reached gh spawn")
        monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": unexpected}))
        with pytest.raises(gitsafe.GitError) as caught:
            REAL_GH(["api", "user"], effect_fds=fds, worktree_root=Path(__file__).resolve().parents[3])
        assert caught.value.code == "invalid_effect_descriptor"
        assert caught.value.process_started is False and caught.value.next_action


def test_effect_gh_unsupported_probe_refuses_before_lookup(monkeypatch):
    from aegis_core import gitsafe
    monkeypatch.setattr(gitops_fds, "descriptor_supported", lambda: False)
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user"], effect_fds=(17,), worktree_root=Path(__file__).resolve().parents[3])
    assert caught.value.code == "unsupported_effect_platform"
    assert caught.value.process_started is False and caught.value.next_action


def test_effect_injected_gh_runner_requires_explicit_contract(tmp_path):
    from aegis_core import gitsafe
    calls = []
    def undeclared(*args, **kwargs):
        calls.append((args, kwargs))
    with pytest.raises(gitsafe.GitError) as caught:
        ghcli.effect_runner(undeclared, (17,), worktree_root=Path(__file__).resolve().parents[3])
    assert caught.value.code == "effect_runner_refused"
    assert calls == []


@pytest.mark.usefixtures("strict_program")
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="effect custody requires Linux child subreaper support")
@pytest.mark.parametrize("failure", ["enoent", "emfile"])
def test_effect_gh_failed_spawn_has_fixed_result_and_preserves_fd(tmp_path, monkeypatch, failure):
    import errno
    from types import SimpleNamespace
    executable = tmp_path / "gh"
    _native_program(executable, "#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    calls = []
    def fail(argv, **kw):
        calls.append(kw)
        raise OSError(errno.ENOENT if failure == "enoent" else errno.EMFILE, "secret-input")
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": fail, "Popen": fail}))
    with (tmp_path / "lock").open("w+b") as stream:
        gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        baseline = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").is_dir() else None
        for _ in range(2):
            from aegis_core import gitsafe
            with pytest.raises(gitsafe.GitError) as caught:
                REAL_GH(["api", "user"], stdin=b"payload", effect_fds=(stream.fileno(),), env={"PATH": str(tmp_path), "TMPDIR": str(tmp_path), "GH_TOKEN": "fixture-public-token"}, worktree_root=Path(__file__).resolve().parents[3])
            assert caught.value.code == "gh_spawn_failed"
            assert caught.value.process_started is False and "no effect process started" in str(caught.value)
            assert calls[-1]["pass_fds"][0] == stream.fileno() and len(calls[-1]["pass_fds"]) == 3
            assert "input" not in calls[-1] and calls[-1]["stdin"] == subprocess.PIPE
            assert not Path(calls[-1]["cwd"]).exists()
            assert not os.get_inheritable(stream.fileno())
            if baseline is not None:
                assert set(os.listdir("/proc/self/fd")) == baseline


@pytest.mark.parametrize("argv", [["pr", "create"], ["extension", "exec", "evil"],
    ["api", "repos/x/y/{branch}"], ["api", "repos/x/y/:branch"],
    ["api", "user", "--input", "untrusted-file"], ["api", "user", "-F", "a=@untrusted-file"],
    ["api", "user", "--input=untrusted-file"], ["api", "user", "--field=a=@untrusted-file"]])
@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="effect custody requires Linux child subreaper support")
def test_effect_gh_refuses_external_consumers_and_unconfined_file_inputs(tmp_path, argv):
    from aegis_core import gitsafe
    with (tmp_path / "lock").open("w+b") as stream:
        gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        with pytest.raises(gitsafe.GitError) as caught:
            REAL_GH(argv, effect_fds=(stream.fileno(),), worktree_root=Path(__file__).resolve().parents[3])
        assert caught.value.code == "effect_command_refused"
        assert caught.value.process_started is False and caught.value.next_action


@pytest.mark.parametrize("effect", [False, True], ids=["legacy", "effect"])
@pytest.mark.parametrize("payload", [None, b"payload"], ids=["devnull", "input"])
def test_effect_gh_spawn_golden_and_helper_environment(tmp_path, monkeypatch, effect, payload):
    from types import SimpleNamespace
    import sys
    if effect:
        strict_program_guard()
    if effect and not gitops_fds.descriptor_supported():
        pytest.skip("effect descriptor inheritance requires POSIX pass_fds")
    executable = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    input_path = tmp_path / "wire-input"
    executable.write_text("#!" + sys.executable + "\nimport sys\nfrom pathlib import Path\nPath(" + repr(str(input_path))
                          + ").write_bytes(sys.stdin.buffer.read())\nsys.stdout.write('{}')\n", encoding="utf-8")
    executable.chmod(0o700)
    if effect: _native_program(executable, executable.read_text(encoding="utf-8"))
    environ = {"PATH": str(tmp_path), "GH_TOKEN": "fixture-public-token", "GH_PAGER": "untrusted-pager",
               "GIT_SSH_COMMAND": "untrusted-ssh -oControlPersist=yes"}
    if effect:
        environ = {"PATH": str(tmp_path), "GH_TOKEN": "fixture-public-token", "TMPDIR": str(tmp_path)}
    calls = []
    def record(argv, **kw):
        calls.append((argv, kw.copy()))
        if effect:
            calls[-1][1]["cwd"] = os.path.realpath(kw["cwd"])
            return subprocess.Popen(argv, **kw)
        return subprocess.CompletedProcess(argv, 0, b"{}", b"")
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": record, "Popen": record}))
    with (tmp_path / "lock").open("w+b") as stream:
        if effect:
            gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        kw = {"effect_fds": (stream.fileno(),)} if effect else {}
        assert REAL_GH(["api", "user"], stdin=payload, env=environ, **kw, worktree_root=Path(__file__).resolve().parents[3]) == ghcli.GhResult(0, "{}", "")
        [(argv, spawn)] = calls
        assert (argv[11:] if effect else argv) == [str(executable), "api", "user", *(["--hostname", "github.com"] if effect else [])]
        if effect:
            assert set(spawn) == {"stdin", "stdout", "stderr", "env", "cwd", "bufsize", "start_new_session", "pass_fds", "executable"}
            assert spawn["stdin"] == (subprocess.DEVNULL if payload is None else subprocess.PIPE)
            assert spawn["stdout"] == spawn["stderr"] == subprocess.PIPE
            assert spawn["bufsize"] == 0 and spawn["start_new_session"] is True
            assert input_path.read_bytes() == (payload or b"")
        else:
            assert set(spawn) == {"input", "stdin", "capture_output", "env", "cwd", "timeout", "check"}
            assert spawn["input"] == payload and spawn["stdin"] == (subprocess.DEVNULL if payload is None else None)
            assert spawn["capture_output"] is True and spawn["check"] is False and spawn["timeout"] == 10
        expected = {**environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
            "GIT_CEILING_DIRECTORIES": os.pathsep.join(dict.fromkeys((os.path.dirname(spawn["cwd"]), os.path.dirname(os.path.realpath(spawn["cwd"])))))}
        if effect:
            assert spawn["pass_fds"][0] == stream.fileno() and len(spawn["pass_fds"]) == 3
            assert spawn["env"]["GH_CONFIG_DIR"] == spawn["cwd"]
            assert spawn["env"]["GH_PAGER"] == spawn["env"]["PAGER"] == ""
            assert spawn["env"]["GIT_SSH_COMMAND"] == "false"
            assert spawn["env"]["GIT_CONFIG_COUNT"] == "5"
            assert [spawn["env"]["GIT_CONFIG_VALUE_" + str(i)] for i in range(5)] == ["", "", "false", "0", "false"]
        else:
            assert spawn["env"] == expected
        assert not Path(spawn["cwd"]).exists()


@pytest.mark.skipif(not gitops_fds.descriptor_supported(), reason="effect custody requires Linux child subreaper support")
def test_effect_injected_runner_forwards_only_the_bound_descriptor(tmp_path):
    from aegis_core import gitsafe
    seen = []
    def declared(argv, stdin=None, cwd=None, **kw):
        seen.append((argv, stdin, cwd, kw))
        return ghcli.GhResult(0, "{}", "")
    declared.supports_effect_fds = True
    with (tmp_path / "lock").open("w+b") as stream:
        gitops_fds.receipt_fds(stream.fileno(), error=gitops_fds.AegisError)
        runner = ghcli.effect_runner(declared, (stream.fileno(),), worktree_root=Path(__file__).resolve().parents[3])
        bound_root = Path(__file__).resolve().parents[3]
        assert runner(["api", "user"], b"body", bound_root) == ghcli.GhResult(0, "{}", "")
        assert seen == [(["api", "user"], b"body", bound_root, {"effect_fds": (stream.fileno(),), "worktree_root": bound_root})]
        with pytest.raises(gitsafe.GitError) as caught:
            runner(["api", "user"], effect_fds=(999,))
        assert caught.value.code == "effect_runner_refused"
        stream.close()
        with pytest.raises(gitsafe.GitError) as caught:
            runner(["api", "user"])
        assert caught.value.code == "invalid_effect_descriptor"
        assert len(seen) == 1


def test_default_gh_runner_preserves_ambient_spawn_environment(tmp_path, monkeypatch):
    from types import SimpleNamespace
    executable = tmp_path / ("gh.exe" if os.name == "nt" else "gh")
    calls = []
    def record(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, b"{}", b"")
    monkeypatch.setattr(ghcli, "pathlookup", SimpleNamespace(which=lambda *args, **kwargs: str(executable)))
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": record}))
    assert REAL_GH(["api", "user"]) == ghcli.GhResult(0, "{}", "")
    [(argv, spawn)] = calls
    assert argv == [str(executable), "api", "user"]
    assert set(spawn) == {"input", "stdin", "capture_output", "env", "cwd", "timeout", "check"}
    expected = {**os.environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
        "GIT_CEILING_DIRECTORIES": os.pathsep.join(dict.fromkeys((os.path.dirname(spawn["cwd"]), os.path.dirname(os.path.realpath(spawn["cwd"])))))}
    assert spawn["env"] == expected
    assert not Path(spawn["cwd"]).exists()


@pytest.mark.parametrize("env", [[], {"PATH": "x" * 65537}, {"bad\0key": "x"}, {"PATH": 3}, {"k" + str(i): "v" for i in range(513)}])
def test_explicit_gh_environment_refuses_before_lookup(env, monkeypatch):
    from types import SimpleNamespace
    from aegis_core import gitsafe
    def unexpected(*args, **kwargs):
        pytest.fail("invalid environment reached executable lookup")
    monkeypatch.setattr(ghcli, "pathlookup", SimpleNamespace(which=unexpected))
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user"], env=env)
    assert caught.value.code == "invalid_gh_environment"
    assert caught.value.process_started is False and caught.value.next_action


@pytest.fixture
def gh_effect_request(tmp_path):
    if not gitops_fds.descriptor_supported():
        pytest.skip("effect custody requires Linux child subreaper support")
    import sys
    log = tmp_path / "effect-gh.json"
    stub = tmp_path / "gh"
    _native_program(stub, "#!" + sys.executable + "\nimport json, os, sys\n"
        + "from pathlib import Path\nPath(" + repr(str(log)) + ").write_text(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
        + "print('HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{}' if '--include' in sys.argv else '{}')\n")
    stub.chmod(0o700)
    git = tmp_path / "git"
    _native_program(git, "#!/bin/sh\nexec '" + git_transport.git_executable() + "' \"$@\"\n")
    git.chmod(0o700)
    with (tmp_path / "lock").open("w+b") as held:
        gitops_fds.receipt_fds(held.fileno(), error=gitops_fds.AegisError)
        yield held.fileno(), {"PATH": str(tmp_path), "TMPDIR": str(tmp_path), "GH_TOKEN": "fixture-public-token"}, log


@pytest.mark.parametrize("flag", ["--jq", "-q", "--template", "-t"])
@pytest.mark.parametrize("paginate", [False, True], ids=["api", "paginate"])
def test_effect_gh_refuses_environment_evaluating_output(gh_effect_request, flag, paginate):
    from aegis_core import gitsafe
    fd, environ, log = gh_effect_request
    argv = ["api", "user", *(["--paginate"] if paginate else []), flag, "env.GH_TOKEN"]
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(argv, env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert caught.value.code == "effect_command_refused"
    assert caught.value.process_started is False and caught.value.next_action
    assert not log.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("tokens, host, arguments, expected", [
    ({"GH_TOKEN": "fixture-public-token"}, None, [], "github.com"),
    ({"GITHUB_TOKEN": "fixture-public-token"}, None, ["--paginate"], "github.com"),
    ({"GH_ENTERPRISE_TOKEN": "fixture-enterprise-token"}, "git.example.com", [], "git.example.com"),
    ({"GITHUB_ENTERPRISE_TOKEN": "fixture-enterprise-token"}, None, ["--hostname", "git.example.com"], "git.example.com"),
    ({"GH_ENTERPRISE_TOKEN": "fixture-enterprise-token"}, None, [], "gh_token_host_mismatch"),
    ({"GH_TOKEN": "fixture-public-token"}, "git.example.com", [], "gh_token_host_mismatch"),
    ({"GH_TOKEN": "fixture-public-token"}, "git.example.com", ["--hostname", "github.com"], "gh_host_mismatch"),
    ({}, None, [], "gh_token_missing"),
    ({"GH_TOKEN": "fixture-public-token"}, None, ["https://other.example.com/user"], "effect_command_refused"),
])
def test_effect_gh_uses_only_host_applicable_request_token(gh_effect_request, tokens, host, arguments, expected):
    from aegis_core import gitsafe
    fd, environ, log = gh_effect_request
    environ = {"PATH": environ["PATH"], "TMPDIR": environ["TMPDIR"], "UNRELATED_CREDENTIAL": "fixture-unrelated", **tokens}
    if host is not None:
        environ["GH_HOST"] = host
    argv = ["api", *([] if arguments and arguments[0].startswith("https:") else ["user"]), *arguments]
    if expected.startswith("gh_") or expected == "effect_command_refused":
        with pytest.raises(gitsafe.GitError) as caught:
            REAL_GH(argv, env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
        assert caught.value.code == expected
        assert caught.value.process_started is False and caught.value.next_action
        assert not log.exists()
    else:
        assert REAL_GH(argv, env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3]).returncode == 0
        record = json.loads(log.read_text(encoding="utf-8"))
        assert record["argv"][-2:] == ["--hostname", expected]
        assert record["env"]["GH_HOST"] == expected
        assert "UNRELATED_CREDENTIAL" not in record["env"]
    assert not os.get_inheritable(fd)


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("slurp", [False, True])
def test_effect_gh_pagination_stays_on_selected_host(gh_effect_request, slurp):
    import sys
    fd, environ, log = gh_effect_request
    stub = Path(environ["PATH"]) / "gh"
    _native_program(stub, "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\n"
        + "p=Path(" + repr(str(log)) + ")\ncalls=json.loads(p.read_text()) if p.exists() else []\ncalls.append(sys.argv[1:])\np.write_text(json.dumps(calls))\n"
        + "print('HTTP/1.1 200 OK\\r\\nContent-Type: application/json')\n"
        + "if len(calls)==1: print('Link: <https://api.github.com/user?page=2>; rel=\"next\"')\n"
        + "print('\\r\\n'+json.dumps({'page': len(calls)}))\n")
    result = REAL_GH(["api", "user", "--paginate", *(["--slurp"] if slurp else [])], env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert result.returncode == 0
    pages = json.loads(result.stdout) if slurp else [json.loads(line) for line in result.stdout.splitlines()]
    assert pages == [{"page": 1}, {"page": 2}]
    calls = json.loads(log.read_text())
    assert len(calls) == 2
    assert all("--paginate" not in call for call in calls)
    assert calls[1] == ["api", "--include", "user?page=2", "--hostname", "github.com"]


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_pagination_refuses_off_host_link_after_first_child(gh_effect_request):
    import sys
    from aegis_core import gitsafe
    fd, environ, log = gh_effect_request
    stub = Path(environ["PATH"]) / "gh"
    _native_program(stub, "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\n"
        + "p=Path(" + repr(str(log)) + ")\ncalls=json.loads(p.read_text()) if p.exists() else []\ncalls.append(sys.argv[1:])\np.write_text(json.dumps(calls))\n"
        + "print('HTTP/1.1 200 OK\\r\\nLink: <https://other.example.com/user?page=2>; rel=\"next\"\\r\\n\\r\\n{}')\n")
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user", "--paginate"], env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert caught.value.code == "gh_pagination_host_refused"
    assert caught.value.process_started is True and caught.value.next_action
    assert len(json.loads(log.read_text())) == 1


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("stream, cap", [("stdout", 4 * 1024 * 1024), ("stderr", 65536)])
def test_effect_gh_caps_each_pipe_before_buffer_growth(gh_effect_request, stream, cap):
    import sys
    from aegis_core import gitsafe
    fd, environ, log = gh_effect_request
    stub = Path(environ["PATH"]) / "gh"
    _native_program(stub, "#!" + sys.executable + "\nimport sys\nsys." + stream
                    + ".buffer.write(b'x' * " + str(cap + 1) + ")\n")
    before = set(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").is_dir() else None
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user"], env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert caught.value.code == "gh_output_limit"
    assert caught.value.process_started is True and caught.value.next_action
    assert not os.get_inheritable(fd)
    if before is not None:
        assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_resolution_uses_explicit_timeout_and_environment(gh_effect_request, tmp_path, monkeypatch):
    fd, environ, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "repository")
    repo.git("config", "remote.origin.url", "https://github.com/real/repository.git")
    original, calls = git_transport.run, []
    def record(args, cwd, **kwargs):
        calls.append(kwargs.copy())
        return original(args, cwd, **kwargs)
    monkeypatch.setattr(git_transport, "run", record)
    assert REAL_GH(["api", "repos/{owner}/{repo}"], cwd=repo.root, env=environ, timeout=0.75, effect_fds=(fd,), worktree_root=repo.root).returncode == 0
    assert calls and calls[0]["timeout"] == 0.75
    assert calls[0]["effect_fds"] == (fd,)
    assert all(calls[0]["_environ"][key] == value for key, value in {**environ, "GH_HOST": "github.com"}.items())
    assert calls[0]["_environ"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert json.loads(log.read_text())["env"]["GH_REPO"] == "real/repository"


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_resolution_ignores_ambient_repository_injection(gh_effect_request, tmp_path):
    import sys
    fd, environ, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "repository")
    repo.git("config", "remote.origin.url", "https://github.com/real/repository.git")
    code = "\nimport os, sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core.ghcli import default_gh_runner\nfrom aegis_core import gitops_fds\nwith open(sys.argv[4],'w+b') as held:\n    gitops_fds.receipt_fds(held.fileno(),error=gitops_fds.AegisError)\n    result=default_gh_runner(['api','repos/{owner}/{repo}'],cwd=sys.argv[2],env={'PATH':sys.argv[3],'TMPDIR':os.path.dirname(sys.argv[4]),'GH_TOKEN':'fixture-public-token'},timeout=2,effect_fds=(held.fileno(),), worktree_root=sys.argv[2])\n    assert result.returncode==0\n"
    root = Path(__file__).resolve().parents[3]
    ambient = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.url",
               "GIT_CONFIG_VALUE_0": "https://github.com/attacker/target.git"}
    child = subprocess.run([sys.executable, "-I", "-c", code, str(root), str(repo.root), environ["PATH"], str(tmp_path / "child-lock")],
                           env=ambient, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert json.loads(log.read_text())["env"]["GH_REPO"] == "real/repository"


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("host,api_host,prefix", [
    ("github.com", "api.github.com", "/"),
    ("tenant.ghe.com", "api.tenant.ghe.com", "/"),
    ("github.localhost", "api.github.localhost", "/"),
    ("git.example.com", "git.example.com", "/api/v3/"),
], ids=["public", "tenancy", "localhost", "enterprise"])
def test_effect_gh_host_classes_and_pagination(gh_effect_request, host, api_host, prefix):
    import sys
    fd, environ, log = gh_effect_request
    public = host in ("github.com", "tenant.ghe.com", "github.localhost")
    environ = {"PATH": environ["PATH"], "TMPDIR": environ["TMPDIR"], "GH_HOST": host,
               "GH_TOKEN" if public else "GH_ENTERPRISE_TOKEN": "fixture-token"}
    stub = Path(environ["PATH"]) / "gh"
    _native_program(stub, "#!" + sys.executable + "\nimport os, json, sys\nfrom pathlib import Path\n"
        + "p=Path(" + repr(str(log)) + ")\ncalls=json.loads(p.read_text()) if p.exists() else []\n"
        + "calls.append({'argv':sys.argv[1:],'env':dict(os.environ)})\np.write_text(json.dumps(calls))\n"
        + "print('HTTP/1.1 200 OK')\nif len(calls)==1: print('Link: <" + ("http" if host == "github.localhost" else "https") + "://" + api_host + prefix
        + "user?page=2>; rel=\"next\"')\nprint('\\r\\n{}')\n")
    result = REAL_GH(["api", "user", "--paginate"], env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert result.returncode == 0
    calls = json.loads(log.read_text())
    assert len(calls) == 2 and calls[1]["argv"] == ["api", "--include", "user?page=2", "--hostname", host]
    assert calls[0]["env"]["GH_TOKEN" if public else "GH_ENTERPRISE_TOKEN"] == "fixture-token"


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_filters_large_ambient_environment_before_limits(gh_effect_request, tmp_path):
    import sys
    fd, environ, log = gh_effect_request
    code = "\nimport os, sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nfrom aegis_core.ghcli import default_gh_runner\nwith open(sys.argv[2],'r+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    assert default_gh_runner(['api','user'],effect_fds=fds, worktree_root=sys.argv[1]).returncode==0\n    os.environ['PATH']='x'*65537\n    try:\n        default_gh_runner(['api','user'],effect_fds=fds, worktree_root=sys.argv[1])\n    except gitsafe.GitError as exc:\n        assert exc.code=='effect_environment_limit'\n        assert exc.process_started is False and 'environment' in exc.next_action.lower()\n    else:\n        raise AssertionError('oversized retained environment was accepted')\n"
    root = Path(__file__).resolve().parents[3]
    child = subprocess.run([sys.executable, "-I", "-c", code, str(root), str(tmp_path / "lock")],
        env={**os.environ, **environ, **{"UNRELATED_"+str(i):"fixture" for i in range(513)}, "UNRELATED_"+"x"*300:"fixture"},
        capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr


@pytest.mark.parametrize("cwd", [".", "../repository", "/tmp/parent/../repository"])
def test_effect_gh_noncanonical_cwd_has_typed_prespawn_refusal(gh_effect_request, cwd):
    from aegis_core import gitsafe
    fd, environ, log = gh_effect_request
    for operation in (
        lambda: REAL_GH(["api", "user"], cwd=cwd, env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3]),
        lambda: ghcli.resolve_repo(cwd, env=environ, effect_fds=(fd,), worktree_root=cwd),
    ):
        with pytest.raises(gitsafe.GitError) as caught:
            operation()
        assert caught.value.code == "invalid_effect_cwd"
        assert caught.value.process_started is False and caught.value.next_action
    assert not log.exists()


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_lookup_fences_implicit_cwd(gh_effect_request, tmp_path):
    import sys
    _, environ, log = gh_effect_request
    checkout = hg.make_repo(tmp_path / "checkout").root
    hostile = checkout / "bin"
    hostile.mkdir(parents=True)
    marker = tmp_path / "hostile-gh-ran"
    fake = hostile / "gh"
    fake.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nprint('{}')\n", encoding="utf-8")
    fake.chmod(0o700)
    code = "\nimport sys\nsys.path.insert(0,sys.argv[1])\nfrom aegis_core import gitsafe, gitops_fds\nfrom aegis_core.ghcli import default_gh_runner\nwith open(sys.argv[2],'r+b') as held:\n    fds=gitops_fds.receipt_fds(held.fileno(),error=gitsafe.GitError)\n    assert default_gh_runner(['api','user'],effect_fds=fds, worktree_root=sys.argv[3]).returncode==0\n"
    root = Path(__file__).resolve().parents[3]
    child = subprocess.run([sys.executable, "-I", "-c", code, str(root), str(tmp_path / "lock"), str(checkout)], cwd=checkout,
        env={**os.environ, **environ, "GH_HOST": "github.com", "PATH": str(hostile) + os.pathsep + environ["PATH"]},
        capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    assert not marker.exists() and log.exists()


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_scratch_uses_the_validated_environment(gh_effect_request, tmp_path):
    fd, environ, log = gh_effect_request
    selected = tmp_path / "selected-temp"
    selected.mkdir()
    environ["TMPDIR"] = str(selected)
    result = REAL_GH(["api", "user"], env=environ, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert result.returncode == 0
    assert Path(json.loads(log.read_text())["env"]["GH_CONFIG_DIR"]).parent == selected


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_explicit_root_blocks_subdirectory_marker(gh_effect_request, tmp_path):
    from aegis_core import gitsafe
    fd, env, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "bound-owner").root
    source = repo / "src"
    source.mkdir(exist_ok=True)
    (source / ".git").write_bytes(b"")
    bad = repo / "bin"
    bad.mkdir()
    marker = tmp_path / "model-gh-ran"
    script = bad / "gh"
    script.write_text("#!/bin/sh\n: > '" + str(marker) + "'\nprintf '{}\\n'\n", encoding="utf-8")
    script.chmod(0o700)
    env = {**env, "PATH": str(bad) + os.pathsep + env["PATH"], "TMPDIR": str(repo)}
    try: result = REAL_GH(["api", "user"], cwd=source, env=env, worktree_root=repo, effect_fds=(fd,))
    except gitsafe.GitError as error:
        assert error.code in ("effect_environment_unavailable", "gh_scratch_unavailable") and error.process_started is False
    else: assert result.returncode == 0 and log.exists()
    assert not marker.exists()


@pytest.mark.parametrize("form", ["missing", "none", "nonexistent", "outside", "symlink"])
def test_effect_gh_root_refuses_before_lookup(gh_effect_request, tmp_path, monkeypatch, form):
    from conftest import symlink_or_skip
    from types import SimpleNamespace
    from aegis_core import gitsafe
    fd, env, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "owner-root").root
    root = repo
    if form == "none": root = None
    elif form == "nonexistent": root = tmp_path / "absent"
    elif form == "outside": root = hg.make_repo(tmp_path / "foreign-root").root
    elif form == "symlink":
        root = tmp_path / "root-link"
        symlink_or_skip(repo, root, target_is_directory=True)
    observed = []
    def unexpected(*args, **kwargs):
        observed.append(True)
        pytest.fail("invalid GitHub root reached lookup")
    monkeypatch.setattr(ghcli, "pathlookup", SimpleNamespace(which=unexpected))
    kwargs = {} if form == "missing" else {"worktree_root": root}
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user"], cwd=repo, env=env, effect_fds=(fd,), **kwargs)
    assert caught.value.code == "effect_environment_unavailable" and caught.value.process_started is False
    assert caught.value.next_action and observed == [] and not log.exists()


@pytest.mark.usefixtures("strict_program")
def test_effect_gh_keeps_repository_binding_out_of_isolated_child(gh_effect_request):
    fd, env, log = gh_effect_request
    result = REAL_GH(["api", "user"], env=env, effect_fds=(fd,), worktree_root=Path(__file__).resolve().parents[3])
    assert result.returncode == 0
    assert {"GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"}.isdisjoint(json.loads(log.read_text())["env"])


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("paginate", [False, True])
@pytest.mark.parametrize("form", ["directory-alias", "worktree-file", "write-root-file", "intermediate-file", "intermediate-directory"])
def test_gh_program_targets_are_fenced_on_every_page(gh_effect_request, tmp_path, paginate, form):
    import sys
    from conftest import symlink_or_skip
    from aegis_core import gitsafe
    fd, env, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "owner-root").root
    write_root = tmp_path / "write-root"
    write_root.mkdir()
    programs = (write_root if form == "write-root-file" else repo) / "programs"
    programs.mkdir()
    marker = tmp_path / "untrusted-gh-ran"
    target = programs / "gh"
    target.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker))
        + ").touch()\nprint('HTTP/1.1 200 OK\\r\\n\\r\\n{}')\n", encoding="utf-8")
    target.chmod(0o700)
    external = tmp_path / "external-bin"
    if form.startswith("intermediate-"):
        trusted = tmp_path / "trusted-programs"
        programs.rename(trusted)
        symlink_or_skip(trusted, programs, target_is_directory=True)
        if form == "intermediate-directory":
            symlink_or_skip(programs, external, target_is_directory=True)
        else:
            external.mkdir()
            symlink_or_skip(programs / "gh", external / "gh")
    elif form == "directory-alias":
        symlink_or_skip(programs, external, target_is_directory=True)
    else:
        external.mkdir()
        symlink_or_skip(target, external / "gh")
    environment = {**env, "PATH": os.pathsep.join((str(external), env["PATH"], os.path.dirname(gitsafe.git_executable())))}
    args = ["api", "user", *(["--paginate"] if paginate else [])]
    try:
        result = REAL_GH(args, cwd=repo, env=environment, effect_fds=(fd,), worktree_root=repo,
                         write_roots=(write_root,))
    except gitsafe.GitError as exc:
        # Directory aliases may be skipped, reaching the deterministic fixture
        # whose ordinary response deliberately lacks pagination headers.
        assert exc.code in ("effect_command_refused", "gh_pagination_response_refused")
        assert exc.next_action
    else:
        assert result.returncode == 0
    assert not marker.exists(), "a fenced gh target received the request token"


@pytest.mark.parametrize("paginate", [False, True])
@pytest.mark.parametrize("layer", ["source", "ambient", "scope", "reuse", "replace"])
@pytest.mark.parametrize("key", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_NOSYSTEM", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "BASH_ENV", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "OPENSSL_CONF"])
def test_gh_selector_inputs_refuse_before_every_page(gh_effect_request, tmp_path, monkeypatch, paginate, layer, key):
    if layer in ("reuse", "replace"):
        strict_program_guard()
    from types import SimpleNamespace
    from aegis_core import gitsafe
    import contextlib
    fd, source, log = gh_effect_request
    root = Path(__file__).resolve().parents[3]
    observed = []
    def launch(argv, **options):
        observed.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    if layer in ("reuse", "replace"):
        assert REAL_GH(["api", "user"], env=source, effect_fds=(fd,), worktree_root=root).returncode == 0
        source = observed[-1]
        log.unlink()
    bad = {key: "UNTRUSTED_SELECTOR_VALUE"}
    if layer == "source":
        source = {**source, **bad}
    elif layer == "ambient":
        monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": {**os.environ, **bad}}))
        source = None
    elif layer == "reuse":
        source.update(bad)
    observed.clear()
    context = gitsafe.custody(scratch=tmp_path / "scope", env=bad, worktree_root=root) if layer == "scope" else contextlib.nullcontext()
    with context, pytest.raises(gitsafe.GitError) as caught:
        if layer == "replace": source = source.with_vars({**source, **bad}, replace=True)
        REAL_GH(["api", "user", *(["--paginate"] if paginate else [])], env=source,
                effect_fds=(fd,), worktree_root=root)
    assert caught.value.code in ("ambient_git_environment", "git_custody_refused")
    assert caught.value.next_action and caught.value.process_started is False
    assert "UNTRUSTED_SELECTOR_VALUE" not in str(caught.value) + caught.value.next_action
    assert observed == [] and not log.exists()


@pytest.mark.usefixtures("strict_program")
def test_pagination_rechecks_a_replaced_executable_target(gh_effect_request, tmp_path):
    from conftest import symlink_or_skip
    from aegis_core import gitsafe
    import sys
    fd, source, log = gh_effect_request
    root = hg.make_repo(tmp_path / "owner").root
    malicious = root / "gh"
    marker = tmp_path / "second-page-program-ran"
    malicious.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
    malicious.chmod(0o700)
    alias = tmp_path / "alias-probe"
    symlink_or_skip(malicious, alias)
    alias.unlink()
    program = Path(source["PATH"]) / "gh"
    _native_program(program, "#!" + sys.executable + "\nfrom pathlib import Path\nimport os\n"
        + "p=Path(" + repr(str(program)) + ")\np.unlink()\nos.symlink(" + repr(str(malicious)) + ",p)\n"
        + "print('HTTP/1.1 200 OK\\r\\nLink: <https://api.github.com/user?page=2>; rel=\"next\"\\r\\n\\r\\n[]')\n")
    source = {**source, "PATH": source["PATH"] + os.pathsep + os.path.dirname(gitsafe.git_executable())}
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user", "--paginate"], cwd=root, env=source, effect_fds=(fd,), worktree_root=root)
    assert caught.value.code == "effect_command_refused"
    assert caught.value.process_started is True and caught.value.effect_process_started is True
    assert not marker.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("host,token", [("github.com", "GH_TOKEN"), ("git.example.com", "GH_ENTERPRISE_TOKEN")])
@pytest.mark.parametrize("change", ["delete-token", "replace", "change-host"])
def test_reused_gh_inputs_do_not_restore_removed_credentials(gh_effect_request, monkeypatch, host, token, change):
    from types import SimpleNamespace
    from aegis_core import gitsafe
    fd, source, log = gh_effect_request
    source = {"PATH": source["PATH"], "TMPDIR": source["TMPDIR"], "GH_HOST": host, token: "fixture-reuse-token"}
    observed = []
    def launch(argv, **options):
        observed.append(options["env"])
        return subprocess.Popen(argv, **options)
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": launch}))
    root = Path(__file__).resolve().parents[3]
    assert REAL_GH(["api", "user"], env=source, effect_fds=(fd,), worktree_root=root).returncode == 0
    source = observed[-1]
    if change == "delete-token":
        del source[token]
    elif change == "replace":
        source = source.with_vars({"PATH": source["PATH"], "GH_HOST": host}, replace=True)
    else:
        source["GH_HOST"] = "git.example.com" if host == "github.com" else "github.com"
    observed.clear()
    log.unlink()
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user"], env=source, effect_fds=(fd,), worktree_root=root)
    assert caught.value.code == ("gh_token_host_mismatch" if change == "change-host" else "gh_token_missing")
    assert caught.value.process_started is False and observed == [] and not log.exists()


@pytest.mark.parametrize("source", [None, {}, {"PATH": "/owner/bin"}])
def test_ordinary_gh_lookup_keeps_missing_path_empty(tmp_path, monkeypatch, source):
    from types import SimpleNamespace
    seen = []
    def which(name, **options):
        seen.append((name, options))
        return None
    monkeypatch.setattr(ghcli, "pathlookup", SimpleNamespace(which=which))
    assert REAL_GH(["api", "user"], cwd=tmp_path, env=source) is None
    assert seen == [("gh", {"outside": tmp_path, **({"path": source.get("PATH", "")} if source is not None else {})})]


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("paginate", [False, True])
def test_gh_holder_interpreter_is_fenced(gh_effect_request, tmp_path, monkeypatch, paginate):
    import sys
    from types import SimpleNamespace
    from aegis_core import gitsafe
    fd, env, log = gh_effect_request
    repo = hg.make_repo(tmp_path / "owner-root").root
    interpreter, marker = repo / "python", tmp_path / "holder-code-ran"
    interpreter.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n", encoding="utf-8")
    interpreter.chmod(0o700)
    monkeypatch.setattr(gitops_fds, "sys", SimpleNamespace(**{**vars(sys), "executable": str(interpreter)}))
    with pytest.raises(gitsafe.GitError) as caught:
        REAL_GH(["api", "user", *(["--paginate"] if paginate else [])], env=env, cwd=repo,
                effect_fds=(fd,), worktree_root=repo)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
    assert not marker.exists() and not log.exists()


@pytest.mark.usefixtures("strict_program")
@pytest.mark.parametrize("entry", ["direct", "bound", "paginate"])
@pytest.mark.parametrize("dispatch", ["absolute", "path"])
def test_script_gh_entry_refuses_before_any_child(gh_effect_request, tmp_path, monkeypatch, entry, dispatch):
    import sys
    from types import SimpleNamespace
    from aegis_core import gitsafe
    fd, source, log = gh_effect_request
    root = hg.make_repo(tmp_path / "root").root
    host = tmp_path / "host"
    host.mkdir()
    interpreter, marker = root / "model-python", tmp_path / "script-ran"
    interpreter.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n", encoding="utf-8")
    interpreter.chmod(0o700)
    script = host / "gh"
    script.write_text(("#!" + str(interpreter) if dispatch == "absolute" else "#!/usr/bin/env model-python") + "\nunused\n", encoding="utf-8")
    script.chmod(0o700)
    def forbidden(*args, **kwargs):
        pytest.fail("script gh entry started a child")
    monkeypatch.setattr(ghcli, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    args = ["api", "user", *(["--paginate"] if entry == "paginate" else [])]
    source = {**source, "PATH": str(host) + os.pathsep + source["PATH"]}
    with pytest.raises(gitsafe.GitError) as caught:
        if entry == "bound":
            ghcli.effect_runner(REAL_GH, (fd,), worktree_root=root)(args, cwd=root, env=source)
        else:
            REAL_GH(args, cwd=root, env=source, effect_fds=(fd,), worktree_root=root)
    assert caught.value.code == "effect_command_refused" and caught.value.process_started is False
    assert str(caught.value).startswith("strict effects require a native executable: ")
    assert str(caught.value).endswith(" is a script; configure the real binary")
    assert not marker.exists() and not log.exists()
