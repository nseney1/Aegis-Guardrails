"""Public lane plumbing contracts; all Git history is created by these tests."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contextlib import contextmanager
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Barrier, Event, Thread
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, gitsafe_run, team_git as tg

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
IDENTITY = tg.CommitIdentity("Lane", "lane@example.com", "1700000000 +0000")


ENV_REDIRECTS = ("GIT_TRACE", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF",
                 "GIT_CONFIG", "GIT_DIR", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY")


@pytest.mark.parametrize("key", ENV_REDIRECTS)
@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("destination", ["HEAD", "packed-refs", "index"])
@pytest.mark.parametrize("worker", [False, True], ids=["direct", "executor"])
def test_runner_environment_redirects_refuse_before_spawn(repo, monkeypatch, key, ambient, destination, worker):
    with new_store(repo) as store:
        before, calls, real = shared_bytes(repo), [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(tuple(argv))
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        value = os.devnull if key == "GIT_CONFIG" else str(repo / ".git" / destination)
        with monkeypatch.context() as scoped:
            if ambient:
                scoped.setenv(key, value)
            with pytest.raises(tg.GitRefusal) as caught:
                if worker:
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pool.submit(store._run, ["version"], extra_env=None if ambient else {key: value}).result(timeout=5)
                else:
                    store._run(["version"], extra_env=None if ambient else {key: value})
            assert caught.value.code == ("ambient_git_environment" if ambient else "git_custody_refused") and not calls
            if ambient:
                assert key in caught.value.next_action
        assert shared_bytes(repo) == before
        assert store._run(["version"]).returncode == 0


@pytest.mark.parametrize("key,style", [(key, "redirect") for key in ENV_REDIRECTS] +
    [("GIT_TRACE", "disabled"), ("GIT_DIR", "hook"), ("GIT_INDEX_FILE", "hook"), ("GIT_TRACE_MYSTERY", "unknown-trace")])
def test_runner_ambient_redirect_before_entry_refuses_and_retries(repo, monkeypatch, key, style):
    before, calls, real = shared_bytes(repo), [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with monkeypatch.context() as scoped:
        value = "0" if style == "disabled" else str(repo / ".git" / ("index" if key == "GIT_INDEX_FILE" else "")) if style == "hook" else os.devnull if key == "GIT_CONFIG" else str(repo / ".git/HEAD")
        scoped.setenv(key, value)
        with pytest.raises(tg.GitRefusal) as caught:
            with new_store(repo):
                pytest.fail("ambient redirect was accepted")
        name = "GIT_TRACE*" if style == "unknown-trace" else key
        assert caught.value.code == "ambient_git_environment" and name in caught.value.next_action and not calls
        assert "secret" not in str(caught.value) + caught.value.next_action
    assert shared_bytes(repo) == before
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0


@pytest.mark.parametrize("field,value", [("GIT_AUTHOR_NAME", "bad\x01name"), ("GIT_AUTHOR_EMAIL", "a\nb"),
    ("GIT_COMMITTER_NAME", "bad\u2028name"), ("GIT_COMMITTER_DATE", "1700000000 +9999")])
def test_runner_refuses_unvalidated_identity_before_spawn(repo, monkeypatch, field, value):
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store:
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(argv)
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        identity = tg._identity(IDENTITY)
        identity[field] = value
        with pytest.raises(tg.GitRefusal) as caught:
            store._run(["commit-tree", tree, "-p", parent], stdin=b"message\n", extra_env=identity)
        assert caught.value.code == "git_custody_refused" and not calls
        assert store._run(["commit-tree", tree, "-p", parent], stdin=b"message\n", extra_env=tg._identity(IDENTITY)).returncode == 0


@pytest.mark.parametrize("command", ["hash-object", "merge-tree"])
def test_runner_config_redirect_cannot_hide_driver_preflight(repo, monkeypatch, command):
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "config", "merge.hostile.driver", "false")
    with new_store(repo) as store:
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(tuple(argv))
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        args = ["hash-object", "-w", "--stdin", "--path=x"] if command == "hash-object" else ["merge-tree", "--write-tree", "-z", head, head]
        with pytest.raises(tg.GitRefusal) as caught:
            store._run(args, stdin=b"x" if command == "hash-object" else None, extra_env={"GIT_CONFIG": os.devnull})
        assert caught.value.code == "git_custody_refused" and not calls


@pytest.mark.parametrize("field", ["scratch", "unproved-scratch", "services", "_lane_binding"])
def test_runner_scratch_replacement_refuses_before_spawn(repo, monkeypatch, field):
    class Unproved:
        def __eq__(self, other):
            pytest.fail("unproved replacement was compared")
    @tg._lane_operation
    def operation(store, *, _runner=None):
        calls = []
        def forbidden(*args, **kwargs):
            calls.append(args)
            pytest.fail("replacement reached Popen")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        values = {"scratch": store.index_path.parent, "unproved-scratch": Unproved(), "services": object(), "_lane_binding": None}
        from aegis_core.errors import AegisError
        with pytest.raises(AegisError) as caught:
            replace(_runner, **{"scratch" if field == "unproved-scratch" else field: values[field]}).run(["read-tree", "--empty"])
        assert caught.value.code == "git_custody_refused" and not calls
    with new_store(repo) as store:
        before = shared_bytes(repo)
        operation(store)
        assert shared_bytes(repo) == before


def test_runner_default_object_writes_are_private(repo):
    @tg._lane_operation
    def operation(store, *, _runner=None):
        result = _runner.run(["hash-object", "-w", "--stdin", "--path=private.txt"], stdin=b"private only\n")
        oid = result.stdout.decode().strip()
        assert result.returncode == 0 and store.object(oid, "blob") == b"private only\n"
        assert not (repo / ".git/objects" / oid[:2] / oid[2:]).exists()
    with new_store(repo) as store:
        operation(store)


def test_runner_unknown_index_selector_refuses_before_spawn(repo, monkeypatch):
    @tg._lane_operation
    def operation(store, *, _runner=None):
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(argv)
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        with pytest.raises(gitsafe.GitError) as caught:
            _runner.run(["ls-files", "--stage", "--debug", "-z"], real_index="true")
        assert caught.value.code == "git_custody_refused" and not calls
    with new_store(repo) as store:
        operation(store)


@pytest.mark.parametrize("scenario", ["remove-attributes", "safecrlf", "nanoseconds", "device", "inode", "uid", "gid", "mtime", "racy-timestamp"])
def test_snapshot_stat_clean_blob_matches_git_add(repo, tmp_path, scenario):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        git(target, "config", "core.trustctime", "false")
        if scenario not in ("remove-attributes", "safecrlf"):
            commit(target, "clean.txt", b"one\r\ntwo\r\n")
        else:
            (target / ".gitattributes").write_bytes(b"*.txt text working-tree-encoding=UTF-16LE\n")
            git(target, "add", ".gitattributes")
            commit(target, "clean.txt", "one\r\ntwo\r\n".encode("utf-16le"))
        os.utime(target / "clean.txt", ns=(1000000000000000000, 1000000000000000000))
        git(target, "update-index", "--refresh")
        if scenario == "remove-attributes":
            git(target, "rm", "--cached", ".gitattributes")
            (target / ".gitattributes").unlink()
        elif scenario == "safecrlf":
            git(target, "config", "core.safecrlf", "true")
        elif scenario == "nanoseconds":
            (target / ".gitattributes").write_bytes(b"*.txt text\n")
            os.utime(target / "clean.txt", ns=(1000000000000000000, 1000000000000000001))
        elif scenario == "racy-timestamp":
            (target / ".gitattributes").write_bytes(b"*.txt text\n")
            os.utime(target / ".git/index", ns=(1000000000500000000, 1000000000500000000))
        else:
            import hashlib
            (target / ".gitattributes").write_bytes(b"*.txt text\n")
            index = target / ".git/index"
            raw, position = bytearray(index.read_bytes()), 12
            assert raw[:8] == b"DIRC\0\0\0\2"
            offset = {"device": 16, "inode": 20, "uid": 28, "gid": 32, "mtime": 8}[scenario]
            for _ in range(int.from_bytes(raw[8:12], "big")):
                end = raw.index(0, position + 62)
                if raw[position + 62:end] == b"clean.txt":
                    original = int.from_bytes(raw[position + offset:position + offset + 4], "big")
                    raw[position + offset:position + offset + 4] = ((original + 1) & 0xffffffff).to_bytes(4, "big")
                position += ((end + 1 - position + 7) // 8) * 8
            raw[-20:] = hashlib.sha1(raw[:-20]).digest()
            index.write_bytes(raw)
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        for _ in range(2):
            if scenario in ("nanoseconds", "device", "racy-timestamp"):
                with pytest.raises(tg.GitRefusal) as caught:
                    tg.snapshot_tree(store)
                assert caught.value.code == "index_stat_unprovable"
                assert caught.value.next_action == "Run `git update-index --refresh` in the worktree, then retry."
            else:
                assert tg.snapshot_tree(store) == expected
        if scenario in ("nanoseconds", "device", "racy-timestamp"):
            for target in (repo, oracle):
                (target / "clean.txt").write_bytes(b"a changed size\r\n")
            git(oracle, "add", "-A")
            assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


@pytest.mark.parametrize("key,value", [("core.eol", "CRLF"), ("core.eol", None), ("core.eol", "unknown"), ("core.checkStat", "MINIMAL")])
def test_snapshot_config_value_parity(repo, tmp_path, key, value):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        if value is None:
            with (target / ".git/config").open("a", encoding="utf-8") as stream:
                stream.write("\n[core]\n eol\n")
        else:
            git(target, "config", key, value)
        (target / ".gitattributes").write_bytes(b"*.txt text\n")
        (target / "new.txt").write_bytes(b"one\r\ntwo\r\n")
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("empty_prior", [False, True])
def test_snapshot_zero_size_racy_sentinel_matches_git_add(repo, tmp_path, native, empty_prior):
    import hashlib
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        git(target, "config", "core.trustctime", "false")
        git(target, "config", "index.version", "2")
        if native:
            (target / ".gitattributes").write_bytes(b"*.txt text working-tree-encoding=UTF-16LE\n")
            git(target, "add", ".gitattributes")
        commit(target, "sentinel.txt", b"" if empty_prior else "nonempty\r\n".encode("utf-16le") if native else b"nonempty\n")
        os.utime(target / "sentinel.txt", ns=(1000000000000000000, 1000000000000000000))
        git(target, "update-index", "--refresh")
        index = target / ".git/index"
        raw, position = bytearray(index.read_bytes()), 12
        assert raw[:8] == b"DIRC\0\0\0\2"
        for _ in range(int.from_bytes(raw[8:12], "big")):
            end = raw.index(0, position + 62)
            if raw[position + 62:end] == b"sentinel.txt":
                raw[position + 36:position + 40] = b"\0" * 4
            position += ((end + 1 - position + 7) // 8) * 8
        raw[-20:] = hashlib.sha1(raw[:-20]).digest()
        index.write_bytes(raw)
        (target / "sentinel.txt").write_bytes(b"")
        os.utime(target / "sentinel.txt", ns=(1000000000000000000, 1000000000000000000))
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        before = shared_bytes(repo)
        for _ in range(2):
            tree = tg.snapshot_tree(store)
            assert tree == expected and store.read_blob(tree, "sentinel.txt") == b""
        assert shared_bytes(repo) == before


@pytest.mark.parametrize("shape", ["value", "count", "name"])
def test_store_entry_environment_bounds_have_public_refusal_and_retry(repo, monkeypatch, shape):
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    environment = dict(os.environ)
    if shape == "value":
        environment["AEGIS_OVERSIZED"] = "x" * 65537
    elif shape == "name":
        environment["X" * 257] = "x"
    else:
        environment.update({"AEGIS_ENV_%d" % n: "x" for n in range(513)})
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": environment}))
    with pytest.raises(tg.GitRefusal) as caught:
        with new_store(repo):
            pytest.fail("oversized environment was accepted")
    actions = {"value": "Reduce every environment value to at most 65,536 characters, then retry.",
               "count": "Reduce the environment to at most 512 variables, then retry.",
               "name": "Shorten every environment variable name to at most 256 characters, then retry."}
    assert caught.value.code == "ambient_environment_too_large" and caught.value.next_action == actions[shape] and not calls
    if shape == "value":
        environment["AEGIS_OVERSIZED"] = "x" * 65536
    elif shape == "name":
        environment["X" * 256] = environment.pop("X" * 257)
    else:
        for key in list(environment):
            if key.startswith("AEGIS_ENV_"):
                del environment[key]
        environment.update({"AEGIS_ENV_%d" % n: "x" for n in range(512 - len(environment))})
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0
    monkeypatch.setattr(gitsafe_run, "os", os)
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0


def strict_request(repo, scratch, args, entry, *, stdin=None, env=None):
    """Exercise both public strict initialization paths, with an owned envelope."""
    with gitsafe.custody(scratch=scratch, strict_lane=True):
        if entry == "run":
            return gitsafe.run(args, repo, stdin=stdin, _env=env)
        envelope = gitsafe.lane_runner(repo, scratch).environment(env, args=args)
        argv = [gitsafe.custody_program(repo), *gitsafe_run.DEFAULT_HARDENING, *gitsafe_run._LANE_OPTIONS, *args]
        return gitsafe_run.capture(argv, cwd=repo, env=envelope, stdin=stdin, timeout=10)


@pytest.mark.parametrize("entry", ["run", "capture"])
@pytest.mark.parametrize("worker", [False, True], ids=["direct", "executor"])
def test_fresh_strict_runner_binds_common_objects_and_keeps_writes_private(repo, tmp_path, monkeypatch, entry, worker):
    scratch = tmp_path / "strict-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    before, calls, real = shared_bytes(repo), [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append((tuple(argv), dict(kwargs["env"])))
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    def invoke(args, **kwargs):
        return strict_request(repo, scratch, args, entry, **kwargs)
    if worker:
        with ThreadPoolExecutor(max_workers=2) as pool:
            answers = [future.result(timeout=10) for future in
                       [pool.submit(invoke, ["cat-file", "-t", head]) for _ in range(2)]]
    else:
        answers = [invoke(["cat-file", "-t", head])]
    assert all(answer.returncode == 0 and answer.stdout == b"commit\n" for answer in answers)
    made = invoke(["commit-tree", tree, "-p", head], stdin=b"private commit\n", env=tg._identity(IDENTITY))
    assert made.returncode == 0
    oid = made.stdout.decode().strip()
    assert invoke(["cat-file", "-t", oid]).stdout == b"commit\n"
    assert not (repo / ".git/objects" / oid[:2] / oid[2:]).exists()
    targets = [env for argv, env in calls if "cat-file" in argv or "commit-tree" in argv]
    assert targets and all(env["GIT_OBJECT_DIRECTORY"] == str(scratch / "objects")
                           and "GIT_ALTERNATE_OBJECT_DIRECTORIES" in env for env in targets)
    assert shared_bytes(repo) == before


def test_cold_lane_runner_common_binding_is_atomic_across_workers(repo, tmp_path, monkeypatch):
    scratch = tmp_path / "cold-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    runner = gitsafe.lane_runner(repo, scratch)
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(tuple(argv))
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(runner.run, ["cat-file", "-t", head]) for _ in range(2)]
        answers = [future.result(timeout=10) for future in futures]
    assert all(answer.returncode == 0 and answer.stdout == b"commit\n" for answer in answers)
    assert runner.run(["cat-file", "-t", head]).stdout == b"commit\n"
    assert len(calls) == 3 and all("cat-file" in argv for argv in calls)


@pytest.mark.parametrize("entry", ["run", "capture"])
@pytest.mark.parametrize("code", ["git_failed", "git_timeout", "os-error", "path-error"])
def test_fresh_strict_binding_failure_preserves_code_and_retries(repo, tmp_path, monkeypatch, entry, code):
    scratch = tmp_path / "failing-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    fail, calls, real_popen = [True], [], subprocess.Popen
    def record(argv, **kwargs):
        if fail[0] and tuple(argv[-2:]) == ("rev-parse", "--git-common-dir"):
            if code == "os-error":
                raise OSError("Metadata fixture I/O failure.")
            if code == "path-error":
                raise RuntimeError("Metadata fixture resolution failure.")
            raise gitsafe.GitError("Metadata fixture refusal.", code=code, process_started=False)
        calls.append(argv)
        return real_popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    before = shared_bytes(repo)
    with pytest.raises(gitsafe.GitError) as caught:
        strict_request(repo, scratch, ["cat-file", "-t", head], entry)
    assert caught.value.code == ("git_failed" if code.endswith("-error") else code)
    assert not any("cat-file" in argv for argv in calls)
    fail[0] = False
    assert strict_request(repo, scratch, ["cat-file", "-t", head], entry).stdout == b"commit\n"
    assert shared_bytes(repo) == before


def test_linked_worktree_symlink_scratch_cannot_name_common_git_dir(repo, tmp_path, monkeypatch):
    make_store(repo)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "--detach", str(linked), "HEAD")
    common, alias = repo / ".git", tmp_path / "scratch-alias"
    common.chmod(0o700)
    symlink_or_skip(common, alias)
    before, calls, real = shared_bytes(repo), [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with pytest.raises(tg.GitRefusal) as caught:
        with tg.GitStore(linked, alias):
            pytest.fail("common Git directory was accepted as scratch")
    assert caught.value.code == "unsafe_scratch" and not any("read-tree" in argv for argv in calls)
    assert shared_bytes(repo) == before


def test_ambient_refusal_is_deterministic_and_lists_every_exact_key(repo, tmp_path):
    scratch = tmp_path / "hash-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    script = """import json,sys
from pathlib import Path
from aegis_core import gitsafe
try:
    gitsafe.lane_runner(Path(sys.argv[1]), Path(sys.argv[2])).run(['version'])
except gitsafe.GitError as exc:
    print(json.dumps([exc.code,str(exc),getattr(exc,'next_action',None)],ensure_ascii=True))
"""
    keys = ["GIT_DIR", "GIT_INDEX_FILE", "GIT_PREFIX", "GIT_TRACE", "GIT_TRACE_MYSTERY", "GIT_TRACE_OTHER"]
    environment = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    environment.update({key: "0" for key in keys})
    answers = []
    for seed in ("1", "2", "3", "4", "5", "6"):
        result = subprocess.run([sys.executable, "-B", "-c", script, str(repo), str(scratch)],
            cwd=Path(__file__).resolve().parents[3], env={**environment, "PYTHONHASHSEED": seed},
            check=True, capture_output=True, timeout=15)
        answers.append(result.stdout)
    assert len(set(answers)) == 1
    code, message, action = json.loads(answers[0])
    assert code == "ambient_git_environment" and "GIT_TRACE*" in message + action
    for field in (message, action):
        assert all(key in field for key in keys)
        assert [field.index(key) for key in sorted(keys)] == sorted(field.index(key) for key in keys)
        assert "GIT_TRACE* (GIT_TRACE_MYSTERY)" in field and "GIT_TRACE* (GIT_TRACE_OTHER)" in field
        assert "GIT_TRACE* (GIT_DIR" not in field and "GIT_TRACE* (GIT_TRACE)" not in field


@pytest.mark.skipif(os.name != "posix", reason="POSIX environment keys are case-sensitive")
def test_ambient_lowercase_key_refuses_with_its_real_spelling(repo, monkeypatch):
    environment = {**os.environ, "git_dir": "not-a-repository"}
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": environment}))
    with pytest.raises(tg.GitRefusal) as caught:
        with new_store(repo):
            pytest.fail("lowercase redirect was accepted")
    assert caught.value.code == "ambient_git_environment"
    assert "git_dir" in caught.value.next_action and "GIT_DIR" not in caught.value.next_action


def test_ambient_key_diagnostics_canonicalize_and_redact_before_display(repo, monkeypatch):
    secret = "ghp_" + "a" * 24
    key = "GIT_TRACE_\x1b[31m" + secret
    environment = {**os.environ, key: "never-display-this-value"}
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": environment}))
    with pytest.raises(gitsafe.GitError) as caught:
        gitsafe.lane_runner(repo, repo.parent / "refused-scratch")
    for field in (str(caught.value), caught.value.next_action):
        assert "GIT_TRACE*" in field and "[REDACTED_VCS_TOKEN]" in field
        assert secret not in field and "\x1b" not in field and "never-display-this-value" not in field


@pytest.mark.parametrize("failure", [KeyError, RuntimeError])
def test_ambient_environment_disappearing_during_snapshot_has_a_public_refusal(repo, monkeypatch, failure):
    class ChangingEnvironment:
        def __len__(self):
            return 1
        def items(self):
            raise failure("private environment data")
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        pytest.fail("unstable environment reached a process")
    environment_type = gitsafe_run._ENVIRON_TYPE
    monkeypatch.setattr(gitsafe_run, "_ENVIRON_TYPE", ChangingEnvironment)
    monkeypatch.setattr(gitsafe_run, "os", SimpleNamespace(**{**vars(os), "environ": ChangingEnvironment()}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    try:
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.lane_runner(repo, repo.parent / "refused-scratch")
        assert caught.value.code == "ambient_environment_changed" and not calls
        assert caught.value.next_action == "Stabilize the environment, then retry."
        assert "private environment data" not in str(caught.value) + caught.value.next_action
    finally:
        monkeypatch.setattr(gitsafe_run, "_ENVIRON_TYPE", environment_type)
        monkeypatch.setattr(gitsafe_run, "os", os)
        monkeypatch.setattr(gitsafe_run, "subprocess", subprocess)
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0


def test_issued_runner_real_index_is_correct_on_the_first_call(repo, tmp_path):
    scratch = tmp_path / "issued-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    expected = git(repo, "ls-files", "--stage", "--debug", "-z")
    assert expected and not (scratch / "index").exists()
    runner = gitsafe.lane_runner(repo, scratch)
    first = runner.run(["ls-files", "--stage", "--debug", "-z"], real_index=True)
    assert first.returncode == 0 and first.stdout == expected
    assert runner.run(["ls-files", "--stage", "--debug", "-z"]).stdout == b""
    assert runner.run(["ls-files", "--stage", "--debug", "-z"], real_index=True).stdout == expected


@pytest.mark.parametrize("entry", ["lane_runner", "run", "publish", "store"])
def test_missing_fenced_git_refuses_before_discovery_and_retries(repo, tmp_path, monkeypatch, entry):
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(tuple(argv))
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    lookup = gitsafe.custody_program
    monkeypatch.setattr("aegis_core.gitsafe.custody_program", lambda cwd: None)
    try:
        with pytest.raises(gitsafe.GitError) as caught:
            if entry == "run":
                with gitsafe.custody(scratch=tmp_path, strict_lane=True):
                    gitsafe.run(["version"], repo)
            elif entry == "store":
                with new_store(repo):
                    pytest.fail("unavailable Git was accepted")
            else:
                runner = gitsafe.lane_runner(repo, tmp_path)
                if entry == "publish":
                    runner.publish(b"")
        assert caught.value.code == "git_custody_refused" and not calls
    finally:
        monkeypatch.setattr("aegis_core.gitsafe.custody_program", lookup)
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0


def test_direct_capture_accepts_an_issued_envelope(repo, tmp_path):
    scratch = tmp_path / "envelope-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    runner = gitsafe.lane_runner(repo, scratch)
    runner.paths()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    args = ["cat-file", "-t", head]
    environment = runner.environment(args=args)
    argv = [gitsafe.custody_program(repo), *gitsafe_run.DEFAULT_HARDENING, *gitsafe_run._LANE_OPTIONS, *args]
    with gitsafe.custody(scratch=scratch, strict_lane=True):
        result = gitsafe_run.capture(argv, cwd=repo, env=environment, stdin=None, timeout=10)
    assert result.returncode == 0 and result.stdout == b"commit\n"


def test_cold_publish_uses_private_destination_and_explicit_shared_publication(repo, tmp_path):
    scratch, donor = tmp_path / "publish-scratch", tmp_path / "donor"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    donor.mkdir()
    git(donor, "init", "-q", "-b", "main")
    oid = git(donor, "hash-object", "-w", "--stdin", data=b"private published blob\n").strip()
    pack = git(donor, "pack-objects", "--stdout", data=oid + b"\n")
    runner = gitsafe.lane_runner(repo, scratch)
    before = shared_bytes(repo)
    result = runner.publish(pack)
    assert result.returncode == 0
    assert shared_bytes(repo) == before
    assert runner.run(["cat-file", "blob", oid.decode()]).stdout == b"private published blob\n"
    assert runner.publish(pack, shared=True).returncode == 0
    assert (repo / ".git/objects" / oid[:2].decode() / oid[2:].decode()).is_file()


@pytest.mark.parametrize("entry", ["run", "capture", "execute", "update_ref", "empty_update_ref", "lane_runner", "publish", "store"])
def test_relative_cwd_public_routes_share_the_git_error_hierarchy(repo, tmp_path, entry):
    scratch = tmp_path / "relative-scratch"
    scratch.mkdir(mode=0o700)
    (scratch / "objects").mkdir()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    with gitsafe.custody(scratch=scratch, strict_lane=True):
        with pytest.raises(gitsafe.GitError) as caught:
            if entry == "run":
                gitsafe.run(["version"], ".")
            elif entry == "capture":
                gitsafe_run.capture([gitsafe.custody_program(repo), *gitsafe_run.DEFAULT_HARDENING,
                    *gitsafe_run._LANE_OPTIONS, "version"], cwd=".", env={}, stdin=None, timeout=10)
            elif entry == "execute":
                gitsafe_run.execute(["version"], ".", executable=gitsafe.git_executable,
                    legacy_runner=subprocess.run, error=gitsafe.GitError, environ=os.environ,
                    timeout=10, stdin=None, hardening=gitsafe_run.DEFAULT_HARDENING, env=None, tty=False)
            elif entry in ("update_ref", "empty_update_ref"):
                gitsafe.update_ref(".", "refs/aegis/relative", head if entry == "update_ref" else None, None)
            elif entry == "lane_runner":
                gitsafe.lane_runner(".", scratch)
            elif entry == "publish":
                gitsafe.lane_runner(".", scratch).publish(b"")
            else:
                with tg.GitStore(".", scratch):
                    pytest.fail("relative store was accepted")
    if entry == "store":
        assert caught.value.code == "invalid_repository"
    else:
        assert caught.value.code == "git_custody_refused"
        assert caught.value.next_action == "Use the lane Git APIs or the CAS fast-forward writer."


RUNTIME_BYPASSES = {
    "keyword": "gitsafe.run(args=bad, cwd=root)",
    "bare-import": "from aegis_core.gitsafe import run\nrun(bad, root)",
    "module-alias": "import aegis_core.gitsafe as g\ng.run(bad, root)",
    "checked-keyword": "gitsafe.run_checked(args=bad, cwd=root)",
    "starred": "gitsafe.run([*bad], root)",
    "positional-hardening": "gitsafe.run(['version', ref, oid], root, 10, None, ['update-ref', '-m'])",
    "same-line": "argv = ['version']; argv[:] = bad; gitsafe.run(argv, root)",
    "local-import-shadow": "def first():\n from aegis_core import gitsafe as g\n g.run(bad, root)\ndef other():\n import math as g\nfirst()",
    "transport-callback": "gitsafe_run.checked(bad, root, runner=gitsafe.run, error=ValueError, git_error=gitsafe.GitError, timeout=10, stdin=None)",
    "loop-carried": "argv = ['version']\nfor index in range(2):\n if index: gitsafe.run(argv, root)\n argv = bad",
    "for-binding": "for argv in (bad,):\n gitsafe.run(argv, root)",
    "with-binding": "with nullcontext(bad) as argv:\n gitsafe.run(argv, root)",
    "walrus-binding": "if (argv := bad):\n gitsafe.run(argv, root)",
    "parameter-shadow": "argv = ['version']\ndef send(argv):\n gitsafe.run(argv, root)\nsend(bad)",
    "alias-slice": "argv = ['version']\nalias = argv\nalias[:] = bad\ngitsafe.run(argv, root)",
    "cross-function": "argv = ['version']\ndef change():\n argv[:] = bad\nchange()\ngitsafe.run(argv, root)",
    "git-helper": "argv = ['version']\ndef _git(argv):\n return gitsafe.run(argv, root)\n_git(bad)",
    "config-override": "gitsafe.run(['-c', 'core.hooksPath=evil', 'version'], root)",
    "root-override": "gitsafe.run(['-C', '.', 'version'], root)",
    "unknown-command": "gitsafe.run(['unknown-command'], root)",
    "raw-capture": "gitsafe_run.capture([gitsafe.git_executable(), *gitsafe_run.DEFAULT_HARDENING, *bad], cwd=root, env=dict(os.environ), stdin=None, timeout=10)",
    "kwargs-forward": "options = {'args': bad, 'cwd': root}\ngitsafe.run(**options)",
    "callable-alias": "module = gitsafe\nrunner = module.run\nrunner(bad, root)",
    "partial": "from functools import partial\npartial(gitsafe.run, args=bad, cwd=root)()",
    "getattr": "getattr(gitsafe, 'run')(bad, root)",
    "bad-environment": "gitsafe.run(['version'], root, _env={1: object()})",
    "bad-cwd": "gitsafe.run(['version'], object())",
}


@pytest.mark.parametrize("form", sorted(RUNTIME_BYPASSES))
def test_strict_custody_refuses_runtime_rebinding_before_spawn(repo, tmp_path, monkeypatch, form):
    from contextlib import nullcontext
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    spawns = []
    def forbidden(argv, **kwargs):
        spawns.append(argv)
        pytest.fail("unapproved command reached the spawn boundary")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    namespace = dict(gitsafe=gitsafe, gitsafe_run=gitsafe_run, root=repo, oid=oid,
                     ref="refs/heads/main", bad=["update-ref", "refs/heads/main", oid],
                     os=os, nullcontext=nullcontext)
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        with pytest.raises(gitsafe.GitError) as caught:
            exec(RUNTIME_BYPASSES[form], namespace)
        assert caught.value.code == "git_custody_refused"
        assert caught.value.next_action == "Use the lane Git APIs or the CAS fast-forward writer."
        assert not spawns


def test_strict_custody_is_inherited_and_legacy_custody_stays_unchanged(repo, tmp_path, monkeypatch):
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        with gitsafe.custody(scratch=tmp_path, strict_lane=False):
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run(["update-ref", "refs/heads/main", oid], repo)
            assert caught.value.code == "git_custody_refused"
            assert not calls
    with gitsafe.custody(scratch=tmp_path):
        assert gitsafe.run(["update-ref", "refs/aegis/legacy", oid], repo).returncode == 0
    assert len(calls) == 1


def test_strict_cas_exemption_is_single_use_and_never_leaks(repo, tmp_path, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    new = commit(repo, "next", b"next\n")
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        assert gitsafe.update_ref(repo, "refs/heads/lane/runtime", parent, None) == "updated"
        assert gitsafe.update_ref(repo, "refs/heads/lane/runtime", new, parent) == "updated"
        assert gitsafe.update_ref(repo, "refs/heads/lane/runtime", new, parent) == "already"
        assert sum("update-ref" in a for a in calls) == 2
        calls.clear()
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.run(["update-ref", "--no-deref", "-z", "--stdin"], repo,
                        stdin=b"update refs/heads/lane/runtime\0" + parent.encode() + b"\0" + new.encode() + b"\0")
        assert caught.value.code == "git_custody_refused"
        assert not calls


def test_strict_mode_is_context_local_during_concurrent_legacy_work(repo, tmp_path, monkeypatch):
    ready, release = Event(), Event()
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append((gitsafe_run.strict_active(), argv))
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    def strict_worker():
        with gitsafe.custody(scratch=tmp_path, strict_lane=True):
            ready.set()
            assert release.wait(5), "legacy control never released the worker"
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run(["update-ref", "refs/heads/main", "0" * 40], repo)
            return caught.value.code
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(strict_worker)
        try:
            assert ready.wait(5), "strict worker never entered custody"
            with gitsafe.custody(scratch=tmp_path):
                assert gitsafe.run(["version"], repo).returncode == 0
        finally:
            release.set()
        assert future.result(timeout=5) == "git_custody_refused"
    assert len(calls) == 1 and calls[0][0] is False


def test_cas_grant_is_consumed_before_popen_callback(repo, tmp_path, monkeypatch):
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    calls, denied, real = [], [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        if "update-ref" in argv:
            source = kwargs["stdin"]
            transaction = source.read()
            source.seek(0)
            before = len(calls)
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run(["update-ref", "--no-deref", "-z", "--stdin"], repo, stdin=transaction)
            assert caught.value.code == "git_custody_refused"
            assert len(calls) == before
            denied.append(True)
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        assert gitsafe.update_ref(repo, "refs/aegis/callback", oid, None) == "updated"
    assert denied == [True]


def test_all_public_lane_work_uses_explicit_runner(repo, monkeypatch):
    context = make_store(repo)
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    calls, bound, real, capture = [], [], subprocess.Popen, gitsafe_run.capture
    def record(argv, **kwargs):
        calls.append((gitsafe_run.strict_active(), argv))
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    def observed(*args, **kwargs):
        bound.append((kwargs.get("_lane"), args[0]))
        return capture(*args, **kwargs)
    monkeypatch.setattr(gitsafe_run, "capture", observed)
    with context as store:
        (repo / "new").write_bytes(b"new\n")
        tree = tg.snapshot_tree(store)
        head = tg.commit_tested(store, tree, parent, "test", IDENTITY)
        assert store.read_blob(tree, "new") == b"new\n"
        assert tg.plan_merge(store, parent, head).status == "clean"
        assert tg.plan_pick(store, parent, (head,), IDENTITY).status == "clean"
        assert tg.cas_fast_forward(store, "refs/heads/lane/strict", None, head) == "updated"
    assert calls and len(calls) == len(bound)
    bootstrap = [(runner, argv) for runner, argv in bound if runner is None]
    assert len(bootstrap) == 4 and all("rev-parse" in argv for _, argv in bootstrap)
    assert all(isinstance(runner, gitsafe_run.LaneRunner) for runner, _ in bound if runner is not None)


def test_strict_argv_bounds_precede_expansion_and_input_scratch(repo, tmp_path, monkeypatch):
    class Unbounded(list):
        def __iter__(self):
            pytest.fail("unproved argv was expanded")
    def forbidden(*args, **kwargs):
        pytest.fail("refusal allocated process input or started a process")
    monkeypatch.setattr(gitsafe_run, "tempfile", SimpleNamespace(**{**vars(tempfile), "TemporaryFile": forbidden}))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        for argv in (Unbounded(), ["version"] * 513, ["version", "x" * 16385]):
            with pytest.raises(gitsafe.GitError) as caught:
                gitsafe.run(argv, repo, stdin=b"input")
            assert caught.value.code == "git_custody_refused"


def test_capture_freezes_validated_argv_and_environment_before_input_preparation(repo, tmp_path, monkeypatch):
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append((tuple(argv), kwargs["env"].get("HOME")))
        assert "update-ref" not in argv, "argv changed after the runtime check"
        return real(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
    with gitsafe.custody(scratch=tmp_path, strict_lane=True):
        assert gitsafe.run(["version"], repo).returncode == 0
        argv = list(next(argv for argv, _ in calls if argv[-1] == "version"))
        environment = gitsafe.lane_runner(repo, tmp_path).environment(args=("version",))
        calls.clear()
        original_home = environment.get("HOME")
        def mutate(*args, **kwargs):
            argv[-1:] = ["update-ref", "refs/heads/main", "0" * 40]
            environment["HOME"] = "after"
            return tempfile.TemporaryFile(*args, **kwargs)
        monkeypatch.setattr(gitsafe_run, "tempfile", SimpleNamespace(**{**vars(tempfile), "TemporaryFile": mutate}))
        result = gitsafe_run.capture(argv, cwd=repo, env=environment, stdin=b"input", timeout=10)
    assert result.returncode == 0
    assert "update-ref" in argv and environment["HOME"] == "after"
    targets = [(argv, home) for argv, home in calls if argv[-1] == "version"]
    assert len(targets) == 1 and targets[0][1] == original_home


def patch_lane_run(monkeypatch, replacement):
    """Mock the bound external-process adapter with a statically known target."""
    original = gitsafe_run.LaneRunner.run
    def call(runner, *args, **kwargs):
        return replacement(original.__get__(runner), *args, **kwargs)
    monkeypatch.setattr(gitsafe_run.LaneRunner, "run", call)
    return lambda: monkeypatch.setattr(gitsafe_run.LaneRunner, "run", original)


def patch_lane_objects(monkeypatch, replacement):
    """Mock the bound external-process adapter with a statically known target."""
    original = gitsafe_run.LaneRunner.read_private_objects
    def call(runner, *args, **kwargs):
        return replacement(original.__get__(runner), *args, **kwargs)
    monkeypatch.setattr(gitsafe_run.LaneRunner, "read_private_objects", call)
    return lambda: monkeypatch.setattr(gitsafe_run.LaneRunner, "read_private_objects", original)




def git(repo, *args, data=None):
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "-c", "commit.gpgsign=false", *args], cwd=str(repo), input=data,
        capture_output=True, check=True).stdout


def commit(repo, name, content):
    (repo / name).write_bytes(content)
    git(repo, "add", "--", name)
    git(repo, "commit", "-qm", "change " + name)
    return git(repo, "rev-parse", "HEAD").decode().strip()


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    commit(path, "x", b"base\n")
    return path


def make_store(repo):
    if not tg.descriptor_support():
        pytest.skip("snapshot requires descriptor-relative no-follow opens")
    return new_store(repo)


@contextmanager
def new_store(repo):
    # Custody service provisions scratch; tests own its creation and cleanup.
    with tempfile.TemporaryDirectory(dir=repo.parent) as directory:
        scratch = Path(directory)
        (scratch / "objects").mkdir(mode=0o700)
        with tg.GitStore(repo, scratch) as store:
            yield store


def refs(repo):
    return git(repo, "show-ref")


def shared_bytes(repo):
    root = repo / ".git"
    return {str(p.relative_to(root)): p.read_bytes()
            for p in root.rglob("*") if p.is_file()}


def test_snapshot_preserves_first_dirty_path_and_all_shared_bytes(repo):
    context = make_store(repo)  # Guard before creating a POSIX-only filename.
    (repo / "x").write_bytes(b"changed\n")
    (repo / "space name\nnext").write_bytes(b"new\n")
    before = shared_bytes(repo)
    with context as store:
        tree = tg.snapshot_tree(store)
        assert store.read_blob(tree, "x") == b"changed\n"
        assert store.read_blob(tree, "space name\nnext") == b"new\n"
        assert tg.snapshot_tree(store) == tree
    assert shared_bytes(repo) == before


def test_snapshot_deletion_and_index_independence(repo):
    git(repo, "rm", "--cached", "x")
    before = shared_bytes(repo)
    with make_store(repo) as store:
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"
        (repo / "x").unlink()
        tree = tg.snapshot_tree(store)
        assert store._run(["ls-tree", "-r", tree]).stdout == b""
    assert shared_bytes(repo) == before


@pytest.mark.parametrize("direction", ["file-to-directory", "directory-to-file"])
def test_snapshot_records_file_directory_replacements_and_retries(repo, direction):
    context = make_store(repo)
    if direction == "directory-to-file":
        (repo / "a").mkdir()
        commit(repo, "a/b", b"old child")
        (repo / "a/b").unlink()
        (repo / "a").rmdir()
        (repo / "a").write_bytes(b"new leaf")
        wanted = "a"
    else:
        commit(repo, "a", b"old leaf")
        (repo / "a").unlink()
        (repo / "a").mkdir()
        (repo / "a/b").write_bytes(b"new leaf")
        wanted = "a/b"
    before = shared_bytes(repo)
    with context as store:
        tree = tg.snapshot_tree(store)
        assert store.read_blob(tree, wanted) == b"new leaf"
        assert tg.snapshot_tree(store) == tree
    assert shared_bytes(repo) == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX permits colon and backslash filenames")
@pytest.mark.parametrize("name", ["C:secret", "bad\\name"])
def test_snapshot_and_blob_read_accept_posix_filename_characters(repo, name):
    context = make_store(repo)
    (repo / name).write_bytes(b"legal path")
    with context as store:
        assert store.read_blob(tg.snapshot_tree(store), name) == b"legal path"


def test_snapshot_platform_refusal(repo, monkeypatch):
    monkeypatch.setattr(tg, "descriptor_support", lambda: False)
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.snapshot_tree(store)
    assert caught.value.code == "unsupported_platform"


def test_snapshot_size_cap_precedes_read(repo, monkeypatch):
    monkeypatch.setattr(tg, "MAX_FILE_BYTES", 2)
    with make_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.snapshot_tree(store)
    assert caught.value.code == "size_limit"


def symlink_or_skip(target, link):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def test_snapshot_refuses_symlink_parent(repo, tmp_path):
    (repo / "dir").mkdir()
    commit(repo, "dir/file", b"inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"secret")
    (repo / "dir/file").unlink()
    (repo / "dir").rmdir()
    symlink_or_skip(outside, repo / "dir")
    with make_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.snapshot_tree(store)
    assert caught.value.code == "unsafe_path"
    assert "secret" not in str(caught.value)


def test_deterministic_unsigned_commit_and_cas_retry(repo):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "branch", "lane/test")
    git(repo, "config", "commit.gpgsign", "true")
    before = shared_bytes(repo)
    with make_store(repo) as store:
        tree = tg.snapshot_tree(store)
        first = tg.commit_tested(store, tree, parent, "fixed\n", IDENTITY)
        assert tg.commit_tested(store, tree, parent, "fixed\n", IDENTITY) == first
        assert b"gpgsig" not in store._run(["cat-file", "commit", first]).stdout
        assert shared_bytes(repo) == before
        assert tg.cas_fast_forward(store, "refs/heads/lane/test", parent, first) == "updated"
        assert tg.cas_fast_forward(store, "refs/heads/lane/test", parent, first) == "already"
    assert git(repo, "show", "lane/test:x") == b"base\n"


@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/tags/no", "HEAD", "refs/heads/lane/../main"])
def test_ref_allowlist_refuses_without_effects(repo, ref):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    before = shared_bytes(repo)
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.cas_fast_forward(store, ref, parent, parent)
    assert caught.value.code == "ref_not_allowed"
    assert shared_bytes(repo) == before


def test_cas_mismatch_and_non_fast_forward_have_zero_effects(repo):
    first = git(repo, "rev-parse", "HEAD").decode().strip()
    second = commit(repo, "x", b"second")
    git(repo, "branch", "lane/test", second)
    before = shared_bytes(repo)
    with new_store(repo) as store:
        for old, new, code in [(first, first, "cas_mismatch"), (second, first, "not_fast_forward")]:
            with pytest.raises(tg.GitRefusal) as caught:
                tg.cas_fast_forward(store, "refs/heads/lane/test", old, new)
            assert caught.value.code == code
    assert shared_bytes(repo) == before


def test_concurrent_cas_has_one_winner(repo):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "branch", "lane/race")
    with new_store(repo) as store:
        tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
        heads = [tg.commit_tested(store, tree, parent, message, IDENTITY) for message in ("one", "two")]
        def move(head):
            try:
                return tg.cas_fast_forward(store, "refs/heads/lane/race", parent, head)
            except tg.GitRefusal as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(move, heads))
        assert sorted(results) == ["cas_mismatch", "updated"]


def test_planners_merge_pick_revert_and_reland(repo):
    base = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "checkout", "-qb", "topic")
    source = commit(repo, "feature", b"feature\n")
    git(repo, "checkout", "-q", "main")
    tip = commit(repo, "other", b"other\n")
    before = refs(repo)
    with new_store(repo) as store:
        plan = tg.plan_merge(store, tip, source)
        assert plan.status == "clean"
        expected = git(repo, "merge-tree", "--write-tree", tip, source).decode().splitlines()[0]
        assert plan.tree == expected
        merge = tg.commit_tested(store, plan.tree, (tip, source), "merge", IDENTITY)
        reverted = tg.plan_revert(store, merge, merge)
        assert reverted.tree == git(repo, "rev-parse", tip + "^{tree}").decode().strip()
        revert_commit = tg.commit_tested(store, reverted.tree, merge, "revert", IDENTITY)
        picked = tg.plan_pick(store, revert_commit, (merge,), IDENTITY)
        assert picked.status == "clean" and len(picked.commits) == 1
        assert picked.tree == plan.tree
        assert picked.commits[0] != source
        text = store._run(["cat-file", "commit", picked.commits[0]]).stdout
        assert ("(cherry picked from commit " + source + ")").encode() in text
        assert tg.plan_pick(store, revert_commit, (merge,), IDENTITY) == picked
    assert refs(repo) == before


def test_conflict_reports_paths_and_never_moves_refs(repo):
    git(repo, "checkout", "-qb", "topic")
    source = commit(repo, "x", b"topic\n")
    git(repo, "checkout", "-q", "main")
    tip = commit(repo, "x", b"main\n")
    before = shared_bytes(repo)
    with new_store(repo) as store:
        for plan in (tg.plan_merge(store, tip, source), tg.plan_pick(store, tip, (source,), IDENTITY)):
            assert plan.status == "conflict" and plan.conflicts == ("x",)
            assert not plan.commits
    assert shared_bytes(repo) == before


@pytest.mark.parametrize("message", ["bad\0message", "x" * (tg.MAX_MESSAGE_BYTES + 1), "ok\nAegis-Approve: yes"],
                         ids=["nul", "oversized", "approval"])
def test_commit_message_refusals(repo, message):
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.commit_tested(store, "0" * 40, "0" * 40, message, IDENTITY)
    assert caught.value.code == "invalid_message"


@pytest.mark.parametrize("separator", ["\n", "\r", "\x85", "\u2028", "\u2029"],
                         ids=["lf", "cr", "nel", "line-separator", "paragraph-separator"])
def test_identity_refuses_multiline(repo, separator):
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.commit_tested(store, "0" * 40, "0" * 40, "ok", tg.CommitIdentity("a" + separator + "b", "x@y", "1700000000 +0000"))
    assert caught.value.code == "invalid_identity"


def test_git_failure_is_documented_and_does_not_echo(repo, monkeypatch):
    with new_store(repo) as store:
        def fail(real, *args, **kwargs):
            raise gitsafe.GitError("token=secret hostile\ntext")
        restore = patch_lane_run(monkeypatch, fail)
        with pytest.raises(tg.GitRefusal) as caught:
            store._run(["version"])
        assert caught.value.code == "git_failed"
        assert "secret" not in str(caught.value)


def test_single_ref_writer_and_no_force_by_construction():
    from tests.unit.core.test_gitsafe import _run_subcommand_offenders
    source = Path(tg.__file__).read_text(encoding="utf-8")
    assert not _run_subcommand_offenders("aegis_core/team_git.py", source)
    tree = ast.parse(source)
    writers = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr == "cas"]
    assert len(writers) == 1
    assert not any(flag in source for flag in ("--force", "--force-with-lease", "+refspec"))


@pytest.mark.parametrize("setting", ["text-auto", "autocrlf-true", "autocrlf-input", "text", "text-crlf", "binary"])
@pytest.mark.parametrize("baseline", ["crlf", "lf", "absent", "staged-crlf"])
def test_snapshot_matches_real_git_add_with_baseline(repo, tmp_path, setting, baseline):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    if baseline != "absent":
        commit(repo, "line.txt", b"one\r\ntwo\r\n" if baseline == "crlf" else b"one\ntwo\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    attributes = {"text-auto": b"line.txt text=auto\nnew.txt text=auto\n", "text": b"*.txt text\n",
                  "text-crlf": b"*.txt text eol=crlf\n", "binary": b"*.txt -text\n"}.get(setting, b"")
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", setting.split("-", 1)[1] if setting.startswith("autocrlf") else "false")
        git(target, "config", "core.safecrlf", "false")
        (target / ".gitattributes").write_bytes(attributes)
        if baseline == "staged-crlf":
            oid = git(target, "hash-object", "-w", "--stdin", "--no-filters", data=b"one\r\ntwo\r\n").strip()
            git(target, "update-index", "--cacheinfo", "100644," + oid.decode() + ",line.txt")
        (target / "line.txt").write_bytes(b"one\r\ntwo\r\n")
        (target / "new.txt").write_bytes(b"new\r\nfile\r\n")
    before = shared_bytes(repo)
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected
    assert shared_bytes(repo) == before


@pytest.mark.parametrize("state", ["root-deleted", "nested-deleted", "head-only", "added-after-crlf"])
@pytest.mark.parametrize("native", [False, True], ids=["text", "native"])
def test_snapshot_attributes_use_real_index_and_match_git_add(repo, tmp_path, state, native):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    prefix = "nested/" if state == "nested-deleted" else ""
    (repo / "nested").mkdir(exist_ok=True)
    commit(repo, prefix + "file.txt", b"one\r\ntwo\r\n")
    attr = prefix + ".gitattributes"
    content = b"*.txt text" + (b" working-tree-encoding=UTF-16LE" if native else b"") + b"\n"
    oracle = tmp_path / "oracle"
    git(tmp_path, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        os.utime(target / (prefix + "file.txt"), (1000000000, 1000000000))
        git(target, "update-index", "--refresh")
        (target / attr).write_bytes(content)
        git(target, "add", "--", attr)
        git(target, "commit", "-qm", "attributes added without renormalizing content")
        if state != "added-after-crlf":
            git(target, "rm", "--cached", "--", attr)
            (target / attr).unlink()
        if state == "head-only":
            git(target, "read-tree", "--empty")
    if state == "added-after-crlf" and native:
        # Native input is a legitimate checkout; its attribute context must survive conversion.
        for target in (repo, oracle):
            (target / (prefix + "file.txt")).write_bytes("one\r\ntwo\r\n".encode("utf-16-le"))
    before = shared_bytes(repo)
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected
    assert shared_bytes(repo) == before


def test_snapshot_unmerged_index_uses_ours_baseline_like_git_add(repo, tmp_path):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    ours = git(repo, "hash-object", "-w", "--stdin", data=b"ours\r\n").strip()
    theirs = git(repo, "hash-object", "-w", "--stdin", data=b"theirs\n").strip()
    (repo / "conflict.txt").write_bytes(b"ours\r\nresolved\r\n")
    (repo / ".gitattributes").write_bytes(b"*.txt text=auto\n")
    records = b"".join(b"100644 " + oid + b" " + str(stage).encode() + b"\tconflict.txt\0"
                       for stage, oid in ((1, theirs), (2, ours), (3, theirs)))
    git(repo, "update-index", "-z", "--index-info", data=records)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for oid, value in ((ours, b"ours\r\n"), (theirs, b"theirs\n")):
        assert git(oracle, "hash-object", "-w", "--stdin", data=value).strip() == oid
    git(oracle, "update-index", "-z", "--index-info", data=records)
    for name in ("conflict.txt", ".gitattributes"):
        (oracle / name).write_bytes((repo / name).read_bytes())
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


def test_snapshot_cleans_emulated_symlink_bytes_before_mode(repo, tmp_path):
    context = make_store(repo)
    oid = git(repo, "hash-object", "-w", "--stdin", data=b"old-target").decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", "120000," + oid + ",link")
    git(repo, "commit", "-qm", "link")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-checkout", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.symlinks", "false")
        if target == oracle:
            git(target, "reset", "--hard", "HEAD")
        (target / ".gitattributes").write_bytes(b"* text=auto\n")
        (target / "link").write_bytes(b"new\r\ntarget\r\n")
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected


def test_stat_clean_crlf_honors_ignored_mode_and_ctime_like_git(repo, tmp_path):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    commit(repo, "file.txt", b"one\r\ntwo\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        git(target, "config", "core.filemode", "false")
        git(target, "config", "core.trustctime", "false")
        os.utime(target / "file.txt", (1000000000, 1000000000))
        git(target, "update-index", "--refresh")
        (target / ".gitattributes").write_bytes(b"*.txt text\n")
        git(target, "add", ".gitattributes")
        git(target, "commit", "-qm", "attributes")
        (target / "file.txt").chmod(0o744)
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


def test_snapshot_refuses_concurrent_index_replacement_then_retries(repo, monkeypatch):
    context = make_store(repo)
    (repo / "staged").write_bytes(b"owner change\n")
    entered, release = Event(), Event()
    def gated_read(fd, count):
        if not entered.is_set():
            entered.set()
            assert release.wait(5), "owner never released the snapshot"
        return os.read(fd, count)
    with context as store, ThreadPoolExecutor(max_workers=1) as executor:
        monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "read": gated_read}))
        future = executor.submit(tg.snapshot_tree, store)
        try:
            assert entered.wait(5), "snapshot never reached descriptor reads"
            git(repo, "add", "staged")
        finally:
            release.set()
        with pytest.raises(tg.GitRefusal) as caught:
            future.result(timeout=5)
        assert caught.value.code == "worktree_changed"
        monkeypatch.setattr(tg, "os", os)
        assert store.read_blob(tg.snapshot_tree(store), "staged") == b"owner change\n"


def test_snapshot_reads_only_needed_crlf_baselines_and_retries_failure(repo, monkeypatch):
    context = make_store(repo)
    (repo / ".gitattributes").write_bytes(b"* text=auto\n")
    for number in range(10):
        commit(repo, "file%d" % number, ("unique %d\n" % number).encode())
    requests = []
    def read(real, *args, **kwargs):
        requests.append(args[1])
        return real(*args, **kwargs)
    with context as store:
        restore = patch_lane_objects(monkeypatch, read)
        tg.snapshot_tree(store)
        assert requests == [[]]
        requests.clear()
        (repo / "file3").write_bytes(b"unique 3\r\n")
        tree = tg.snapshot_tree(store)
        assert len(requests) == 1 and len(requests[0]) == 1
        assert store.read_blob(tree, "file3") == b"unique 3\n"
        restore()
        def fail(real, *args, **kwargs):
            raise gitsafe.GitError("never echo token=private", code="privacy_refused")
        restore = patch_lane_objects(monkeypatch, fail)
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "privacy_refused" and "private" not in str(caught.value)
        restore()
        assert tg.snapshot_tree(store) == tree


@pytest.mark.parametrize("fault", ["unterminated", "unknown-stage", "duplicate", "bad-stat", "stat-overflow", "bad-config", "unknown-flags"])
def test_snapshot_refuses_unknown_index_or_config_protocol_and_retries(repo, monkeypatch, fault):
    context = make_store(repo)
    def damaged(real, args, *rest, **kwargs):
        result = real(args, *rest, **kwargs)
        data = result.stdout
        if "ls-files" in args and "--debug" in args and fault != "bad-config":
            if fault == "unterminated":
                data = data.replace(b"\0", b"", 1)
            elif fault == "unknown-stage":
                data = data.replace(b" 0\t", b" 4\t", 1)
            elif fault == "duplicate":
                data += data
            elif fault == "bad-stat":
                data = data.replace(b"  ctime:", b"  secret:", 1)
            elif fault == "unknown-flags":
                data = data.replace(b"flags: 0", b"flags: 40000000", 1)
            else:
                data = data.replace(b"  size: ", b"  size: 99999999999", 1)
        if "config" in args and "--get-regexp" in args and fault == "bad-config" and tg._CONFIG_QUERY in args:
            data = b"core.autocrlf\nunknown-token=secret\0"
        return subprocess.CompletedProcess(result.args, result.returncode, data, result.stderr)
    before = shared_bytes(repo)
    with context as store:
        restore = patch_lane_run(monkeypatch, damaged)
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code in ("conversion_unavailable", "size_limit")
            assert "secret" not in str(caught.value)
        restore()
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"
    assert shared_bytes(repo) == before


def test_snapshot_matches_git_add_for_emulated_symlink(repo, tmp_path):
    context = make_store(repo)
    oid = git(repo, "hash-object", "-w", "--stdin", data=b"x").decode().strip()
    git(repo, "update-index", "--add", "--cacheinfo", "120000," + oid + ",link")
    git(repo, "commit", "-qm", "link")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-checkout", "--no-hardlinks", str(repo), str(oracle))
    git(oracle, "config", "core.symlinks", "false")
    git(oracle, "reset", "--hard", "HEAD")
    git(repo, "config", "core.symlinks", "false")
    for target in (repo, oracle):
        (target / "link").write_bytes(b"x-new-target")
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


@pytest.mark.parametrize("conversion", ["text-auto", "autocrlf", "plain"])
def test_snapshot_process_count_is_constant_for_new_and_existing_files(repo, monkeypatch, conversion):
    context = make_store(repo)
    if conversion == "text-auto":
        (repo / ".gitattributes").write_bytes(b"* text=auto\n")
    if conversion == "autocrlf":
        git(repo, "config", "core.autocrlf", "true")
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    with context as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        tg.snapshot_tree(store)
        small = len(calls)
        calls.clear()
        for number in range(100):
            (repo / ("new%d" % number)).write_bytes(("unique %d\r\n" % number).encode())
        first = tg.snapshot_tree(store)
        assert len(calls) <= small + 1
        assert not any("hash-object" in a for a in calls)
        calls.clear()
        assert tg.snapshot_tree(store) == first
        assert len(calls) <= small + 1


@pytest.mark.parametrize("attributes,auto", [(b"*.txt text=auto", "false"), (b"*.txt text", "false"),
    (b"*.txt -text", "true"), (b"*.txt text=auto eol=lf", "false"),
    (b"*.txt text=auto eol=crlf", "false"), (b"*.txt crlf=input", "false"), (b"", "input")])
@pytest.mark.parametrize("payload", [b"one\r\ntwo\n", b"one\rtwo\r\n", b"a\0\r\n", b"abc\r\n\x1a",
    b"a" * 127 + b"\x01\r\n", b"a" * 128 + b"\x01\r\n", b"", b"$Id: expanded $\r\n"])
def test_snapshot_eol_byte_statistics_match_git_add(repo, tmp_path, attributes, auto, payload):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", auto)
        git(target, "config", "core.safecrlf", "false")
        (target / ".gitattributes").write_bytes(attributes + b"\n")
        (target / "file.txt").write_bytes(payload)
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


@pytest.mark.parametrize("autocrlf,eol,payload", [("input", "lf", b"a\r\n"),
    ("true", "crlf", b"a\n"), ("false", "crlf", b"a\r\nb\n")])
def test_snapshot_safecrlf_refusal_and_retry_match_git(repo, autocrlf, eol, payload):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", autocrlf)
    git(repo, "config", "core.safecrlf", "true")
    (repo / ".gitattributes").write_bytes(("*.txt text eol=" + eol + "\n").encode())
    (repo / "file.txt").write_bytes(payload)
    result = subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True)
    assert result.returncode != 0
    before = shared_bytes(repo)
    with context as store:
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code == "conversion_unavailable"
        git(repo, "config", "core.safecrlf", "false")
        assert store.read_blob(tg.snapshot_tree(store), "file.txt") == payload.replace(b"\r\n", b"\n")
    # Only the deliberate config edit may change the shared repository.
    after = shared_bytes(repo)
    assert {k: v for k, v in before.items() if k != "config"} == {k: v for k, v in after.items() if k != "config"}


def test_snapshot_encoding_and_ident_keep_automatic_crlf_baseline(repo, tmp_path):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    commit(repo, "file.txt", b"one\r\n$Id$\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        (target / ".gitattributes").write_bytes(b"file.txt text=auto ident working-tree-encoding=UTF-16LE\n")
        (target / "file.txt").write_bytes("one\r\n$Id: expanded $\r\n".encode("utf-16-le"))
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


@pytest.mark.parametrize("failure", ["exit", "timeout-before", "timeout-after"])
def test_snapshot_blob_batch_failure_closes_descriptors_and_retry_succeeds(repo, monkeypatch, failure):
    context = make_store(repo)
    (repo / "new").write_bytes(b"unique batch bytes\n")
    failed, calls = [], []
    opened, closed = [], []
    def tracked_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd
    def tracked_close(fd):
        closed.append(fd)
        os.close(fd)
    def boundary(real, args, *rest, **kwargs):
        calls.append(args)
        if "unpack-objects" in args and not failed:
            failed.append(True)
            if failure == "exit":
                return subprocess.CompletedProcess(args, 1, b"", b"secret input")
            if failure == "timeout-after":
                real(args, *rest, **kwargs)
            raise gitsafe.GitError("secret input", code="git_timeout")
        return real(args, *rest, **kwargs)
    before = shared_bytes(repo)
    with context as store:
        restore = patch_lane_run(monkeypatch, boundary)
        monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": tracked_open,
            "close": tracked_close, "supports_dir_fd": os.supports_dir_fd | {tracked_open}}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == ("git_failed" if failure == "exit" else "git_timeout")
        assert "secret" not in str(caught.value)
        assert sorted(opened) == sorted(closed)
        assert not any("update-index" in a for a in calls)
        assert store.read_blob(tg.snapshot_tree(store), "new") == b"unique batch bytes\n"
        assert sorted(opened) == sorted(closed)
    assert shared_bytes(repo) == before


def test_snapshot_refuses_nonblob_conversion_baseline_and_recovers(repo):
    context = make_store(repo)
    (repo / ".gitattributes").write_bytes(b"* text=auto\n")
    (repo / "x").write_bytes(b"base\r\n")
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    git(repo, "update-index", "--cacheinfo", "100644," + tree + ",x")
    with context as store:
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "invalid_object"
        git(repo, "read-tree", "HEAD")
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"


def test_snapshot_pack_budget_is_checked_before_compression_and_can_retry(repo, monkeypatch):
    context = make_store(repo)
    (repo / "x").unlink()
    (repo / "new").write_bytes(b"a" * 100)
    def unexpected(*args):
        pytest.fail("compression allocated before the pack budget check")
    before = shared_bytes(repo)
    with context as store:
        monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", 128)
        monkeypatch.setattr(tg, "zlib", SimpleNamespace(compress=unexpected))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "size_limit"
        monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", 128 * 1024 * 1024)
        import zlib
        monkeypatch.setattr(tg, "zlib", zlib)
        assert store.read_blob(tg.snapshot_tree(store), "new") == b"a" * 100
    assert shared_bytes(repo) == before


def test_repository_programs_never_run(repo, tmp_path):
    if os.name != "posix":
        pytest.skip("shell marker executable requires POSIX")
    marker = tmp_path / "executed"
    script = tmp_path / "marker.sh"
    script.write_text("#!/bin/sh\necho ran > '" + str(marker) + "'\ncat\n", encoding="utf-8")
    script.chmod(0o700)
    hooks = repo / ".git/hooks"
    for name in ("pre-commit", "post-commit", "reference-transaction"):
        hook = hooks / name
        hook.write_bytes(script.read_bytes())
        hook.chmod(0o700)
    for key in ("filter.hostile.clean", "filter.hostile.smudge", "core.fsmonitor"):
        git(repo, "config", key, str(script))
    (repo / ".gitattributes").write_bytes(b"* filter=hostile\n")
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    with make_store(repo) as store:
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "conversion_unavailable"
        (repo / ".gitattributes").write_bytes(b"* -filter\n")
        tree = tg.snapshot_tree(store)
        head = tg.commit_tested(store, tree, parent, "safe", IDENTITY)
        assert tg.plan_merge(store, parent, head).status == "clean"
        assert tg.cas_fast_forward(store, "refs/heads/lane/safe", None, head) == "updated"
    assert not marker.exists()


def test_repository_merge_driver_is_refused(repo):
    git(repo, "config", "merge.hostile.driver", "must-never-run")
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.plan_merge(store, parent, parent)
    assert caught.value.code == "repository_merge_driver"


@pytest.mark.parametrize("status,output,code", [(0, b"", "merge_unavailable"),
    (0, b"malformed", "repository_merge_driver"), (1, b"malformed", "merge_unavailable")])
def test_indeterminate_driver_listing_never_allows_merge(repo, monkeypatch, status, output, code):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    def listing(real, args, *rest, **kwargs):
        if any("^merge" in arg for arg in args):
            return subprocess.CompletedProcess(args, status, output, b"")
        return real(args, *rest, **kwargs)
    with new_store(repo) as store:
        restore = patch_lane_run(monkeypatch, listing)
        with pytest.raises(tg.GitRefusal) as caught:
            tg.plan_merge(store, parent, parent)
        assert caught.value.code == code


def test_snapshot_applies_git_text_conversion_and_retries(repo):
    context = make_store(repo)
    (repo / ".gitattributes").write_bytes(b"*.txt text eol=crlf\n")
    (repo / "line.txt").write_bytes(b"first\r\nsecond\r\n")
    before = shared_bytes(repo)
    with context as store:
        tree = tg.snapshot_tree(store)
        assert store.read_blob(tree, "line.txt") == b"first\nsecond\n"
        assert tg.snapshot_tree(store) == tree
    assert shared_bytes(repo) == before


def test_snapshot_refuses_external_conversion_before_execution_and_can_retry(repo, monkeypatch):
    context = make_store(repo)
    git(repo, "config", "filter.lfs.clean", "must-never-run")
    git(repo, "config", "filter.lfs.required", "true")
    (repo / ".gitattributes").write_bytes(b"x filter=lfs\n")
    calls, real = [], gitsafe.run
    def record(args, *rest, **kwargs):
        calls.append(args)
        return real(args, *rest, **kwargs)
    with context as store:
        monkeypatch.setattr(tg, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": record}))
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code == "conversion_unavailable"
        assert not any("hash-object" in args for args in calls)
        (repo / ".gitattributes").write_bytes(b"x -filter\n")
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"


@pytest.mark.parametrize("mode,configured,expected", [(0o654, True, b"100644"), (0o744, False, b"100644")])
def test_snapshot_uses_owner_execute_bit_and_core_filemode(repo, mode, configured, expected):
    context = make_store(repo)
    (repo / "x").chmod(mode)
    git(repo, "config", "core.filemode", str(configured).lower())
    with context as store:
        tree = tg.snapshot_tree(store)
        assert store._run(["ls-tree", tree, "--", "x"]).stdout.split()[0] == expected


def test_snapshot_batches_index_and_reuses_existing_blobs(repo, monkeypatch):
    context = make_store(repo)
    for number in range(30):
        (repo / ("file%d" % number)).write_bytes(b"same existing blob\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "many files")
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    with context as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        tree = tg.snapshot_tree(store)
        assert sum("update-index" in a for a in calls) == 1
        assert not any("hash-object" in a for a in calls)
        calls.clear()
        assert tg.snapshot_tree(store) == tree
        assert sum("update-index" in a for a in calls) == 1


def test_publication_batches_all_objects(repo, monkeypatch):
    context = make_store(repo)
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    with context as store:
        for number in range(12):
            (repo / ("new%d" % number)).write_bytes(("new%d" % number).encode())
        head = tg.commit_tested(store, tg.snapshot_tree(store), parent, "many objects", IDENTITY)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        assert tg.cas_fast_forward(store, "refs/heads/lane/batch", None, head) == "updated"
        assert sum("pack-objects" in a for a in calls) == 1
        assert sum("unpack-objects" in a for a in calls) == 1
        assert not any("hash-object" in a for a in calls)
        assert sum("--batch-check" in a for a in calls) == 2
    assert git(repo, "rev-parse", "refs/heads/lane/batch").decode().strip() == head


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe select")
def test_custody_waits_for_pipe_readiness_instead_of_fixed_poll(repo, monkeypatch):
    import select
    waits = []
    def blocking(read, write, errors, timeout):
        waits.append(timeout)
        return select.select(read, write, errors, timeout)
    monkeypatch.setattr(gitsafe_run, "select", SimpleNamespace(select=blocking))
    with new_store(repo) as store:
        assert store._run(["version"]).returncode == 0
    assert waits and all(timeout > 0 for timeout in waits)


@pytest.mark.parametrize("planner", ["merge", "pick", "revert"])
def test_global_merge_driver_is_refused_before_merge_tree(repo, tmp_path, monkeypatch, planner):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    side = commit(repo, "side", b"side\n")
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    merged = git(repo, "commit-tree", tree, "-p", parent, "-p", side,
                 data=b"merge\n").decode().strip()
    config = tmp_path / "global-config"
    script, marker = repo / "child-script", tmp_path / "driver-executed"
    script.write_text('echo ran > "' + marker.as_posix() + '"\n', encoding="utf-8")
    git(repo, "config", "--file", str(config), "merge.hostile.driver",
        'sh "' + script.as_posix() + '" %O %A %B')
    (repo / ".gitattributes").write_bytes(b"x merge=hostile\n")
    calls, real = [], subprocess.Popen
    def observed(args, **kwargs):
        calls.append(args)
        return real(args, **kwargs)
    home = tmp_path / "home"
    home.mkdir()
    shutil.copyfile(config, home / ".gitconfig")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": observed}))
    with new_store(repo) as store:
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                if planner == "merge":
                    tg.plan_merge(store, parent, side)
                elif planner == "pick":
                    tg.plan_pick(store, parent, [side], IDENTITY)
                else:
                    tg.plan_revert(store, merged, merged)
            assert caught.value.code == "repository_merge_driver"
    assert not any("merge-tree" in args for args in calls)
    assert not marker.exists()


@pytest.mark.parametrize("command", ["update-ref", "symbolic-ref", "branch", "tag", "notes",
    "replace", "fast-import", "push", "fetch", "reflog", "pack-refs", "gc", "config-write"])
@pytest.mark.parametrize("prefix", [[], ["-c", "aegis.test=value"], ["-C", "."]])
def test_store_dispatcher_refuses_ref_writers_before_git(repo, monkeypatch, command, prefix):
    with new_store(repo) as store:
        before = shared_bytes(repo)
        def unexpected(*args, **kwargs):
            pytest.fail("ref writer reached Git outside cas_fast_forward")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
        argv = [*prefix, command] if command != "config-write" else [*prefix, "config", "aegis.x", "y"]
        dispatch = store._run
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                dispatch(argv)
            assert caught.value.code == "git_custody_refused"
        assert shared_bytes(repo) == before


def test_parent_rename_race_cannot_read_external_bytes(repo, tmp_path, monkeypatch):
    if not tg.descriptor_support():
        pytest.skip("requires descriptor-relative opens")
    (repo / "dir").mkdir()
    commit(repo, "dir/file", b"inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"secret")
    # Establish capability before installing the race.
    symlink_or_skip(outside, repo / "probe")
    (repo / "probe").unlink()
    real_open, raced = os.open, []
    def swapping_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == "dir" and not raced:
            raced.append(True)
            (repo / "dir").rename(repo / "old-dir")
            (repo / "dir").symlink_to(outside, target_is_directory=True)
        return fd
    monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": swapping_open,
        "supports_dir_fd": os.supports_dir_fd | {swapping_open}}))
    with make_store(repo) as store:
        tree = tg.snapshot_tree(store)
        assert store.read_blob(tree, "dir/file") == b"inside"
    assert raced


def test_descriptor_cleanup_on_read_failure_and_retry(repo, monkeypatch):
    opened, closed = [], []
    real_open, real_close = os.open, os.close
    def track_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def track_close(fd):
        closed.append(fd)
        return real_close(fd)
    def fail_read(*args):
        raise OSError("private input")
    monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": track_open, "close": track_close,
        "read": fail_read, "supports_dir_fd": os.supports_dir_fd | {track_open}}))
    with make_store(repo) as store:
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "path_unreadable"
        monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": track_open, "close": track_close,
            "supports_dir_fd": os.supports_dir_fd | {track_open}}))
        assert sorted(opened) == sorted(closed)
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"
    assert sorted(opened) == sorted(closed)


def test_lost_lane_ref_ack_is_observed_without_retry(repo, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    real_popen, writes = subprocess.Popen, []
    def lost_ack(argv, **kwargs):
        result = real_popen(argv, **kwargs)
        if "update-ref" in argv:
            writes.append(argv)
            original_wait = result.wait
            def wait(*args, **kw):
                original_wait(*args, **kw)
                raise subprocess.TimeoutExpired(argv, 10)
            result.wait = wait
        return result
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": lost_ack}))
        assert tg.cas_fast_forward(store, "refs/heads/lane/lost", None, parent) == "already"
        assert len(writes) == 1


@pytest.mark.parametrize("namespace", ["refs/heads/lane/outcome", "refs/aegis/qual/outcome"])
@pytest.mark.parametrize("failure", ["nonzero", "git_cleanup_failed", "git_output_limit", "git_failed"])
@pytest.mark.parametrize("observation", ["old", "new", "winner"])
def test_cas_classifies_failed_acknowledgments_and_never_retries(repo, monkeypatch, namespace, failure, observation):
    new = git(repo, "rev-parse", "HEAD").decode().strip()
    winner = commit(repo, "winner", b"competing commit")
    real, writes = gitsafe_run.capture, []
    def fail(args, **kwargs):
        if "update-ref" not in args:
            return real(args, **kwargs)
        writes.append(args)
        if observation != "old":
            git(repo, "update-ref", namespace, new if observation == "new" else winner)
        if failure == "nonzero":
            return subprocess.CompletedProcess(args, 1, b"", b"private error")
        raise gitsafe.GitError("private error", code=failure, process_started=True)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "capture", fail)
        if observation == "new":
            assert tg.cas_fast_forward(store, namespace, None, new) == "already"
        else:
            with pytest.raises(tg.GitRefusal) as caught:
                tg.cas_fast_forward(store, namespace, None, new)
            expected = "cas_mismatch" if observation == "winner" else (
                "ref_update_failed" if failure == "nonzero" else "ref_update_unknown")
            assert caught.value.code == expected
            assert "private" not in str(caught.value)
        assert len(writes) == 1
        monkeypatch.setattr(gitsafe_run, "capture", real)
        if observation == "old" and failure == "nonzero":
            assert tg.cas_fast_forward(store, namespace, None, new) == "updated"
        elif observation == "new":
            assert tg.cas_fast_forward(store, namespace, None, new) == "already"


@pytest.mark.parametrize("ref", ["refs/heads/lane/spawn", "refs/aegis/qual/spawn"])
def test_cas_spawn_failure_is_definite_and_can_be_retried(repo, monkeypatch, ref):
    new = git(repo, "rev-parse", "HEAD").decode().strip()
    real, attempts = subprocess.Popen, []
    def refuse_spawn(argv, **kwargs):
        if "update-ref" in argv:
            attempts.append(argv)
            raise OSError("private spawn failure")
        return real(argv, **kwargs)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": refuse_spawn}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.cas_fast_forward(store, ref, None, new)
        assert caught.value.code == "ref_update_failed"
        assert "private" not in str(caught.value)
        assert len(attempts) == 1
        monkeypatch.setattr(gitsafe_run, "subprocess", subprocess)
        assert tg.cas_fast_forward(store, ref, None, new) == "updated"


def test_ref_symbolic_target_is_never_written(repo):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    git(repo, "symbolic-ref", "refs/heads/lane/link", "refs/heads/main")
    before = shared_bytes(repo)
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.cas_fast_forward(store, "refs/heads/lane/link", parent, parent)
    assert caught.value.code == "ref_unreadable"
    assert shared_bytes(repo) == before


def test_conflict_display_is_canonical_then_redacted_then_truncated(repo, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    secret_path = b"token=\x1b[31msecret\x1b[0m" + b"z" * 300
    def conflict(real, args, *other, **kwargs):
        if "merge-tree" in args:
            return subprocess.CompletedProcess(args, 1, parent.encode() + b"\0" + secret_path + b"\0\0", b"")
        return real(args, *other, **kwargs)
    with new_store(repo) as store:
        restore = patch_lane_run(monkeypatch, conflict)
        plan = tg.plan_merge(store, parent, parent)
    assert len(plan.conflicts[0]) <= 240
    assert "secret" not in plan.conflicts[0] and "\x1b" not in plan.conflicts[0]


def test_aegis_delegate_must_not_retry_unknown_write(repo, monkeypatch):
    """ADR G3: a failed acknowledgment never authorizes a repeated write."""
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    real_popen, writes = subprocess.Popen, []
    def timeout(argv, **kwargs):
        if "update-ref" in argv:
            writes.append(argv)
            raise subprocess.TimeoutExpired(argv, 10)
        return real_popen(argv, **kwargs)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": timeout}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.cas_fast_forward(store, "refs/aegis/qual/test", None, parent)
        assert caught.value.code == "ref_update_unknown"
        assert len(writes) == 1


def test_aegis_delegate_must_keep_required_hardening(repo, monkeypatch):
    """ADR G6 hardening reaches every custody helper and the delegated write."""
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    real_popen, writes, calls = subprocess.Popen, [], []
    def recording(argv, **kwargs):
        calls.append(argv)
        if "update-ref" in argv:
            writes.append(argv)
        return real_popen(argv, **kwargs)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": recording}))
        assert tg.cas_fast_forward(store, "refs/aegis/qual/test", None, parent) == "updated"
    assert len(writes) == 1
    assert calls
    assert all("gc.auto=0" in argv and "maintenance.auto=false" in argv for argv in calls)


def test_refusal_code_is_preserved_by_public_planner_and_cas(repo, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store:
        def refuse(real, *args, **kwargs):
            raise gitsafe.GitError("private hostile text", code="privacy_refused")
        restore = patch_lane_run(monkeypatch, refuse)
        for operation in (lambda: tg.plan_merge(store, parent, parent),
                          lambda: tg.cas_fast_forward(store, "refs/heads/lane/x", None, parent)):
            with pytest.raises(tg.GitRefusal) as caught:
                operation()
            assert caught.value.code == "privacy_refused"
            assert "hostile" not in str(caught.value)


def test_invalid_ref_identity_precedes_every_git_call(repo, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store:
        def unexpected(*args, **kwargs):
            pytest.fail("invalid ref caused a git call")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
        for ref in ("refs/heads/lane/../main", "refs/heads/lane/x.lock", "refs/heads/lane/x@{bad"):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.cas_fast_forward(store, ref, parent, parent)
            assert caught.value.code == "ref_not_allowed"


def test_snapshot_includes_staged_ignored_additions_without_changing_index(repo):
    (repo / ".gitignore").write_bytes(b"ignored\n")
    (repo / "ignored").write_bytes(b"explicitly tracked\n")
    git(repo, "add", "-f", "ignored")
    before = shared_bytes(repo)
    with make_store(repo) as store:
        assert store.read_blob(tg.snapshot_tree(store), "ignored") == b"explicitly tracked\n"
    assert shared_bytes(repo) == before


def test_malformed_parent_header_returns_refusal_without_echo(repo):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").strip()
    malformed = b"tree " + tree + b"\nparent \xffhostile\nauthor A <a@b> 1 +0000\n\nmessage\n"
    source = git(repo, "hash-object", "--literally", "-w", "-t", "commit", "--stdin", data=malformed).decode().strip()
    with new_store(repo) as store:
        with pytest.raises(tg.GitRefusal) as caught:
            tg.plan_pick(store, parent, (source,), IDENTITY)
        assert caught.value.code == "invalid_object"
        assert "hostile" not in str(caught.value)


def test_snapshot_aggregate_cap_precedes_file_read(repo, monkeypatch):
    monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", 2)
    def forbidden_read(*args):
        pytest.fail("over-limit file was read")
    monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "read": forbidden_read}))
    with make_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        tg.snapshot_tree(store)
    assert caught.value.code == "size_limit"


def test_disappearance_after_identity_check_refuses_then_retry_succeeds(repo, monkeypatch):
    context = make_store(repo)
    real_open = os.open
    def disappear(path, flags, *args, **kwargs):
        if path == "x":
            (repo / "x").unlink()
        return real_open(path, flags, *args, **kwargs)
    with context as store:
        monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": disappear,
            "supports_dir_fd": os.supports_dir_fd | {disappear}}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "worktree_changed"
        monkeypatch.setattr(tg, "os", os)
        (repo / "x").write_bytes(b"restored")
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"restored"


def test_invalid_root_identity_precedes_git_or_metadata(repo, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid identity caused a git invocation")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    for root in (repo / ".." / "repo", Path("relative"), "invalid\0root"):
        with pytest.raises(tg.GitRefusal) as caught:
            with tg.GitStore(root, repo.parent):
                pass
        assert caught.value.code == "invalid_repository"


def test_publish_budget_is_enforced_before_payload_capture(repo, monkeypatch):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    calls = []
    real_popen = subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real_popen(argv, **kwargs)
    with new_store(repo) as store:
        head = tg.commit_tested(store, tree, parent, "private commit", IDENTITY)
        monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", 1)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.cas_fast_forward(store, "refs/heads/lane/budget", None, head)
        assert caught.value.code == "git_object_limit"
        # Validation reads the commit once; publication must refuse at metadata,
        # before capturing a second copy beyond its remaining aggregate budget.
        assert sum(tuple(argv[-3:]) == ("cat-file", "commit", head) for argv in calls) == 1
    assert gitsafe.read_ref(repo, "refs/heads/lane/budget") is None


def test_mainline_revert_tree_matches_porcelain_on_a_later_tip(repo):
    git(repo, "checkout", "-qb", "topic")
    commit(repo, "x", b"feature\n")
    git(repo, "checkout", "-q", "main")
    commit(repo, "other", b"mainline\n")
    git(repo, "merge", "--no-ff", "-qm", "merge", "topic")
    merge = git(repo, "rev-parse", "HEAD").decode().strip()
    tip = commit(repo, "later", b"keep this later change\n")
    before = shared_bytes(repo)
    with new_store(repo) as store:
        plan = tg.plan_revert(store, tip, merge)
        assert plan.status == "clean"
    assert shared_bytes(repo) == before
    git(repo, "revert", "--no-commit", "-m", "1", merge)
    assert plan.tree == git(repo, "write-tree").decode().strip()


def test_closed_store_refuses_every_public_operation_before_git(repo, monkeypatch):
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store:
        pass
    def unexpected(*args, **kwargs):
        pytest.fail("closed store invoked Git")
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
    operations = (lambda: store._run(["version"]), lambda: store.object(oid, "commit"),
        lambda: store.read_blob(oid, "x"), lambda: tg.snapshot_tree(store),
        lambda: tg.commit_tested(store, oid, oid, "message", IDENTITY),
        lambda: tg.cas_fast_forward(store, "refs/heads/lane/x", None, oid),
        lambda: tg.plan_merge(store, oid, oid), lambda: tg.plan_pick(store, oid, (oid,), IDENTITY),
        lambda: tg.plan_revert(store, oid, oid))
    for operation in operations:
        with pytest.raises(tg.GitRefusal) as caught:
            operation()
        assert caught.value.code == "store_closed"


@pytest.mark.parametrize("path", ["../secret", "C:secret", "bad\\name", "\ud800"],
                         ids=["parent", "drive", "backslash", "surrogate"])
def test_object_path_identity_refuses_before_git(repo, monkeypatch, path):
    if os.name != "nt" and path in ("C:secret", "bad\\name"):
        pytest.skip("these are valid POSIX names, covered by the acceptance test")
    oid = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    with new_store(repo) as store:
        def unexpected(*args, **kwargs):
            pytest.fail("invalid object path invoked Git")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
        with pytest.raises(tg.GitRefusal) as caught:
            store.read_blob(oid, path)
        assert caught.value.code == "unsafe_path"


def test_lone_surrogate_is_refused_even_when_fsencode_accepts_it(repo, monkeypatch):
    oid = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    with new_store(repo) as store:
        monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os),
            "fsencode": lambda value: value.encode("utf-8", "surrogatepass")}))
        def unexpected(*args, **kwargs):
            pytest.fail("lone surrogate reached Git")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": unexpected}))
        with pytest.raises(tg.GitRefusal) as caught:
            store.read_blob(oid, "\ud800")
        assert caught.value.code == "unsafe_path"


@pytest.mark.parametrize("cap", ["bad", True, -1], ids=["text", "boolean", "negative"])
def test_bad_object_budget_returns_refusal(repo, cap):
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    with new_store(repo) as store, pytest.raises(tg.GitRefusal) as caught:
        store.object(oid, "commit", max_bytes=cap)
    assert caught.value.code == "invalid_object"


def test_snapshot_has_one_index_writer_and_can_retry_after_busy(repo, monkeypatch):
    context = make_store(repo)
    entered, release = Event(), Event()
    def pause_read(fd, size):
        if not entered.is_set():
            entered.set()
            assert release.wait(3), "snapshot read was never released"
        return os.read(fd, size)
    monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "read": pause_read}))
    with context as store, ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(tg.snapshot_tree, store)
        try:
            assert entered.wait(3), "snapshot did not reach the read boundary"
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code == "store_busy"
        finally:
            release.set()
        tree = first.result(timeout=3)
        assert tg.snapshot_tree(store) == tree


def test_descriptor_close_failure_still_closes_all_and_releases_index(repo, monkeypatch):
    context = make_store(repo)
    (repo / "dir").mkdir()
    commit(repo, "dir/file", b"nested")
    opened, closed = [], []
    def track_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd
    def fail_once_close(fd):
        os.close(fd)
        closed.append(fd)
        if len(closed) == 1:
            raise OSError("never display close input")
    monkeypatch.setattr(tg, "os", SimpleNamespace(**{**vars(os), "open": track_open, "close": fail_once_close,
        "supports_dir_fd": os.supports_dir_fd | {track_open}}))
    try:
        with context as store:
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code == "descriptor_cleanup_failed"
            assert sorted(opened) == sorted(closed)
            monkeypatch.setattr(tg, "os", os)
            assert store.read_blob(tg.snapshot_tree(store), "dir/file") == b"nested"
    finally:
        for fd in opened:
            if fd not in closed:
                os.close(fd)


def test_ignored_untracked_secret_stays_out_of_snapshot_and_publication(repo, tmp_path):
    context = make_store(repo)
    parent = commit(repo, ".env", b"TOKEN=old\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "rm", "--cached", "--", ".env")
        (target / ".gitignore").write_bytes(b".env\n")
        (target / ".env").write_bytes(b"TOKEN=new-secret\n")
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    before = shared_bytes(repo)
    with context as store:
        for _ in range(2):
            tree = tg.snapshot_tree(store)
            assert tree == expected
            with pytest.raises(tg.GitRefusal) as caught:
                store.read_blob(tree, ".env")
            assert caught.value.code == "path_missing"
        new = tg.commit_tested(store, tree, parent, "safe snapshot", IDENTITY)
        assert tg.cas_fast_forward(store, "refs/aegis/no-secret", None, new) == "updated"
        assert tg.cas_fast_forward(store, "refs/aegis/no-secret", None, new) == "already"
    assert b".env" not in git(repo, "ls-tree", "-r", new)
    secret = gitsafe.blob_id(b"TOKEN=new-secret\n")
    assert subprocess.run(["git", "cat-file", "-e", secret], cwd=repo, capture_output=True).returncode != 0
    assert before["index"] == shared_bytes(repo)["index"]


@pytest.mark.parametrize("setting", ["autocrlf", "safecrlf", "filemode", "symlinks", "trustctime"])
@pytest.mark.parametrize("value", [None, "", "true", "false"], ids=["valueless", "empty", "true", "false"])
def test_snapshot_git_boolean_config_semantics(repo, tmp_path, setting, value):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    commit(repo, "file.txt", b"one\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        with (target / ".git/config").open("a") as config:
            config.write("\n[core]\n\t" + setting + ("" if value is None else " = " + value) + "\n")
        (target / "file.txt").write_bytes(b"one\r\nchanged\r\n")
        (target / "file.txt").chmod(0o744)
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected


@pytest.mark.parametrize("setting,value", [("autocrlf", "INPUT"), ("safecrlf", "WARN")])
def test_snapshot_git_special_config_values_are_case_insensitive(repo, tmp_path, setting, value):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core." + setting, value)
        (target / "new.txt").write_bytes(b"one\r\n")
    git(oracle, "add", "-A")
    with context as store:
        assert tg.snapshot_tree(store) == git(oracle, "write-tree").decode().strip()


def test_snapshot_intent_to_add_has_no_conversion_baseline(repo, tmp_path):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        (target / ".gitattributes").write_bytes(b"* text=auto\n")
        (target / "new.txt").write_bytes(b"new\r\ncontent\r\n")
        git(target, "add", "-N", "--", "new.txt")
    before = shared_bytes(repo)
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected
    assert shared_bytes(repo) == before


@pytest.mark.parametrize("flag", ["assume-unchanged", "skip-worktree"])
def test_snapshot_unsupported_index_flags_have_action_and_recover(repo, flag):
    context = make_store(repo)
    git(repo, "update-index", "--" + flag, "--", "x")
    before = shared_bytes(repo)
    with context as store:
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code == "index_flags_unsupported"
            assert caught.value.next_action == "Clear assume-unchanged and skip-worktree flags, then retry."
        assert shared_bytes(repo) == before
        git(repo, "update-index", "--no-" + flag, "--", "x")
        assert store.read_blob(tg.snapshot_tree(store), "x") == b"base\n"


@pytest.mark.parametrize("stages", [(1, 3), (1,), (3,)])
def test_snapshot_unmerged_mode_uses_first_available_stage(repo, tmp_path, stages):
    context = make_store(repo)
    git(repo, "config", "core.filemode", "false")
    oid = git(repo, "hash-object", "-w", "--stdin", data=b"old\r\n").strip()
    records = b"".join(b"100755 " + oid + b" " + str(stage).encode() + b"\tconflict.txt\0" for stage in stages)
    git(repo, "update-index", "-z", "--index-info", data=records)
    (repo / ".gitattributes").write_bytes(b"*.txt text=auto\n")
    (repo / "conflict.txt").write_bytes(b"old\r\nresolved\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    git(oracle, "config", "core.filemode", "false")
    git(oracle, "hash-object", "-w", "--stdin", data=b"old\r\n")
    git(oracle, "update-index", "-z", "--index-info", data=records)
    (oracle / ".gitattributes").write_bytes(b"*.txt text=auto\n")
    (oracle / "conflict.txt").write_bytes(b"old\r\nresolved\r\n")
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    with context as store:
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected


def test_snapshot_minimal_stat_ignores_ctime_like_git_add(repo, tmp_path):
    import hashlib
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    commit(repo, "file.txt", b"one\r\ntwo\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        git(target, "config", "core.autocrlf", "false")
        git(target, "config", "core.filemode", "false")
        git(target, "config", "core.trustctime", "true")
        git(target, "config", "core.checkStat", "minimal")
        git(target, "config", "index.version", "2")
        os.utime(target / "file.txt", (1000000000, 1000000000))
        git(target, "update-index", "--refresh")
        (target / ".gitattributes").write_bytes(b"*.txt text\n")
        git(target, "add", "--", ".gitattributes")
        git(target, "commit", "-qm", "attributes")
        # Make a deterministic ctime-only cache mismatch without sleeping.
        index = target / ".git/index"
        raw = bytearray(index.read_bytes())
        assert raw[:8] == b"DIRC\0\0\0\2"
        count, position = int.from_bytes(raw[8:12], "big"), 12
        for _ in range(count):
            end = raw.index(0, position + 62)
            if raw[position + 62:end] == b"file.txt":
                raw[position:position + 4] = (1).to_bytes(4, "big")
            position += ((end + 1 - position + 7) // 8) * 8
        raw[-20:] = hashlib.sha1(raw[:-20]).digest()
        index.write_bytes(raw)
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected


@pytest.mark.parametrize("native", [False, True], ids=["text", "native"])
def test_snapshot_and_read_allow_leading_dash_after_option_boundary(repo, tmp_path, native):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        (target / ".gitattributes").write_bytes(b"*.txt text\n" + (b"*.txt working-tree-encoding=UTF-16LE\n" if native else b""))
        (target / "-file.txt").write_bytes("one\r\n".encode("utf-16-le") if native else b"one\r\n")
        git(target, "add", "--", "-file.txt", ".gitattributes")
        git(target, "commit", "-qm", "dash path")
        (target / "-file.txt").write_bytes("changed\r\n".encode("utf-16-le") if native else b"changed\r\n")
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert store.read_blob(expected, "-file.txt") == b"changed\n"
        assert tg.snapshot_tree(store) == expected


LANE_BYPASSES = {**RUNTIME_BYPASSES,
    "transport-callback": "gitsafe_run.checked(bad, root, runner=gitsafe.run, error=ValueError, git_error=git_error, timeout=10, stdin=None)",
    "bare-import": "run = gitsafe.run\nrun(bad, root)",
    "module-alias": "g = gitsafe\ng.run(bad, root)",
    "local-import-shadow": "def first():\n g = gitsafe\n g.run(bad, root)\ndef other():\n import math as g\nfirst()",
    "raw-capture": "gitsafe.run([gitsafe_program, *gitsafe_run.DEFAULT_HARDENING, *bad], root)",
}
STATIC_LANE_FORBIDDEN = {
    "direct-writer-helper": "gitsafe_run.lane_update_ref(root, ref, new, old)",
    "other-operation-cas": "def snapshot(store, _runner=None):\n _require_runner(_runner)\n return _runner.cas(ref, new, old)",
    "parameter-module": "def send(g):\n return g.run(argv, root)",
    "unproved-runner": "def send(runner):\n return runner.run(argv, root)",
    "rebound-runner": "def send(_runner):\n _require_runner(_runner)\n _runner = supplied\n return _runner.run(argv, root)",
    "other-facade-helper": "def send(g):\n return g.read_blob(root, rev, path)",
    "call": "gitsafe.run(['update-ref', ref, oid], root)",
    "checked-call": "gitsafe.run_checked(['commit'], root)",
    "symbolic": "gitsafe.run(['symbolic-ref', ref, other], root)",
    "thread-target": "Thread(target=gitsafe.run, args=(argv, root))",
    "executor-target": "executor.submit(gitsafe.run, argv, root)",
    "callback-value": "send(gitsafe.run)",
    "attribute-local": "runner = gitsafe.run",
    "transport-callback": "gitsafe_run.update_once(root, ref, new, old, command, runner=gitsafe.run)",
    "transport-execute": "gitsafe_run.execute(argv, root)",
    "transport-capture": "gitsafe_run.capture(argv, cwd=root)",
    "transport-checked": "gitsafe_run.checked(argv, root, runner=gitsafe.run)",
    "bare-import": "from aegis_core.gitsafe import run as runner\nrunner(argv, root)",
    "module-alias": "import aegis_core.gitsafe as g\ng.run(argv, root)",
    "transport-alias": "import aegis_core.gitsafe_run as r\nr.capture(argv, cwd=root)",
    "factory": "runner = gitsafe.lane_runner(root, scratch)",
    "constructor": "runner = gitsafe_run.LaneRunner(root, scratch, services)",
    "constructor-value": "spawn(gitsafe_run.LaneRunner)",
    "module-forward": "send(gitsafe)",
}


@pytest.mark.parametrize("form", sorted(STATIC_LANE_FORBIDDEN))
def test_lane_structure_refuses_every_unrestricted_reference(form):
    from tests.unit.core.test_gitsafe import _run_subcommand_offenders
    assert _run_subcommand_offenders("aegis_core/team_git.py", STATIC_LANE_FORBIDDEN[form])


@pytest.mark.parametrize("worker", ["direct", "thread", "executor"])
@pytest.mark.parametrize("form", sorted(LANE_BYPASSES))
def test_injected_lane_runner_refuses_rebinding_across_workers(repo, monkeypatch, form, worker):
    from contextlib import nullcontext
    context = new_store(repo)
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    @tg._lane_operation
    def operation(store, *, _runner=None):
        spawns = []
        def forbidden(argv, **kwargs):
            spawns.append(argv)
            pytest.fail("unapproved command reached Popen")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        namespace = dict(gitsafe=_runner, gitsafe_run=gitsafe_run, root=repo, oid=oid,
                         ref="refs/heads/main", bad=["update-ref", "refs/heads/main", oid],
                         os=os, nullcontext=nullcontext, gitsafe_program=gitsafe.git_executable(), git_error=gitsafe.GitError)
        def call():
            with pytest.raises(gitsafe.GitError) as caught:
                exec(LANE_BYPASSES[form], namespace)
            assert caught.value.code == "git_custody_refused"
            assert caught.value.next_action == "Use the lane Git APIs or the CAS fast-forward writer."
            return caught.value.code
        if worker == "executor":
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(call).result(timeout=5) == "git_custody_refused"
        elif worker == "thread":
            result = []
            thread = Thread(target=lambda: result.append(call()))
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive() and result == ["git_custody_refused"]
        else:
            call()
        assert not spawns
    with context as store:
        operation(store)


@pytest.mark.parametrize("command", ["update-ref", "symbolic-ref", "commit"])
@pytest.mark.parametrize("worker", ["thread", "executor"])
def test_lane_runner_forwarded_as_thread_target_remains_closed(repo, monkeypatch, command, worker):
    context = new_store(repo)
    @tg._lane_operation
    def operation(store, *, _runner=None):
        calls, results = [], []
        def forbidden(*args, **kwargs):
            calls.append(args)
            pytest.fail("ref writer reached Popen")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        # This local gitsafe name is the explicitly injected object, never the facade.
        gitsafe = _runner
        def submit():
            try:
                gitsafe.run([command], repo)
            except AegisError as exc:
                results.append(exc.code)
        if worker == "thread":
            thread = Thread(target=submit)
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive()
        else:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(submit).result(timeout=5)
        assert results == ["git_custody_refused"] and not calls
    from aegis_core.errors import AegisError
    with context as store:
        operation(store)


def test_uninjected_lane_function_refuses_before_any_spawn(repo, monkeypatch):
    context = new_store(repo)
    with context as store:
        def forbidden(*args, **kwargs):
            pytest.fail("uninjected operation started a process")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree.__wrapped__(store)
        assert caught.value.code == "lane_runner_required"


@pytest.mark.parametrize("args", [["read-tree", "--empty"], ["update-index", "-z", "--index-info"]])
@pytest.mark.parametrize("index", ["absent", "real", "ref", "private"])
def test_lane_index_writes_require_exact_private_index(repo, monkeypatch, args, index):
    context = new_store(repo)
    @tg._lane_operation
    def operation(store, *, _runner=None):
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(tuple(argv))
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        env = {} if index == "absent" else {"GIT_INDEX_FILE": str(store.index_path) if index == "real" else str(repo / ".git/refs/heads/main") if index == "ref" else store.env["GIT_INDEX_FILE"]}
        if index == "absent":
            assert _runner.run(args, repo, stdin=b"", _env=env).returncode == 0
            assert len(calls) == 1
        else:
            with pytest.raises(gitsafe.GitError) as caught:
                _runner.run(args, repo, stdin=b"", _env=env)
            assert caught.value.code == "git_custody_refused" and not calls
        assert _runner.run(["version"], repo).returncode == 0
    with context as store:
        before = shared_bytes(repo)
        operation(store)
        assert shared_bytes(repo) == before


def test_lane_write_tree_cannot_touch_the_real_index(repo, monkeypatch):
    context = new_store(repo)
    @tg._lane_operation
    def operation(store, *, _runner=None):
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(argv)
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        with pytest.raises(gitsafe.GitError) as caught:
            _runner.run(["write-tree"], repo, _env={"GIT_INDEX_FILE": str(store.index_path)})
        assert caught.value.code == "git_custody_refused" and not calls
    with context as store:
        operation(store)


def test_lane_runner_worker_cas_is_local_and_cannot_lend_a_write_grant(repo, monkeypatch):
    context = new_store(repo)
    first = git(repo, "rev-parse", "HEAD").decode().strip()
    second = commit(repo, "later", b"next\n")
    @tg._lane_operation
    def operation(store, *, _runner=None):
        ready, release = Event(), Event()
        calls, real = [], subprocess.Popen
        def record(argv, **kwargs):
            calls.append(argv)
            if "update-ref" in argv:
                with pytest.raises(gitsafe.GitError) as denied:
                    _runner.run(["update-ref", "--no-deref", "-z", "--stdin"], repo, stdin=b"same shape")
                assert denied.value.code == "git_custody_refused"
            return real(argv, **kwargs)
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        def worker():
            assert not gitsafe_run.strict_active()
            ready.set()
            assert release.wait(5), "worker was not released"
            assert _runner.run(["version"]).returncode == 0
            assert _runner.cas("refs/heads/lane/worker", first, None) == "updated"
            return _runner.cas("refs/heads/lane/worker", second, first)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(worker)
            try:
                assert ready.wait(5), "worker did not start"
                with pytest.raises(gitsafe.GitError) as denied:
                    _runner.run(["symbolic-ref", "refs/heads/main", "refs/heads/lane/worker"])
                assert denied.value.code == "git_custody_refused"
            finally:
                release.set()
            assert future.result(timeout=5) == "updated"
        assert _runner.cas("refs/heads/lane/worker", second, first) == "already"
        assert sum("update-ref" in argv for argv in calls) == 2
    with context as store:
        operation(store)


def test_lane_object_request_bounds_precede_custom_iteration(repo, monkeypatch):
    class Unproved(list):
        def __iter__(self):
            pytest.fail("unproved object request was iterated")
    @tg._lane_operation
    def operation(store, *, _runner=None):
        def forbidden(*args, **kwargs):
            pytest.fail("invalid object request reached Popen")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        for request in (Unproved(), ["0" * 40] * 20001):
            with pytest.raises(gitsafe.GitError) as caught:
                _runner.read_private_objects(repo, request, max_bytes=1024, max_object_bytes=1024,
                                             env=store.env, scratch=store.scratch)
            assert caught.value.code == "invalid_object"
    with new_store(repo) as store:
        operation(store)


def test_lane_runner_cannot_be_supplied_by_a_public_caller(repo, monkeypatch):
    with new_store(repo) as store:
        def forbidden(*args, **kwargs):
            pytest.fail("caller-supplied runner reached Popen")
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": forbidden}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.plan_merge(store, "0" * 40, "0" * 40, _runner=object())
        assert caught.value.code == "lane_runner_required"


@pytest.mark.parametrize("encoding,codec", [
    ("UTF-8", "utf-8"), ("UTF-16", "utf-16"), ("UTF-16LE", "utf-16-le"),
    ("UTF-16BE", "utf-16-be"), ("UTF-32", "utf-32"), ("UTF-32LE", "utf-32-le"),
    ("UTF-32BE", "utf-32-be"), ("ASCII", "ascii"), ("ISO-8859-1", "latin-1"),
    ("CP1252", "cp1252"), ("SHIFT_JIS", "shift_jis"),
])
def test_native_encoding_uses_index_only_attributes_like_git_add(repo, tmp_path, encoding, codec):
    context = make_store(repo)
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        (target / ".gitattributes").write_bytes(("*.txt text working-tree-encoding=" + encoding + "\n").encode())
        (target / "!first.txt").write_bytes("one\r\ntwo\r\n".encode(codec))
        git(target, "add", "--", ".gitattributes", "!first.txt")
        git(target, "commit", "-qm", "encoded")
        (target / ".gitattributes").unlink()
        text = {"ASCII": "changed", "ISO-8859-1": "café", "CP1252": "€ café", "SHIFT_JIS": "日本語ソ"}.get(encoding, "changed é 日本語 😀")
        (target / "!first.txt").write_bytes((text + "\r\ntwo\r\n").encode(codec))
    git(oracle, "add", "-A")
    expected = git(oracle, "write-tree").decode().strip()
    before = shared_bytes(repo)
    with context as store:
        assert tg.snapshot_tree(store) == expected
        assert store.read_blob(expected, "!first.txt") == (text + "\ntwo\n").encode("utf-8")
        assert tg.snapshot_tree(store) == expected
    assert shared_bytes(repo) == before


@pytest.mark.parametrize("encoding,payload", [
    ("UTF-16", b"one\r\n"), ("UTF-16LE", b"\xff\xfeo\0n\0e\0"),
    ("UTF-16BE", b"\xfe\xff\0o\0n\0e"),
    ("UTF-32", b"one\r\n"), ("UTF-32LE", b"\xff\xfe\0\0o\0\0\0"),
    ("UTF-32BE", b"\0\0\xfe\xff\0\0\0o"), ("ASCII", b"\xff"),
])
def test_native_encoding_invalid_bom_and_bytes_refuse_then_retry(repo, encoding, payload):
    context = make_store(repo)
    (repo / ".gitattributes").write_bytes(("*.txt text working-tree-encoding=" + encoding + "\n").encode())
    (repo / "bad.txt").write_bytes(payload)
    assert subprocess.run(["git", "add", "--", "bad.txt"], cwd=repo, capture_output=True).returncode != 0
    with context as store:
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.snapshot_tree(store)
            assert caught.value.code in ("conversion_unavailable", "git_failed")
        codec = {"UTF-16": "utf-16", "UTF-16LE": "utf-16-le", "UTF-16BE": "utf-16-be",
                 "UTF-32": "utf-32", "UTF-32LE": "utf-32-le", "UTF-32BE": "utf-32-be", "ASCII": "ascii"}[encoding]
        (repo / "bad.txt").write_bytes("valid\r\n".encode(codec))
        assert store.read_blob(tg.snapshot_tree(store), "bad.txt") == b"valid\n"


@pytest.mark.parametrize("bridge", ["checked", "completed"])
def test_explicit_lane_transport_bridge_keeps_failed_worker_results_typed(repo, bridge):
    @tg._lane_operation
    def operation(store, *, _runner=None):
        def query():
            with pytest.raises(gitsafe.GitError) as caught:
                if bridge == "checked":
                    gitsafe_run.checked(["cat-file", "blob", "0" * 40], repo, runner=_runner.run,
                        error=ValueError, git_error=gitsafe.GitError, timeout=10, stdin=None)
                else:
                    gitsafe_run.completed(["cat-file", "blob", "0" * 40], repo, runner=_runner.run, error=ValueError)
            assert caught.value.code == "git_failed"
            assert "00000000" not in str(caught.value)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(query).result(timeout=5)
    with new_store(repo) as store:
        operation(store)


def test_stat_clean_file_predating_native_attributes_is_kept_like_git_add(repo, tmp_path):
    context = make_store(repo)
    git(repo, "config", "core.autocrlf", "false")
    commit(repo, "old.txt", b"one\r\ntwo\r\n")
    oracle = tmp_path / "oracle"
    git(tmp_path, "-c", "core.autocrlf=false", "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        os.utime(target / "old.txt", (1000000000, 1000000000))
        git(target, "update-index", "--refresh")
        (target / ".gitattributes").write_bytes(b"*.txt text working-tree-encoding=UTF-16LE\n")
        git(target, "add", "--", ".gitattributes")
        git(target, "commit", "-qm", "native attributes without renormalization")
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert store.read_blob(expected, "old.txt") == b"one\r\ntwo\r\n"


@pytest.mark.parametrize("encoding,codec", [("ISO-8859-1", "latin-1"), ("CP1252", "cp1252"), ("SHIFT_JIS", "shift_jis")])
def test_native_finite_legacy_codepages_match_git_for_every_valid_unit(repo, tmp_path, encoding, codec):
    context = make_store(repo)
    units = [bytes((value,)) for value in range(256)]
    if codec == "shift_jis":
        units.extend(bytes((lead, trail)) for lead in (*range(0x81, 0xa0), *range(0xe0, 0xf0)) for trail in range(0x40, 0xfd))
    valid = []
    for unit in units:
        try:
            if unit.decode(codec).encode(codec) == unit:
                valid.append(unit)
        except UnicodeError:
            pass
    payload = b"\n".join(valid) + b"\n"
    oracle = tmp_path / "oracle"
    git(tmp_path, "clone", "-q", "--no-hardlinks", str(repo), str(oracle))
    for target in (repo, oracle):
        (target / ".gitattributes").write_bytes(("*.txt text working-tree-encoding=" + encoding + "\n").encode())
        (target / "all.txt").write_bytes(payload)
    git(oracle, "add", "-A")
    with context as store:
        expected = git(oracle, "write-tree").decode().strip()
        assert tg.snapshot_tree(store) == expected
        assert tg.snapshot_tree(store) == expected


@pytest.mark.parametrize("status,payload", [(0, b""), (1, b"filter.secret.clean\0"), (0, b"filter.secret.clean"), (2, b"")])
def test_lane_filter_observation_is_closed_and_retryable(repo, monkeypatch, status, payload):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    def invalid(real, args, *rest, **kwargs):
        if args == ["config", "--null", "--name-only", "--get-regexp", r"^filter\."]:
            return subprocess.CompletedProcess(args, status, payload, b"")
        return real(args, *rest, **kwargs)
    calls, popen = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return popen(argv, **kwargs)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        restore = patch_lane_run(monkeypatch, invalid)
        for _ in range(2):
            with pytest.raises(tg.GitRefusal) as caught:
                tg.plan_merge(store, parent, parent)
            assert caught.value.code == "merge_unavailable"
            assert "secret" not in str(caught.value)
        assert not any("merge-tree" in argv for argv in calls)
        restore()
        assert tg.plan_merge(store, parent, parent).status == "clean"


@pytest.mark.parametrize("drivers", [50, 80])
def test_lane_filter_options_deduplicate_and_bound_before_target_spawn(repo, monkeypatch, drivers):
    parent = git(repo, "rev-parse", "HEAD").decode().strip()
    config = repo / ".git/config"
    original = config.read_bytes()
    with config.open("a") as output:
        for index in range(drivers):
            output.write('\n[filter "d%d"]\nclean = forbidden\nsmudge = forbidden\nprocess = forbidden\nrequired = false\n' % index)
    calls, real = [], subprocess.Popen
    def record(argv, **kwargs):
        calls.append(argv)
        return real(argv, **kwargs)
    with new_store(repo) as store:
        monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))
        if drivers == 50:
            assert tg.plan_merge(store, parent, parent).status == "clean"
            assert len(calls) == 4
        else:
            with pytest.raises(tg.GitRefusal) as caught:
                tg.plan_merge(store, parent, parent)
            assert caught.value.code == "git_custody_refused"
            assert not any("merge-tree" in argv for argv in calls)
        config.write_bytes(original)
        assert tg.plan_merge(store, parent, parent).status == "clean"


def test_native_decode_checks_remaining_snapshot_budget_before_utf8_allocation(repo, monkeypatch):
    import codecs
    context = make_store(repo)
    (repo / ".gitattributes").write_bytes(b"*.txt text working-tree-encoding=ISO-8859-1\n")
    (repo / "!first.txt").write_bytes(b"\xe9" * 8)  # Eight input bytes become sixteen UTF-8 bytes.
    original_limit = tg.MAX_SNAPSHOT_BYTES
    class NoAllocation(str):
        def encode(self, *args, **kwargs):
            pytest.fail("UTF-8 payload was allocated beyond the remaining snapshot budget")
    def decoder(name):
        implementation = codecs.getincrementaldecoder(name)
        class Observed:
            def __init__(self):
                self.decoder = implementation()
            def decode(self, *args, **kwargs):
                return NoAllocation(self.decoder.decode(*args, **kwargs))
        return Observed
    with context as store:
        before = shared_bytes(repo)
        monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", 9)
        monkeypatch.setattr(tg, "codecs", SimpleNamespace(**{**vars(codecs), "getincrementaldecoder": decoder}))
        with pytest.raises(tg.GitRefusal) as caught:
            tg.snapshot_tree(store)
        assert caught.value.code == "size_limit"
        assert shared_bytes(repo) == before
        monkeypatch.setattr(tg, "codecs", codecs)
        monkeypatch.setattr(tg, "MAX_SNAPSHOT_BYTES", original_limit)
        assert store.read_blob(tg.snapshot_tree(store), "!first.txt") == b"\xc3\xa9" * 8
