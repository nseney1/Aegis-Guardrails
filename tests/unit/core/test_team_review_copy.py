"""Public review-copy API: typed refusals, legacy manifest parity, descriptor confinement."""
from __future__ import annotations

import errno
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from tests.conftest import symlink_or_skip
from tests.unit.core.test_gitsafe import (
    _bound_ordinary_root,
    _temporary_env,
    test_no_package_module_reaches_gitsafe_private_names as assert_public_reader_census,
)

import aegis_core.team_review_copy as review_copy
from aegis_core import gitsafe
from aegis_core.team_git import object_read_argv, object_read_env
from aegis_core.team_host_registry import child_environment


ROOT = Path(__file__).resolve().parents[3]
_HEX = "0123456789abcdef"


def _require_descriptors():
    if os.name != "posix" or not review_copy.descriptor_support():
        pytest.skip("dir_fd and O_NOFOLLOW are unavailable")
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not os.path.isdir(f"/proc/{os.getpid()}/fd/{fd}/."):
            pytest.skip("Git cannot address held directories")
    finally:
        os.close(fd)


@pytest.fixture(autouse=True)
def _review_umask():
    previous = os.umask(0o022)
    yield
    os.umask(previous)


class GitProcess:
    """Bounded git child. stderr is discarded; reads are the caller's size."""

    def __init__(self, popen):
        self.popen = popen
        self.closed = False

    def close_stdin(self):
        stream = self.popen.stdin
        if stream is not None and not stream.closed:
            stream.close()

    def read(self, count):
        return self.popen.stdout.read(count)

    def wait(self, timeout):
        return self.popen.wait(timeout=timeout)

    def kill(self):
        if self.popen.poll() is None:
            self.popen.kill()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.close_stdin()
        if self.popen.stdout is not None:
            self.popen.stdout.close()
        self.kill()
        try:
            self.popen.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.kill()
            self.popen.wait(timeout=5)


def real_spawn(repository, args, env, timeout):
    del timeout
    popen = subprocess.Popen(
        args, env=env, cwd=f"/proc/{os.getpid()}/fd/{repository}",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
    )
    return GitProcess(popen)


class Scripted:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def git_spawn(self, repository, args, env, timeout):
        del repository, timeout
        self.calls.append((tuple(args), env))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return _Buffer(reply)


class _Buffer:
    def __init__(self, reply):
        self.stdout = reply.get("stdout", b"")
        self.pos = 0
        self.code = reply.get("code", 0)
        self.closed = False

    def close_stdin(self):
        return None

    def read(self, count):
        chunk = self.stdout[self.pos:self.pos + count]
        self.pos += len(chunk)
        return chunk

    def wait(self, timeout):
        del timeout
        return self.code

    def kill(self):
        return None

    def close(self):
        self.closed = True


def _records(tmp_path):
    records = tmp_path / ".review-records"
    records.mkdir(mode=0o700, exist_ok=True)
    return str(records)


def _keywords(spawn, tmp_path, child=None, *, program=None):
    def port(repository, args, env, timeout):
        return spawn(repository, args, env, timeout)

    port.executable = program or shutil.which("git")
    return {
        "object_read_argv": object_read_argv,
        "object_read_env": object_read_env,
        "child_environment": child or child_environment,
        "git_spawn": port,
        "preparation_dir": _records(tmp_path),
    }


def _patch_readers(monkeypatch, *, sizes=gitsafe.blob_sizes, blobs=gitsafe.read_blobs, custody=gitsafe.custody):
    ports = SimpleNamespace(blob_sizes=sizes, read_blobs=blobs, custody=custody, GitError=gitsafe.GitError)
    monkeypatch.setattr(review_copy, "gitsafe", ports)


def _git(path, *args, input_bytes=None):
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "Reviewer",
        "GIT_AUTHOR_EMAIL": "reviewer@example.com",
        "GIT_COMMITTER_NAME": "Reviewer",
        "GIT_COMMITTER_EMAIL": "reviewer@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    })
    done = subprocess.run(
        ["git", *args], cwd=path, input=input_bytes, capture_output=True, env=env, timeout=30,
    )
    if done.returncode != 0:
        raise AssertionError(done.stderr.decode("utf-8", "replace"))
    return done.stdout


def _init_repo(path):
    try:
        _git(path, "init", "-q", "-b", "develop")
    except AssertionError:
        _git(path, "init", "-q")
        _git(path, "checkout", "-q", "-b", "develop")


def _scripted_repo(tmp_path):
    repo = tmp_path / "repository"
    repo.mkdir()
    _init_repo(repo)
    return repo


def make_repo(tmp):
    _require_descriptors()
    path = tmp / "repository"
    path.mkdir()
    _init_repo(path)
    (path / "src").mkdir()
    (path / "src" / "app.py").write_text("value = 1\n")
    (path / "lines.txt").write_bytes(b"line one\nline two\n")
    (path / ".gitattributes").write_text("*.txt text eol=crlf\nsrc/app.py export-ignore\n")
    symlink_or_skip("/etc/hostname", path / "link")
    _git(path, "add", ".")
    _git(path, "commit", "-qm", "base commit")
    base = _git(path, "rev-parse", "HEAD").decode().strip()
    base_tree = _git(path, "rev-parse", "HEAD^{tree}").decode().strip()
    (path / "src" / "app.py").write_text("value = 2\n")
    (path / "src" / "added.py").write_text("new file\n")
    _git(path, "add", ".")
    _git(path, "commit", "-qm", "feat: candidate subject")
    candidate = _git(path, "rev-parse", "HEAD").decode().strip()
    candidate_tree = _git(path, "rev-parse", "HEAD^{tree}").decode().strip()
    return path, base, base_tree, candidate, candidate_tree


def _prepare(repo, base, candidate, out, **extra):
    return review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(real_spawn, repo.parent), **extra)


def _legacy(command, *args):
    script = ROOT / "tools" / "hierarchy_review.py"
    done = subprocess.run(
        [sys.executable, "-I", str(script), command, *args], capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return done.returncode, done.stdout, done.stderr


def _manifest(folder):
    return json.loads((folder / "manifest.json").read_text(encoding="ascii"))


def _stable(manifest):
    body = dict(manifest)
    body.pop("created_at", None)
    body.pop("repository", None)
    return body


def _fds():
    return set(os.listdir("/proc/self/fd"))


def test_unsupported_platform_refuses_before_git_or_output(monkeypatch, tmp_path):
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: False)
    calls = []

    def spawn(*args, **kwargs):
        del args, kwargs
        calls.append(True)
        raise AssertionError("git must not start")

    out = tmp_path / "review"
    code, result = review_copy.prepare(
        str(tmp_path), _HEX * 5, _HEX * 5, str(out), **_keywords(spawn, tmp_path),
    )
    assert code == 2
    assert result["code"] == "unsupported_platform"
    assert result["reason"] == "unsupported_platform"
    assert result["next_action"]
    assert "error" not in result
    assert calls == []
    checked, verified = review_copy.verify(str(out))
    assert checked == 2 and verified["code"] == "unsupported_platform"
    removed, gone = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert removed == 2 and gone["code"] == "unsupported_platform"
    assert not out.exists()
    assert list(tmp_path.glob(".pending-*")) == []


def test_missing_ports_refuse_without_output(tmp_path):
    _require_descriptors()
    out = tmp_path / "review"
    code, result = review_copy.prepare(str(tmp_path), _HEX * 5, _HEX * 5, str(out))
    assert code == 2 and result["code"] == "port_required"
    assert not out.exists()


@pytest.mark.parametrize("base,candidate", [
    ("develop", _HEX * 5),
    (_HEX * 5, "HEAD"),
    (_HEX * 5, "--output=/tmp/x"),
    ("0" * 39, _HEX * 5),
    ("G" * 40, _HEX * 5),
])
def test_invalid_commit_ids_refuse_before_git(tmp_path, base, candidate):
    _require_descriptors()
    calls = []
    out = tmp_path / "review"
    code, result = review_copy.prepare(
        str(tmp_path / "repository"), base, candidate, str(out),
        **_keywords(lambda *args, **kwargs: calls.append(args), tmp_path),
    )
    assert code == 2 and result["code"] == "invalid_commit"
    assert calls == []
    assert not out.exists()
    assert str(tmp_path) not in json.dumps(result)
    assert base not in json.dumps(result) and candidate not in json.dumps(result)


def test_unknown_commit_refuses_and_retry_succeeds(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    before = _fds() if Path("/proc/self/fd").exists() else None
    code, result = _prepare(repo, "0" * 40, candidate, out)
    assert code == 2 and result["code"] == "commit_missing"
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    if before is not None:
        assert _fds() == before
    code, ready = _prepare(repo, base, candidate, out)
    assert code == 0 and ready["base"]["commit"] == base and ready["candidate"]["commit"] == candidate
    checked, body = review_copy.verify(str(out), expect_manifest=ready["manifest_sha256"])
    assert checked == 0 and body["ok"] is True and body["problems"] == []
    removed, gone = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert removed == 0 and gone["removed"] == str(out) and not out.exists()


def test_tree_mismatch_leaves_no_folder(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    code, result = _prepare(repo, base, candidate, out, expect_candidate_tree="0" * 40)
    assert code == 2 and result["code"] == "tree_mismatch"
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    assert "0" * 40 not in json.dumps(result)


def test_missing_object_refuses_without_fetch(tmp_path):
    _require_descriptors()
    repo = tmp_path / "repository"
    repo.mkdir()
    _init_repo(repo)
    out = tmp_path / "review"
    commit = "a" * 40
    tree = "b" * 40
    oid = "c" * 40
    listing = b"100644 blob " + oid.encode() + b"\tapp.py\0"
    scripted = Scripted([
        {"stdout": b"/elsewhere\n", "code": 1},
        {"stdout": b".git\n"},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": listing},
        {"stdout": listing},
    ])
    code, result = review_copy.prepare(
        str(repo), commit, commit, str(out), **_keywords(scripted.git_spawn, tmp_path),
    )
    assert code == 2 and result["code"] == "object_missing"
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    assert all("fetch" not in " ".join(args) for args, _env in scripted.calls)
    assert any(env.get("GIT_NO_LAZY_FETCH") == "1" and env.get("GIT_ALLOW_PROTOCOL") == ""
               for _args, env in scripted.calls)
    assert oid not in json.dumps(result)


def test_filters_symlink_and_submodule_match_the_legacy_copy(tmp_path):
    repo, base, base_tree, candidate, candidate_tree = make_repo(tmp_path)
    _git(repo, "update-index", "--add", "--cacheinfo", "160000," + "a" * 40 + ",vendored")
    _git(repo, "commit", "-qm", "add a submodule entry")
    candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
    out = tmp_path / "review"
    code, result = _prepare(
        repo, base, candidate, out, expect_base_tree=base_tree, expect_candidate_tree=None,
    )
    assert code == 0
    assert (out / "base" / "lines.txt").read_bytes() == b"line one\nline two\n"
    link = out / "base" / "link"
    assert not link.is_symlink()
    assert link.read_text(encoding="utf-8") == "/etc/hostname"
    listed = [json.loads(line) for line in (out / "candidate.files.jsonl").read_text().splitlines()]
    assert {"path": "vendored", "mode": "160000", "commit": "a" * 40} in listed
    assert not (out / "candidate" / "vendored").exists()
    checked, body = review_copy.verify(str(out))
    assert checked == 0 and body["ok"] is True
    assert result["manifest_sha256"] == hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    legacy_out = tmp_path / "legacy"
    status, stdout, stderr = _legacy(
        "prepare", "--repository", str(repo), "--base", base, "--candidate", candidate, "--out", str(legacy_out),
    )
    assert status == 0, stdout + stderr
    assert _stable(_manifest(out)) == _stable(_manifest(legacy_out))
    assert (out / "changes.diff").read_bytes() == (legacy_out / "changes.diff").read_bytes()
    assert (out / "commits.txt").read_bytes() == (legacy_out / "commits.txt").read_bytes()
    checked, body = review_copy.verify(str(out))
    status, stdout, stderr = _legacy("verify", "--out", str(legacy_out))
    assert status == 0, stdout + stderr
    legacy_body = json.loads(stdout)
    assert checked == 0 and body["ok"] is True and legacy_body["ok"] is True
    assert body["problems"] == legacy_body["problems"] == []
    assert body["base"] == legacy_body["base"] and body["candidate"] == legacy_body["candidate"]
    status, stdout, stderr = _legacy("remove", "--out", str(legacy_out))
    assert status == 0, stdout + stderr
    assert json.loads(stdout)["removed"] == str(legacy_out) and not legacy_out.exists()
    removed, gone = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert removed == 0 and gone["removed"] == str(out) and not out.exists()


def test_verify_names_the_side_and_problem_then_remove_refuses_a_foreign_folder(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    code, _ready = _prepare(repo, base, candidate, out)
    assert code == 0
    target = out / "candidate" / "src" / "app.py"
    os.chmod(target.parent, 0o755)
    os.chmod(target, 0o644)
    target.write_bytes(b"value = 3\n")
    checked, body = review_copy.verify(str(out))
    assert checked == 3 and body["ok"] is False
    assert body["code"] == "copy_differs" and body["reason"] == "copy_differs"
    assert any(row == "candidate/src/app.py changed" for row in body["problems"])
    assert body["problem_count"] == len(body["problems"]) or body["problem_count"] >= 1
    foreign = tmp_path / "precious"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("keep\n")
    status, refused = review_copy.remove(str(foreign), preparation_dir=_records(tmp_path))
    assert status == 2 and refused["code"] == "not_review_copy"
    assert (foreign / "keep.txt").read_text() == "keep\n"


def test_prepare_verify_remove_follow_the_dogfood_flow(tmp_path):
    repo, base, _base_tree, candidate, candidate_tree = make_repo(tmp_path)
    out = tmp_path / "reviews" / "review-1"
    trace = tmp_path / "review-git.jsonl"
    markers = {"CODEX_SESSION_ID": "fixture-session", "ANTHROPIC_API_KEY": "fixture-billing", "GIT_TRACE": "0"}
    ports = _keywords(real_spawn, tmp_path)
    ports["object_read_env"] = lambda: {
        **object_read_env(), "GIT_TRACE2_EVENT": str(trace), "GIT_TRACE2_ENV_VARS": ",".join(markers),
    }
    with _temporary_env(markers):
        code, prepared = review_copy.prepare(str(repo), base, candidate, str(out), expect_candidate_tree=candidate_tree, **ports)
    assert code == 0 and prepared["candidate"]["tree"] == candidate_tree
    assert (out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"
    checked, body = review_copy.verify(str(out), expect_manifest=prepared["manifest_sha256"])
    assert checked == 0 and body["ok"] is True and body["manifest_sha256"] == prepared["manifest_sha256"]
    removed, gone = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert removed == 0 and gone == {"removed": str(out)}
    assert not out.exists()
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    children = {event["sid"] for event in events if event["event"] == "start"}
    commands = {event["sid"]: event["name"] for event in events if event["event"] == "cmd_name"}
    assert children == commands.keys()
    assert Counter(commands.values()) == {"cat-file": 4, "init": 1, "rev-parse": 6, "ls-tree": 2, "diff": 2, "log": 1}
    for sid in children:
        assert not markers.keys() & {event.get("param") for event in events if event["sid"] == sid}

@pytest.mark.parametrize("supplied", [
    False, b"a" * 64, "", "a" * 63, "a" * 65, "A" * 64, "g" * 64,
    "ａ" + "a" * 63, "a" * 63 + " ", "a" * 63 + "\0", "a" * 63 + "\n",
    "a" * 31 + "\u2028" + "a" * 32,
])
def test_verify_refuses_malformed_expected_manifest_before_folder_access(monkeypatch, tmp_path, supplied):
    opened = []

    def track_open(*args, **kwargs):
        opened.append(args)
        raise OSError(errno.EACCES, "unexpected folder access")

    monkeypatch.setattr(review_copy, "descriptor_support", lambda: True)
    monkeypatch.setattr(review_copy, "os", SimpleNamespace(**{**vars(os), "open": track_open}))
    assert review_copy.verify(str(tmp_path / "missing"), expect_manifest=supplied) == (2, {
        "reason": "invalid_input",
        "code": "invalid_input",
        "next_action": "Pass expect_manifest as a 64-character lowercase hexadecimal SHA-256 digest.",
    })
    assert opened == []


def test_verify_unsupported_platform_takes_precedence_over_malformed_expected_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: False)
    assert review_copy.verify(str(tmp_path / "missing"), expect_manifest="typo") == (2, {
        "reason": "unsupported_platform",
        "code": "unsupported_platform",
        "next_action": "Use a platform with directory descriptors and no-follow opens.",
    })


def test_verify_uses_the_retained_prepare_digest_for_concurrent_comparisons(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    status, prepared = _prepare(repo, base, candidate, out)
    assert status == 0
    retained = prepared["manifest_sha256"]
    clean = {
        "ok": True, "manifest_sha256": retained, "base": base, "candidate": candidate,
        "problems": [], "problem_count": 0,
    }
    assert review_copy.verify(str(out), expect_manifest=retained) == (0, clean)

    manifest = out / "manifest.json"
    changed_bytes = manifest.read_bytes() + b"\n"
    mode = stat.S_IMODE(manifest.stat().st_mode)
    manifest.chmod(mode | stat.S_IWUSR)
    manifest.write_bytes(changed_bytes)
    manifest.chmod(mode)
    changed = {**clean, "manifest_sha256": hashlib.sha256(changed_bytes).hexdigest()}
    mismatch = {
        **changed, "ok": False, "reason": "copy_differs", "code": "copy_differs",
        "next_action": "Inspect the named side and problem, then prepare a fresh copy.",
        "problems": ["manifest.json does not match the recorded hash"], "problem_count": 1,
    }
    before = _snapshot(out)
    expected = (None, retained, "typo")
    start = threading.Barrier(len(expected))

    def verify(supplied):
        start.wait(timeout=5)
        return review_copy.verify(str(out), expect_manifest=supplied)

    with ThreadPoolExecutor(max_workers=len(expected)) as pool:
        jobs = [pool.submit(verify, supplied) for supplied in expected]
        consistent, differs, refused = [job.result(timeout=10) for job in jobs]
    assert consistent == (0, changed)
    assert differs == (3, mismatch)
    assert (refused[0], refused[1]["code"]) == (2, "invalid_input")
    assert review_copy.verify(str(out), expect_manifest=changed["manifest_sha256"]) == (0, changed)
    assert _snapshot(out) == before


def test_remove_refuses_a_checkout_with_a_planted_manifest(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    (repo / "manifest.json").write_bytes((out / "manifest.json").read_bytes())

    def snapshot():
        return {p.relative_to(repo): (p.lstat().st_mode, os.readlink(p) if p.is_symlink()
                else p.read_bytes() if p.is_file() else None) for p in repo.rglob("*")}

    before = snapshot()
    status, result = review_copy.remove(str(repo), preparation_dir=_records(tmp_path))
    assert (status, result.get("code")) == (2, "not_review_copy")
    assert (repo / ".git").is_dir() and snapshot() == before


def test_remove_requires_unchanged_manifest_and_private_state(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    records = Path(_records(tmp_path))
    assert _prepare(repo, base, candidate, out)[0] == 0
    manifest = out / "manifest.json"
    original = manifest.read_bytes()
    before = out.stat().st_mode
    os.chmod(manifest, 0o644)
    manifest.write_bytes(original + b"\n")
    assert review_copy.remove(str(out), preparation_dir=str(records))[1]["code"] == "not_review_copy"
    assert out.stat().st_mode == before and (out / ".git").is_dir()
    assert len(list(records.iterdir())) == 1
    manifest.write_bytes(original)
    os.chmod(manifest, 0o444)
    os.chmod(records, 0o755)
    assert review_copy.remove(str(out), preparation_dir=str(records))[1]["code"] == "not_review_copy"
    assert out.stat().st_mode == before and manifest.read_bytes() == original
    os.chmod(records, 0o700)
    assert review_copy.remove(str(out), preparation_dir=str(records))[0] == 0
    assert not out.exists() and not list(records.iterdir())


@pytest.mark.parametrize("placement", ["checkout", "git-dir", "ancestor", "non-ascii-ancestor", "absent", "non-private"])
def test_prepare_refuses_invalid_preparation_directory_before_git(tmp_path, placement):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    if placement == "non-ascii-ancestor":
        _git(repo, "branch", "-m", "review-é./topic")
    source = repo / "src" if placement in ("ancestor", "non-ascii-ancestor") else repo
    places = {"checkout": repo, "git-dir": repo / ".git", "ancestor": repo, "non-ascii-ancestor": repo,
              "non-private": tmp_path}
    state = places[placement] / "state" if placement in places else None
    if state is not None:
        state.mkdir(mode=0o755 if placement == "non-private" else 0o700)
    calls = []

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    out = tmp_path / "never-created" / "review"
    options = dict(_keywords(observe, tmp_path), preparation_dir=str(state) if state else None)
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **options)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.parent.exists() and (state is None or not list(state.iterdir()))
    assert _prepare(repo, base, candidate, out)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0


@pytest.mark.parametrize("case", [
    "planted-bare", "empty-dotgit", "linked-head", "gitfile", "symlink", "symlink-gitfile", "commondir",
])
def test_prepare_checks_all_repository_metadata_boundaries_before_git(tmp_path, case):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    source, state_root = outer / "src", outer
    if case == "planted-bare":
        (source / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        for name in ("objects", "refs"):
            (source / name).mkdir()
        source = source / "deep"
        source.mkdir()
    elif case == "empty-dotgit":
        bare = tmp_path / "bare"
        _git(tmp_path, "clone", "--bare", str(outer), str(bare))
        source, state_root = bare / "src", bare
        source.mkdir()
        (bare / ".git").mkdir()
    elif case == "linked-head":
        head = outer / ".git" / "HEAD"
        head.rename(head.with_name("saved-head"))
        symlink_or_skip("refs/heads/develop", head)
    elif case in ("gitfile", "symlink", "symlink-gitfile"):
        admin = tmp_path / "administration"
        if case == "gitfile":
            source = tmp_path / "separate"
            _git(tmp_path, "clone", "--separate-git-dir", str(admin), str(outer), str(source))
        elif case == "symlink":
            marker = outer / ".git"
            marker.rename(admin)
            symlink_or_skip(f"{admin}/", marker)
        else:
            source = tmp_path / "separate"
            _git(tmp_path, "clone", "--separate-git-dir", str(admin), str(outer), str(source))
            redirected = tmp_path / "markers" / "target"
            redirected.parent.mkdir()
            original = source / ".git"
            original.rename(redirected)
            redirected.write_text(f"gitdir: {os.path.relpath(admin, source)}\n", encoding="utf-8")
            symlink_or_skip(redirected, original)
        state_root = admin
    else:
        source, state_root = tmp_path / "linked", outer / ".git"
        _git(outer, "worktree", "add", "--detach", str(source), candidate)
    state = Path(_records(state_root))
    out, calls = tmp_path / "new-parent" / "review", []

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    ports = dict(_keywords(observe, tmp_path), preparation_dir=str(state))
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **ports)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.parent.exists() and not list(state.iterdir())

    if case == "planted-bare":
        for name in ("HEAD", "objects", "refs"):
            path = source.parent / name
            path.rmdir() if path.is_dir() else path.unlink()
    elif case == "empty-dotgit":
        (state_root / ".git").rmdir()
        source = state_root
    elif case == "linked-head":
        head.unlink()
        head.with_name("saved-head").rename(head)
    valid = _keywords(observe, tmp_path)
    assert review_copy.prepare(str(source), base, candidate, str(out), **valid)[0] == 0
    assert calls and review_copy.remove(str(out), preparation_dir=valid["preparation_dir"])[0] == 0


@pytest.mark.parametrize("case", [
    "missing", "symlink-component", "oversized", "multiline", "shared-link", "symlink-file-as-directory",
])
def test_prepare_refuses_unresolved_repository_metadata_and_can_retry(tmp_path, case):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    marker, admin = repo / ".git", tmp_path / "storage" / "admin"
    admin.parent.mkdir()
    marker.rename(admin)
    pointer = str(admin)
    if case == "missing":
        pointer = str(tmp_path / "missing")
    elif case in ("symlink-component", "shared-link"):
        alias = tmp_path / "aliased-storage"
        symlink_or_skip(admin.parent, alias)
        pointer = str(alias / "admin")
    elif case == "oversized":
        pointer = "x" * 4096
    elif case == "multiline":
        pointer += "\nsecond-line"
    common = admin / "commondir"
    if case == "shared-link":
        common.write_text(pointer + "\n", encoding="utf-8")
        pointer = str(admin)
    if case == "symlink-file-as-directory":
        target = tmp_path / "gitfile"
        target.write_text(f"gitdir: {admin}\n", encoding="utf-8")
        symlink_or_skip(f"{target}/", marker)
    else:
        marker.write_text(f"gitdir: {pointer}\n", encoding="utf-8")
    out, calls = tmp_path / "new-parent" / "review", []

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    ports = _keywords(observe, tmp_path)
    status, result = review_copy.prepare(str(repo), base, candidate, str(out), **ports)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.parent.exists() and not list(Path(ports["preparation_dir"]).iterdir())
    common.unlink(missing_ok=True)
    marker.unlink()
    admin.rename(marker)
    assert review_copy.prepare(str(repo), base, candidate, str(out), **ports)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0


_GIT_LINE_ENDINGS = (
    (b"\n\n", "\n"),
    (b"\r\r\n", "\r"),
    (b"\n\r\n", "\n"),
)


def _plant_decoy(base, relative):
    current = base
    parts = Path(relative).parts
    for part in parts[:-1]:
        current = current.parent if part == ".." else current / part
    leaf = parts[-1]
    if leaf != "..":
        (current / leaf).mkdir(exist_ok=True)


def _spawn_log():
    calls = []

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    return calls, observe


def _assert_inside_then_outside(source, anchor, base, candidate, calls, observe, tmp_path):
    out = tmp_path / "review"
    inside = dict(_keywords(observe, tmp_path), preparation_dir=_records(anchor))
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **inside)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.exists() and not list(Path(inside["preparation_dir"]).iterdir())
    outside = _keywords(observe, tmp_path)
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **outside)
    assert status == 0, result
    assert calls and review_copy.remove(str(out), preparation_dir=outside["preparation_dir"])[0] == 0


@pytest.mark.parametrize("ending,suffix", _GIT_LINE_ENDINGS, ids=["lf-lf", "cr-cr-lf", "lf-cr-lf"])
def test_prepare_matches_git_trailing_newlines_in_a_gitfile(tmp_path, ending, suffix):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    source, admin = tmp_path / "separate", tmp_path / "admin"
    _git(tmp_path, "clone", "--separate-git-dir", str(admin), str(outer), str(source))
    relative = os.path.relpath(admin, source)
    (source / ".git").write_bytes(b"gitdir: " + os.fsencode(relative) + ending)
    _plant_decoy(source, relative + suffix)
    calls, observe = _spawn_log()
    _assert_inside_then_outside(source, admin, base, candidate, calls, observe, tmp_path)


@pytest.mark.parametrize("ending,suffix", _GIT_LINE_ENDINGS, ids=["lf-lf", "cr-cr-lf", "lf-cr-lf"])
def test_prepare_matches_git_trailing_newlines_in_commondir(tmp_path, ending, suffix):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    source = tmp_path / "linked"
    _git(outer, "worktree", "add", "--detach", str(source), candidate)
    pointer = (source / ".git").read_bytes()
    assert pointer.startswith(b"gitdir: ")
    gitdir = Path(os.fsdecode(pointer[8:].removesuffix(b"\n").removesuffix(b"\r")))
    if not gitdir.is_absolute():
        gitdir = (source / gitdir).resolve()
    marker = gitdir / "commondir"
    body = marker.read_bytes().removesuffix(b"\n").removesuffix(b"\r")
    marker.write_bytes(body + ending)
    _plant_decoy(gitdir, os.fsdecode(body + suffix.encode("ascii")))
    common = gitdir
    for part in Path(os.fsdecode(body)).parts:
        common = common.parent if part == ".." else common / part
    calls, observe = _spawn_log()
    _assert_inside_then_outside(source, common, base, candidate, calls, observe, tmp_path)


@pytest.mark.parametrize("name,payload", (
    (" X", b"gitdir:  X\n"),
    ("X ", b"gitdir: X \n"),
), ids=["leading-space", "trailing-space"])
def test_prepare_keeps_gitfile_spaces_like_git(tmp_path, name, payload):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    source, staging = tmp_path / "separate", tmp_path / "staging-admin"
    _git(tmp_path, "clone", "--separate-git-dir", str(staging), str(outer), str(source))
    admin = source / name
    staging.rename(admin)
    (source / ".git").write_bytes(payload)
    calls, observe = _spawn_log()
    _assert_inside_then_outside(source, admin, base, candidate, calls, observe, tmp_path)


@pytest.mark.parametrize("payload", (b"gitdir: \n\n", b"gitdir: ../admin\0\n"), ids=["empty", "embedded-nul"])
def test_prepare_gitfile_rejects_empty_and_nul_paths(tmp_path, payload):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    source, admin = tmp_path / "separate", tmp_path / "admin"
    _git(tmp_path, "clone", "--separate-git-dir", str(admin), str(outer), str(source))
    (source / ".git").write_bytes(payload)
    out, calls, observe = tmp_path / "review", *_spawn_log()
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **_keywords(observe, tmp_path))
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.exists() and not list(Path(_keywords(observe, tmp_path)["preparation_dir"]).iterdir())


@pytest.mark.parametrize("at_source", [False, True], ids=["intermediate", "source"])
@pytest.mark.parametrize("marker", [
    "bare-names", "invalid-gitfile", "invalid-gitdir", "invalid-head", "shared-gitdir", "symlinked-target",
])
def test_prepare_ignores_unproven_nested_repository_before_git(tmp_path, at_source, marker):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    source = repo / "src" / "deep"
    source.mkdir()
    marked = source if at_source else source.parent
    admin = marked if marker == "bare-names" else marked / ".git"
    if marker == "bare-names":
        for name in ("HEAD", "objects", "refs"):
            (admin / name).touch()
    elif marker == "invalid-gitfile":
        admin.write_bytes(b"not an administrative path\n")
    elif marker == "shared-gitdir":
        admin.write_text(f"gitdir: {repo / '.git'}\n", encoding="utf-8")
    elif marker == "symlinked-target":
        independent, alias = tmp_path / "independent.git", tmp_path / "symlinked-admin"
        _git(tmp_path, "clone", "--bare", str(repo), str(independent))
        symlink_or_skip(independent, alias)
        admin.write_text(f"gitdir: {alias}\n", encoding="utf-8")
    else:
        admin.mkdir()
        if marker == "invalid-head":
            (admin / "HEAD").write_bytes(b"invalid head\n")
            for name in ("objects", "refs"):
                (admin / name).mkdir()
    state = Path(_records(repo))
    out, calls = tmp_path / "new-parent" / "review", []

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    options = dict(_keywords(observe, tmp_path), preparation_dir=str(state))
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **options)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.parent.exists() and not list(state.iterdir())

    if marker == "bare-names":
        for name in ("HEAD", "objects", "refs"):
            (admin / name).unlink()
    elif admin.is_dir():
        shutil.rmtree(admin)
    else:
        admin.unlink()
    valid = _keywords(real_spawn, tmp_path)
    assert review_copy.prepare(str(source), base, candidate, str(out), **valid)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=valid["preparation_dir"])[0] == 0


@pytest.mark.parametrize("layout", ["checkout", "gitfile", "relative-gitfile", "worktree", "non-ascii-head"])
def test_prepare_nested_checkout_requires_external_state_and_preserves_legacy_copy(tmp_path, layout):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    nested = outer / "nested"
    admin = tmp_path / "admin"
    if layout == "worktree":
        clone = tmp_path / "independent"
        _git(tmp_path, "clone", str(outer), str(clone))
        _git(clone, "worktree", "add", "--detach", str(nested), candidate)
    else:
        options = ("--separate-git-dir", str(admin)) if "gitfile" in layout else ()
        _git(tmp_path, "clone", *options, str(outer), str(nested))
        if layout == "relative-gitfile":
            (nested / ".git").write_text(f"gitdir: {os.path.relpath(admin, nested)}\n", encoding="utf-8")
        if layout == "non-ascii-head":
            _git(nested, "branch", "-m", "review-é./topic")
    source, out, legacy = nested / "src", outer / "review", outer / "legacy-review"
    status, result, err = _legacy("prepare", "--repository", str(source), "--base", base,
                                  "--candidate", candidate, "--out", str(legacy))
    assert status == 0, (result, err)

    state, calls = _records(outer), []

    def observe(root, argv, env, timeout):
        calls.append(argv)
        assert not {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"} & env.keys()
        return real_spawn(root, argv, env, timeout)

    ports = _keywords(observe, tmp_path)
    internal = dict(ports, preparation_dir=state)
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **internal)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.exists() and not list(Path(state).iterdir())
    status, result = review_copy.prepare(str(source), base, candidate, str(out), **ports)
    assert status == 0, result
    assert _stable(_manifest(out)) == _stable(_manifest(legacy))
    assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0
    assert _legacy("remove", "--out", str(legacy))[0] == 0


def test_prepare_rejects_a_gitfile_replaced_during_preflight(tmp_path, monkeypatch):
    outer, base, _, candidate, _ = make_repo(tmp_path)
    nested = outer / "nested"
    _git(tmp_path, "clone", "--separate-git-dir", str(tmp_path / "admin"), str(outer), str(nested))
    marker, moved, replacement = nested / ".git", tmp_path / "saved-marker", tmp_path / "replacement"
    replacement.write_bytes(marker.read_bytes())
    identity = nested.stat()
    state, out = _records(tmp_path), tmp_path / "review"
    calls, changed = [], []

    def replace_marker(name, flags, *args, **kwargs):
        if name == ".git" and not changed and os.path.samestat(os.fstat(kwargs["dir_fd"]), identity):
            marker.rename(moved)
            replacement.rename(marker)
            changed.append(True)
        return os.open(name, flags, *args, **kwargs)

    def observe(*args):
        calls.append(args[1])
        return real_spawn(*args)

    proxy = SimpleNamespace(**{**vars(os), "open": replace_marker,
                               "supports_dir_fd": {*os.supports_dir_fd, replace_marker}})
    monkeypatch.setattr(review_copy, "os", proxy)
    ports = dict(_keywords(observe, tmp_path), preparation_dir=state)
    status, result = review_copy.prepare(str(nested), base, candidate, str(out), **ports)
    assert changed and (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.exists() and not list(Path(state).iterdir())
    marker.unlink()
    moved.rename(marker)
    assert review_copy.prepare(str(nested), base, candidate, str(out), **ports)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=state)[0] == 0


def test_prepare_uses_legacy_discovery_with_a_symlinked_inner_marker(tmp_path):
    outer, base, _, _, _ = make_repo(tmp_path)
    nested = outer / "nested"
    _git(tmp_path, "clone", str(outer), str(nested))
    (nested / "independent.txt").write_bytes(b"nested only\n")
    _git(nested, "add", "independent.txt")
    _git(nested, "commit", "-qm", "nested candidate")
    nested_candidate = _git(nested, "rev-parse", "HEAD").decode().strip()
    source = nested / "src"
    marker = source / ".git"
    symlink_or_skip(outer / ".git", marker)
    out, calls = tmp_path / "review", []

    def observe(root, argv, env, timeout):
        calls.append(argv)
        assert not {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"} & env.keys()
        return real_spawn(root, argv, env, timeout)

    ports = _keywords(observe, tmp_path)
    internal = dict(ports, preparation_dir=_records(outer))
    status, result = review_copy.prepare(str(source), base, nested_candidate, str(out), **internal)
    assert (status, result.get("code"), calls) == (2, "record_required", [])
    assert not out.exists()
    legacy = tmp_path / "legacy-review"
    status, body, _ = _legacy("prepare", "--repository", str(source), "--base", base,
                              "--candidate", nested_candidate, "--out", str(legacy))
    assert status == 2 and "commit is not in the repository" in body and not legacy.exists()
    status, result = review_copy.prepare(str(source), base, nested_candidate, str(out), **ports)
    assert (status, result.get("code")) == (2, "commit_missing")
    assert calls and not out.exists()
    marker.unlink()
    status, result = review_copy.prepare(str(source), base, nested_candidate, str(out), **ports)
    assert status == 0, result
    assert (out / "candidate" / "independent.txt").read_bytes() == b"nested only\n"
    assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0


def test_prepare_replaces_a_stale_record_for_recycled_directory_identity(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out, state = tmp_path / "review", Path(_records(tmp_path))
    stale_paths = []

    def recycled_identity(root, argv, env, timeout):
        if "init" in argv:
            info = os.fstat(root)
            stale = state / f"{info.st_dev:x}-{info.st_ino:x}"
            stale.write_bytes(f"{info.st_dev:x}:{info.st_ino:x}:{'0' * 64}\n".encode("ascii"))
            stale_paths.append(stale)
        return real_spawn(root, argv, env, timeout)

    status, result = review_copy.prepare(str(repo), base, candidate, str(out),
                                         **_keywords(recycled_identity, tmp_path))
    assert status == 0 and len(stale_paths) == 1, result
    assert stale_paths[0].read_bytes().split(b":")[-1] == result["manifest_sha256"].encode("ascii") + b"\n"
    assert review_copy.remove(str(out), preparation_dir=str(state))[0] == 0
    assert not out.exists() and not list(state.iterdir())


@pytest.mark.parametrize("change", ["mode", "identity"])
def test_prepare_rechecks_state_privacy_before_publication_and_can_retry(tmp_path, change):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out, state = tmp_path / "new-parent" / "copy", Path(_records(tmp_path))

    previous = tmp_path / "original-state"

    def unprotect_state(*args):
        if change == "mode":
            state.chmod(0o755)
        elif not previous.exists():
            state.rename(previous)
            state.mkdir(mode=0o700)
        return real_spawn(*args)

    status, result = review_copy.prepare(str(repo), base, candidate, str(out),
                                         **_keywords(unprotect_state, tmp_path))
    assert (status, result["code"]) == (2, "record_required")
    assert not out.parent.exists() and not list(state.iterdir())
    if change == "mode":
        state.chmod(0o700)
    else:
        assert not list(previous.iterdir())
        state.rmdir()
        previous.rename(state)
    assert _prepare(repo, base, candidate, out)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=str(state))[0] == 0


def test_prepare_respects_a_bare_repository_inside_a_checkout(tmp_path):
    checkout, base, _, candidate, _ = make_repo(tmp_path)
    bare, out = checkout / "bare.git", tmp_path / "review"
    _git(tmp_path, "clone", "--bare", str(checkout), str(bare))
    state = _records(tmp_path)
    options = dict(_keywords(real_spawn, tmp_path), preparation_dir=state)

    status, result = review_copy.prepare(str(bare), base, candidate, str(out), **options)
    assert status == 0, result
    assert review_copy.remove(str(out), preparation_dir=state)[0] == 0


def test_remove_checks_prepared_root_again_after_preflight(tmp_path, monkeypatch):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out, moved = tmp_path / "review", tmp_path / "moved"
    assert _prepare(repo, base, candidate, out)[0] == 0
    identity = out.stat()

    def move_root(fd):
        if os.path.samestat(os.fstat(fd), identity) and not moved.exists() and not (tmp_path / "foreign").exists():
            out.rename(moved)
            out.mkdir()
            (out / "keep").write_bytes(b"foreign")
        return os.scandir(fd)

    monkeypatch.setattr(review_copy, "os", SimpleNamespace(
        **{**vars(os), "scandir": move_root, "supports_fd": {*os.supports_fd, move_root}}))
    result = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert (result[0], result[1]["code"]) == (2, "not_review_copy")
    assert (out / "keep").read_bytes() == b"foreign"
    assert moved.stat().st_mode == identity.st_mode and (moved / "manifest.json").is_file()
    out.rename(tmp_path / "foreign")
    moved.rename(out)
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0


def test_prepare_requires_private_external_record_state_and_can_retry(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    records = Path(_records(tmp_path))
    records.chmod(0o755)
    status, result = _prepare(repo, base, candidate, out)
    assert (status, result["code"]) == (2, "record_required")
    assert not out.exists() and not list(tmp_path.glob(".pending-*")) and not list(records.iterdir())
    records.chmod(0o700)
    assert _prepare(repo, base, candidate, out)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=str(records))[0] == 0


def test_prepare_uses_the_spawn_ports_git_outside_default_path(tmp_path, monkeypatch):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    owner_bin = tmp_path / "owner-bin"
    owner_bin.mkdir()
    selected = owner_bin / "git"
    symlink_or_skip(shutil.which("git"), selected)
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setattr("aegis_core.gitsafe_run.os", SimpleNamespace(**{**vars(os), "defpath": str(empty_bin)}))

    def spawn(repository, args, env, timeout):
        assert args[0] == str(selected)
        return real_spawn(repository, args, env, timeout)

    out = tmp_path / "review"
    with _bound_ordinary_root(repo):
        status, result = review_copy.prepare(
            str(repo), base, candidate, str(out), **_keywords(spawn, tmp_path, program=str(selected)))
    assert (status, result.get("code")) == (0, None)
    assert (out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"


@pytest.mark.parametrize("phase", ["stage", "scaffold", "lock"])
def test_prepare_rolls_back_with_a_low_descriptor_limit(tmp_path, phase):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    import resource

    out = tmp_path.joinpath(*(["new"] * 48 if phase == "stage" else ["new"]), "review")
    listing = b"100644 blob " + _git(repo, "rev-parse", base + ":src/app.py").strip()
    listing += b"\t" + b"d/" * 80 + b"file\0"

    borrowed = []

    def spawn(root, args, env, timeout):
        if phase == "lock" and "ls-tree" in args:
            return _Buffer({"stdout": listing})
        return real_spawn(root, args, env, timeout)

    def exhaust_at_scaffold(root, args, env, timeout):
        if phase == "scaffold" and "init" in args:
            try:
                for _ in range(limit):
                    borrowed.append(os.open(os.devnull, os.O_RDONLY))
            except OSError as error:
                assert error.errno == errno.EMFILE
                raise
            pytest.fail("the descriptor fixture did not reach EMFILE")
        return spawn(root, args, env, timeout)

    opened = [int(fd) for fd in _fds() if os.path.exists("/proc/self/fd/" + fd)]
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    slots = len(out.parent.parts) + 1 if phase == "stage" else 32
    limit = len(opened) + slots
    assert limit > max(opened) and (soft == resource.RLIM_INFINITY or limit < soft)
    resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
    try:
        status, result = review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(exhaust_at_scaffold, tmp_path))
        assert (status, result.get("code")) == (2, "filesystem")
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        for fd in borrowed:
            os.close(fd)
    assert bool(borrowed) == (phase == "scaffold")
    assert {int(fd) for fd in _fds() if os.path.exists("/proc/self/fd/" + fd)} == set(opened)
    assert not (tmp_path / "new").exists()
    assert review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(spawn, tmp_path))[0] == 0
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0


def test_remove_directory_open_count_is_linear_for_disjoint_chains(monkeypatch, tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    os.chmod(out, 0o755)
    chains, depth = 12, 72
    for branch in range(chains):
        current = out / str(branch)
        current.mkdir()
        for _ in range(depth - 1):
            current = current / "d"
            current.mkdir()
    opened = []

    def count_open(path, flags, *args, **kwargs):
        if flags & os.O_DIRECTORY:
            opened.append(path)
        return os.open(path, flags, *args, **kwargs)

    proxy = SimpleNamespace(**{**vars(os), "open": count_open})
    monkeypatch.setattr(review_copy, "os", proxy)
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: True)
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0
    assert len(opened) <= 5 * chains * depth
    assert not out.exists()


def test_remove_refuses_when_directory_parent_changes_during_preflight(monkeypatch, tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out, foreign = tmp_path / "review", tmp_path / "foreign"
    assert _prepare(repo, base, candidate, out)[0] == 0
    original = out / "candidate" / "src"
    os.chmod(original.parent, 0o755)
    os.chmod(original, 0o755)
    foreign.mkdir()
    moved, marker = foreign / "src", foreign / "keep"
    marker.write_text("outside")
    identity = original.stat()
    moves = []

    def replace_on_ascent(path, flags, *args, **kwargs):
        if path == ".." and not moves and os.path.samestat(os.fstat(kwargs["dir_fd"]), identity):
            original.rename(moved)
            moves.append(moved)
        return os.open(path, flags, *args, **kwargs)

    proxy = SimpleNamespace(**{**vars(os), "open": replace_on_ascent})
    monkeypatch.setattr(review_copy, "os", proxy)
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: True)
    status, result = review_copy.remove(str(out), preparation_dir=_records(tmp_path))
    assert (status, result.get("code")) == (2, "unsafe_path")
    assert (out / "manifest.json").is_file() and (moved / "app.py").is_file()
    assert marker.read_text() == "outside"
    moved.rename(original)
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0


def test_copy_uses_the_public_git_reader_and_passes_the_census(monkeypatch, tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    moved = tmp_path / "moved-repository"
    deadlines = []

    def reader(read):
        def bound(cwd, oids, *, timeout):
            deadlines.append(timeout)
            repo.rename(moved)
            try:
                assert os.path.samefile(cwd, moved)
                return read(cwd, oids, timeout=timeout)
            finally:
                moved.rename(repo)
        return bound

    _patch_readers(monkeypatch, sizes=reader(gitsafe.blob_sizes), blobs=reader(gitsafe.read_blobs))
    assert _prepare(repo, base, candidate, out)[0] == 0
    assert len(deadlines) == 4 and deadlines == sorted(deadlines, reverse=True)
    assert (out / "base" / "src" / "app.py").read_bytes() == b"value = 1\n"
    assert (out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"
    assert_public_reader_census()


def test_output_guards_refuse_without_creating_the_copy(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    inside = repo / "reviews" / "one"
    code, result = _prepare(repo, base, candidate, inside)
    assert code == 2 and result["code"] == "inside_repository"
    assert not (repo / "reviews").exists()
    existing = tmp_path / "review"
    existing.mkdir()
    code, result = _prepare(repo, base, candidate, existing)
    assert code == 2 and result["code"] == "output_exists"
    assert list(existing.iterdir()) == []
    code, result = review_copy.prepare(
        str(repo), base, candidate, "relative", **_keywords(real_spawn, tmp_path),
    )
    assert code == 2 and result["code"] == "unsafe_path"
    linked = tmp_path / "linked-repo"
    symlink_or_skip(repo, linked)
    code, result = _prepare(linked, base, candidate, tmp_path / "elsewhere")
    assert code == 2 and result["code"] == "unsafe_path"
    assert not (tmp_path / "elsewhere").exists()


@pytest.mark.parametrize("name", [" repository", "repository "])
@pytest.mark.parametrize("location, status, refusal", [
    ("internal-output", 2, "inside_repository"),
    ("internal-state", 2, "record_required"),
    ("sibling-output", 0, None),
    ("sibling-state", 0, None),
])
def test_prepare_uses_the_exact_checkout_top_for_containment(tmp_path, name, location, status, refusal):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    checkout = repo.rename(tmp_path / name)
    source = checkout / "nested"
    source.mkdir()
    repo.mkdir()  # A distinct sibling with the whitespace-stripped name.
    output_root = {"internal-output": checkout, "sibling-output": repo}.get(location, tmp_path)
    state_root = {"internal-state": checkout, "sibling-state": repo}.get(location, tmp_path)
    out = output_root / "reviews" / "one"
    ports = _keywords(real_spawn, state_root)

    actual, result = review_copy.prepare(str(source), base, candidate, str(out), **ports)
    assert (actual, result.get("code")) == (status, refusal)
    if status == 0:
        assert result["out"] == str(out)
        assert (out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"
        assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0
    else:
        assert not out.parent.exists() and not list(Path(ports["preparation_dir"]).iterdir())


def test_prepare_refuses_a_sibling_parent_swapped_during_checkout_discovery(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    checkout = repo.rename(tmp_path / "repository ")
    repo.mkdir()
    moved = tmp_path / "moved-sibling"
    replacement = tmp_path / "replacement"
    symlink_or_skip(checkout, replacement)
    out = repo / "review"

    def spawn(root, args, env, timeout):
        if "--git-dir" in args:
            repo.rename(moved)
            replacement.rename(repo)
        return real_spawn(root, args, env, timeout)

    ports = _keywords(spawn, tmp_path)
    status, result = review_copy.prepare(str(checkout), base, candidate, str(out), **ports)
    assert (status, result.get("code")) == (2, "unsafe_path")
    assert repo.is_symlink() and not (checkout / out.name).exists() and not list(moved.iterdir())
    assert not list(Path(ports["preparation_dir"]).iterdir())

    repo.unlink()
    moved.rename(repo)
    assert _prepare(checkout, base, candidate, out)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0


def test_prepare_refuses_state_inside_the_reported_checkout_top(tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    checkout = tmp_path / "reported-checkout "
    checkout.mkdir()
    (tmp_path / "reported-checkout").mkdir()
    out = tmp_path / "review"

    def spawn(root, args, env, timeout):
        # Exercise the check after Git answers, independent of the metadata preflight.
        if "--show-toplevel" in args:
            return _Buffer({"stdout": os.fsencode(checkout) + b"\n"})
        return real_spawn(root, args, env, timeout)

    ports = _keywords(spawn, checkout)
    status, result = review_copy.prepare(str(repo), base, candidate, str(out), **ports)
    assert (status, result.get("code")) == (2, "record_required")
    assert not out.exists() and not list(Path(ports["preparation_dir"]).iterdir())


@pytest.mark.parametrize("record, refusal", [
    (b"/untrusted\0path\n", "unsafe_path"),
    (b"/untrusted\npath\n", "unsafe_path"),
    (b"/untrusted/path\n\n", "unsafe_path"),
    (b"/untrusted/path\r\n", "unsafe_path"),
    (b"/untrusted/path\xff\n", "encoding"),
    (b"untrusted/path\n", "unsafe_path"),
    (b"\n", "unsafe_path"),
    pytest.param(b"/" + b"x" * review_copy.MAX_PATH_BYTES, "limit_exceeded", id="over-limit"),
])
def test_prepare_refuses_malformed_checkout_top_and_can_retry(tmp_path, record, refusal):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "new-parent" / "review"
    child = _Buffer({"stdout": record})

    def spawn(root, args, env, timeout):
        if "--show-toplevel" in args:
            return child
        return real_spawn(root, args, env, timeout)

    ports = _keywords(spawn, tmp_path)
    status, result = review_copy.prepare(str(repo), base, candidate, str(out), **ports)
    assert (status, result.get("reason"), result.get("code")) == (2, refusal, refusal)
    assert "untrusted" not in json.dumps(result)
    assert child.closed and not out.parent.exists()
    assert not list(Path(ports["preparation_dir"]).iterdir())

    assert _prepare(repo, base, candidate, out)[0] == 0
    assert review_copy.remove(str(out), preparation_dir=ports["preparation_dir"])[0] == 0


def test_unsafe_tree_path_leaves_nothing(tmp_path):
    repo, base, _base_tree, _candidate, _candidate_tree = make_repo(tmp_path)
    blob = _git(repo, "hash-object", "-w", "--stdin", input_bytes=b"planted\n").decode().strip()
    inner = _git(repo, "mktree", input_bytes=("100644 blob %s\tescaped\n" % blob).encode()).decode().strip()
    tree = _git(repo, "mktree", input_bytes=("040000 tree %s\t..\n" % inner).encode()).decode().strip()
    commit = _git(repo, "commit-tree", tree, "-m", "hostile tree").decode().strip()
    out = tmp_path / "review"
    code, result = _prepare(repo, base, commit, out)
    assert code == 2 and result["code"] == "unsafe_tree_path"
    assert not out.exists() and not (tmp_path / "escaped").exists()


def test_overdeep_tree_refuses_before_creating_output(monkeypatch, tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "new-parent" / "review"
    oid = _git(repo, "rev-parse", base + ":src/app.py").strip()
    listing = b"100644 blob " + oid + b"\t" + b"x/" * 1200 + b"file\0"
    mkdir_calls = []

    def record_mkdir(*args, **kwargs):
        mkdir_calls.append(True)
        raise AssertionError("prepare attempted a directory before validating depth")

    proxy = SimpleNamespace(**{**vars(os), "mkdir": record_mkdir,
                               "supports_dir_fd": {*os.supports_dir_fd, record_mkdir}})
    monkeypatch.setattr(review_copy, "os", proxy)

    def spawn(root, args, env, timeout):
        if "ls-tree" in args:
            return _Buffer({"stdout": listing})
        return real_spawn(root, args, env, timeout)

    status, result = review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(spawn, tmp_path))
    assert (status, result["code"]) == (2, "limit_exceeded")
    assert not mkdir_calls and not out.parent.exists()


def test_prepare_refuses_when_the_parent_descriptor_alias_is_unavailable(monkeypatch, tmp_path):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    proxy = SimpleNamespace(**{**vars(os), "getpid": lambda: -1})
    monkeypatch.setattr(review_copy, "os", proxy)
    out = tmp_path / "new-parent" / "review"
    status, result = _prepare(repo, base, candidate, out)
    assert (status, result["code"]) == (2, "unsupported_platform")
    assert not out.parent.exists()


def test_symlink_replacement_during_export_refuses_and_retry_succeeds(monkeypatch, tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    secret = tmp_path / "secret"
    planted = {"done": False}

    def read_blobs(cwd, oids, *, timeout):
        if not planted["done"]:
            planted["done"] = True
            pending = next(tmp_path.glob(".pending-*"))
            side = pending / "base"
            (side / "src").mkdir(parents=True, exist_ok=True)
            symlink_or_skip(secret, side / "src" / "app.py")
        return gitsafe.read_blobs(cwd, oids, timeout=timeout)

    _patch_readers(monkeypatch, blobs=read_blobs)
    code, result = _prepare(repo, base, candidate, out)
    assert code == 2 and result["code"] == "unsafe_tree_path"
    assert not secret.exists()
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    code, ready = _prepare(repo, base, candidate, out)
    assert code == 0 and (out / "base" / "src" / "app.py").read_text() == "value = 1\n"
    assert ready["changed_files"] >= 1


def test_multiline_problem_text_is_refused_instead_of_joined(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    side = out / "candidate"
    os.chmod(out, 0o755)
    os.chmod(side, 0o755)
    symlink_or_skip("target", side / "has\nnewline")
    code, result = review_copy.verify(str(out))
    assert code == 2 and result["code"] == "multiline_field"
    rendered = json.dumps(result)
    assert "\n" not in rendered and "has newline" not in rendered and "has\\nnewline" not in rendered


def test_problem_fields_are_canonicalized_then_redacted_then_truncated(monkeypatch, tmp_path):
    _require_descriptors()
    calls = []

    def sanitize(text, max_len=80):
        calls.append(("sanitize", text, max_len))
        return text

    def redact(text, max_len=10 ** 6):
        calls.append(("redact", text, max_len))
        return "REDACTED " + text

    monkeypatch.setattr(review_copy, "sanitize_display", sanitize)
    monkeypatch.setattr(review_copy, "redact_insight_text", redact)
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    target = out / "candidate" / "src" / "app.py"
    os.chmod(out, 0o755)
    os.chmod(target.parent.parent, 0o755)
    os.chmod(target.parent, 0o755)
    os.chmod(target, 0o644)
    target.write_bytes(b"changed\n")
    _code, body = review_copy.verify(str(out))
    problem = next(row for row in body["problems"] if row.endswith(" changed"))
    assert problem.startswith("REDACTED ")
    sanitize_calls = [item for item in calls if item[0] == "sanitize" and item[1].endswith(" changed")]
    redact_calls = [item for item in calls if item[0] == "redact" and "changed" in item[1]]
    assert sanitize_calls and redact_calls
    assert sanitize_calls[0][2] is None
    assert redact_calls[0][1] == sanitize_calls[0][1]
    assert any(item[0] == "sanitize" and item[1].startswith("REDACTED ") and item[2] == 200 for item in calls)


def test_listing_limit_is_enforced_before_parse(monkeypatch, tmp_path):
    _require_descriptors()
    monkeypatch.setattr(review_copy, "MAX_LISTING_BYTES", 8)
    repo = _scripted_repo(tmp_path)
    out = tmp_path / "review"
    commit = "d" * 40
    tree = "e" * 40
    scripted = Scripted([
        {"stdout": b"", "code": 1},
        {"stdout": b".git\n"},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": b"100644 blob " + b"f" * 40 + b"\tapp.py\0"},
    ])
    code, result = review_copy.prepare(str(repo), commit, commit, str(out), **_keywords(scripted.git_spawn, tmp_path))
    assert code == 2 and result["code"] == "limit_exceeded"
    assert not out.exists()


def test_child_environment_is_applied_unless_explicitly_unplanned(tmp_path):
    _require_descriptors()
    seen = []

    def child(env, purpose):
        seen.append(purpose)
        return env

    repo = _scripted_repo(tmp_path)
    out = tmp_path / "review"
    commit = "1" * 40
    scripted = Scripted([{"stdout": b"", "code": 1}, {"stdout": b"", "code": 1}])
    code, result = review_copy.prepare(
        str(repo), commit, commit, str(out), planned=None, **_keywords(scripted.git_spawn, tmp_path, child),
    )
    assert code == 2 and result["code"] == "not_repository"
    assert seen == ["no-host", "no-host"]
    seen.clear()
    scripted.replies = [{"stdout": b"", "code": 1}, {"stdout": b"", "code": 1}]
    review_copy.prepare(
        str(repo), commit, commit, str(out), planned=False, **_keywords(scripted.git_spawn, tmp_path, child),
    )
    assert seen == []


def test_multiline_manifest_commit_is_refused_without_echo(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    manifest_path = out / "manifest.json"
    os.chmod(out, 0o755)
    os.chmod(manifest_path, 0o644)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["base"]["commit"] = "line one\nSECRET-COMMIT"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    code, result = review_copy.verify(str(out))
    assert code == 2 and result["code"] == "manifest_shape"
    rendered = json.dumps(result)
    assert "SECRET-COMMIT" not in rendered and "line one" not in rendered
    assert "\n" not in rendered
    assert out.exists() and (out / "manifest.json").exists()


def test_claim_failure_closes_the_descriptor_and_retry_succeeds(monkeypatch, tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    before = _fds() if Path("/proc/self/fd").exists() else None
    state = {"fail": True}

    def set_inheritable(fd, inheritable):
        if state["fail"]:
            raise OSError("claim failed")
        return os.set_inheritable(fd, inheritable)

    proxy = type("Proxy", (), {})()
    proxy.name = os.name
    proxy.sep = os.sep
    proxy.path = os.path
    proxy.getpid = os.getpid
    proxy.geteuid = os.geteuid
    proxy.O_RDONLY = os.O_RDONLY
    proxy.O_DIRECTORY = os.O_DIRECTORY
    proxy.O_NOFOLLOW = os.O_NOFOLLOW
    proxy.O_CLOEXEC = os.O_CLOEXEC
    proxy.O_WRONLY = os.O_WRONLY
    proxy.O_CREAT = os.O_CREAT
    proxy.O_EXCL = os.O_EXCL
    proxy.O_NONBLOCK = os.O_NONBLOCK
    proxy.open = os.open
    proxy.close = os.close
    proxy.stat = os.stat
    proxy.fstat = os.fstat
    proxy.mkdir = os.mkdir
    proxy.rename = os.rename
    proxy.unlink = os.unlink
    proxy.rmdir = os.rmdir
    proxy.listdir = os.listdir
    proxy.scandir = os.scandir
    proxy.readlink = os.readlink
    proxy.read = os.read
    proxy.write = os.write
    proxy.fchmod = os.fchmod
    proxy.fsencode = os.fsencode
    proxy.fsdecode = os.fsdecode
    proxy.dup = os.dup
    proxy.set_inheritable = set_inheritable
    monkeypatch.setattr(review_copy, "os", proxy)
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: True)
    code, result = review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(real_spawn, tmp_path))
    assert code == 2 and result["code"] == "filesystem"
    assert "claim failed" not in json.dumps(result)
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    if before is not None:
        assert _fds() == before
    state["fail"] = False
    code, ready = review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(real_spawn, tmp_path))
    assert code == 0 and ready["base"]["commit"] == base
    if before is not None:
        assert _fds() == before


def test_entry_count_is_refused_before_parse_and_retry_succeeds(monkeypatch, tmp_path):
    _require_descriptors()
    repo = _scripted_repo(tmp_path)
    out = tmp_path / "review"
    commit, tree, oid = "a" * 40, "b" * 40, "c" * 40
    two = (
        b"100644 blob " + oid.encode() + b"\tone.py\0"
        + b"100644 blob " + oid.encode() + b"\tSECRET-PATH\0"
    )
    original = review_copy.MAX_ENTRIES
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", 1)
    scripted = Scripted([
        {"stdout": b"", "code": 1},
        {"stdout": b".git\n"},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": two},
    ])
    code, result = review_copy.prepare(str(repo), commit, commit, str(out), **_keywords(scripted.git_spawn, tmp_path))
    assert code == 2 and result["code"] == "limit_exceeded"
    rendered = json.dumps(result)
    assert "one.py" not in rendered and "SECRET-PATH" not in rendered
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", original)
    real = tmp_path / "real"
    real.mkdir()
    real_repo, base, _base_tree, candidate, _candidate_tree = make_repo(real)
    ready_out = real / "review"
    assert _prepare(real_repo, base, candidate, ready_out)[0] == 0
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", 1)
    code, again = review_copy.verify(str(ready_out))
    assert code == 2 and again["code"] == "limit_exceeded"
    assert "SECRET-PATH" not in json.dumps(again)
    assert ready_out.is_dir()


def test_listing_rows_stop_before_parse_when_the_entry_cap_is_exceeded(monkeypatch, tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    widest = 0
    for folder, dirs, files in os.walk(out):
        del folder
        widest = max(widest, len(dirs) + len(files))
    listing = out / "candidate.files.jsonl"
    os.chmod(out, 0o755)
    os.chmod(listing, 0o644)
    row = '{"path": "kept.py", "sha256": "' + ("ab" * 32) + '"}\n'
    listing.write_text(row * widest + "NOT-JSON SECRET-PATH\n", encoding="ascii")
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", widest)
    code, result = review_copy.verify(str(out))
    assert code == 2 and result["code"] == "limit_exceeded"
    assert "SECRET-PATH" not in json.dumps(result) and "NOT-JSON" not in json.dumps(result)
    assert out.is_dir() and listing.is_file()


def test_object_header_limit_is_enforced_before_parsing(monkeypatch, tmp_path):
    _require_descriptors()
    repo = _scripted_repo(tmp_path)
    out = tmp_path / "review"
    commit = "a" * 40
    tree = "b" * 40
    oid = "c" * 40
    listing = b"100644 blob " + oid.encode() + b"\tapp.py\0"
    scripted = Scripted([
        {"stdout": b"", "code": 1},
        {"stdout": b".git\n"},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": (commit + "\n").encode()},
        {"stdout": (tree + "\n").encode()},
        {"stdout": listing},
        {"stdout": listing},
    ])
    caps = []

    def custody(**kwargs):
        caps.append(kwargs["stdout_limit"])
        return gitsafe.custody(**kwargs)

    def oversized(_cwd, _oids, *, timeout):
        raise gitsafe.GitError("x" * 30, code="git_output_limit")

    _patch_readers(monkeypatch, sizes=oversized, custody=custody)
    code, result = review_copy.prepare(
        str(repo), commit, commit, str(out), **_keywords(scripted.git_spawn, tmp_path),
    )
    assert code == 2 and result["code"] == "limit_exceeded"
    assert caps == [review_copy.MAX_HEADER_BYTES + 1]
    assert "x" * 20 not in json.dumps(result)
    assert not out.exists() and list(tmp_path.glob(".pending-*")) == []


def test_timeout_refuses_and_closes_without_a_copy(tmp_path):
    _require_descriptors()
    repo = _scripted_repo(tmp_path)
    out = tmp_path / "review"

    class Boom(Scripted):
        def git_spawn(self, repository, args, env, timeout):
            del repository, args, env, timeout
            raise TimeoutError("slow")

    code, result = review_copy.prepare(str(repo), "2" * 40, "3" * 40, str(out), **_keywords(Boom([]).git_spawn, tmp_path))
    assert code == 2 and result["code"] == "git_timeout"
    assert "slow" not in json.dumps(result)
    assert not out.exists()


@pytest.mark.parametrize("header", [b"0" * 40 + b" blob 1\nx\n", b""])
def test_failed_export_leaves_no_new_parent_and_can_retry(monkeypatch, tmp_path, header):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "new-parent" / "nested" / "review"
    requests = []

    def sizes(cwd, oids, *, timeout):
        requests.append(oids)
        if len(requests) == 1:
            raise gitsafe.GitError(header.decode("ascii"))
        return gitsafe.blob_sizes(cwd, oids, timeout=timeout)

    _patch_readers(monkeypatch, sizes=sizes)
    code, result = _prepare(repo, base, candidate, out)
    assert (code, result["code"]) == (2, "object_missing")
    assert len(requests) == 1 and requests[0]
    assert not out.parent.parent.exists()
    assert _prepare(repo, base, candidate, out)[0] == 0


@pytest.mark.parametrize("object_limit", [True, False], ids=["object", "side"])
def test_blob_sizes_refuse_before_content_is_requested(monkeypatch, tmp_path, object_limit):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "review"
    requests = []
    object_bytes = review_copy.MAX_OBJECT_BYTES
    side_bytes = review_copy.MAX_SIDE_BYTES

    def content(cwd, oids, *, timeout):
        requests.append(oids)
        return gitsafe.read_blobs(cwd, oids, timeout=timeout)

    _patch_readers(monkeypatch, blobs=content)
    monkeypatch.setattr(review_copy, "MAX_OBJECT_BYTES", 5 if object_limit else object_bytes)
    monkeypatch.setattr(review_copy, "MAX_SIDE_BYTES", side_bytes if object_limit else 5)
    status, result = _prepare(repo, base, candidate, out)
    assert (status, result["code"]) == (2, "limit_exceeded")
    assert not requests and not out.exists() and not list(tmp_path.glob(".pending-*"))
    monkeypatch.setattr(review_copy, "MAX_OBJECT_BYTES", object_bytes)
    monkeypatch.setattr(review_copy, "MAX_SIDE_BYTES", side_bytes)
    assert _prepare(repo, base, candidate, out)[0] == 0


@pytest.mark.parametrize(("git_code", "refusal"), [
    ("ERR_AEGIS", "object_truncated"),
    ("git_failed", "export_failed"),
    ("git_timeout", "git_timeout"),
])
def test_public_reader_failure_is_typed_and_retryable(monkeypatch, tmp_path, git_code, refusal):
    repo, base, _, candidate, _ = make_repo(tmp_path)
    out = tmp_path / "nested" / "review"
    errors = [gitsafe.GitError("private Git output", code=git_code)]

    def content(cwd, oids, *, timeout):
        if errors:
            raise errors.pop()
        return gitsafe.read_blobs(cwd, oids, timeout=timeout)

    _patch_readers(monkeypatch, blobs=content)
    status, result = _prepare(repo, base, candidate, out)
    assert (status, result["code"]) == (2, refusal)
    assert "private Git output" not in json.dumps(result)
    assert not out.parent.exists()
    assert _prepare(repo, base, candidate, out)[0] == 0


def test_git_ports_receive_held_repository_and_scaffold_descriptors(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    identity = repo.stat()
    opened = []

    def spawn(root, args, env, timeout):
        assert type(root) is int
        opened.append(root)
        info = os.fstat(root)
        expected = identity
        if "init" in args:
            assert args[-1] == "--template="
            expected = next(tmp_path.glob(".pending-*")).stat()
        assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
        return real_spawn(root, args, env, timeout)

    assert review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(spawn, tmp_path))[0] == 0
    assert opened
    for descriptor in set(opened):
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF


def test_publish_refuses_a_destination_created_during_export(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    competing = []

    def spawn(root, args, env, timeout):
        if "init" in args:
            out.mkdir()
            competing.append(out.stat().st_ino)
        return real_spawn(root, args, env, timeout)

    code, result = review_copy.prepare(str(repo), base, candidate, str(out), **_keywords(spawn, tmp_path))
    assert (code, result.get("code")) == (2, "output_exists")
    assert out.stat().st_ino == competing[0] and list(out.iterdir()) == []
    assert list(tmp_path.glob(".pending-*")) == []
    assert list(Path(_records(tmp_path)).iterdir()) == []
    out.rmdir()
    assert _prepare(repo, base, candidate, out)[0] == 0


def test_remove_unlinks_without_chmodding_a_hardlinked_file(tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    linked = tmp_path / "retained"
    os.link(out / "base" / "lines.txt", linked)
    mode = linked.stat().st_mode
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0
    assert linked.stat().st_mode == mode
    assert linked.read_bytes() == b"line one\nline two\n"


def test_remove_refuses_an_overdeep_copy_before_changing_it(monkeypatch, tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    expected = sorted((str(path.relative_to(out)), path.stat().st_mode) for path in out.rglob("*"))
    os.chmod(out, 0o755)
    deep = out
    for _ in range(review_copy.MAX_WALK_DEPTH + 2):
        deep = deep / "d"
        deep.mkdir()
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[1]["code"] == "limit_exceeded"
    assert (out / "manifest.json").is_file()
    assert sorted((str(path.relative_to(out)), path.stat().st_mode)
                  for path in out.rglob("*") if path.relative_to(out).parts[0] != "d") == expected
    monkeypatch.setattr(review_copy, "MAX_WALK_DEPTH", review_copy.MAX_WALK_DEPTH + 2)
    assert review_copy.remove(str(out), preparation_dir=_records(tmp_path))[0] == 0


def test_verify_bounds_total_side_files_across_directories(monkeypatch, tmp_path):
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    side = out / "candidate"
    os.chmod(side / "src", 0o755)
    for index in range(5):
        (side / "src" / f"added-{index}").write_bytes(b"extra")
    original = review_copy.MAX_ENTRIES
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", 8)
    code, result = review_copy.verify(str(out))
    assert (code, result["code"]) == (2, "limit_exceeded")
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", original)
    assert review_copy.verify(str(out))[0] == 3


def _snapshot(root):
    rows = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            info = path.lstat()
            payload = None
            if stat.S_ISREG(info.st_mode):
                payload = path.read_bytes()
            elif stat.S_ISLNK(info.st_mode):
                payload = os.readlink(path)
            rows.append((str(path.relative_to(root)), info.st_mode, payload))
    return tuple(sorted(rows))


def _chmod_tree(root, directory_mode, file_mode):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        os.chmod(dirpath, directory_mode)
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink():
                os.chmod(path, file_mode)


def test_review_verification_is_a_public_facade_over_bounded_retention():
    files = importlib.import_module("aegis_core.team_review_files")
    verifier = importlib.import_module("aegis_core.team_review_verify")
    assert list(files.__all__) == ["ProblemPrefix", "strict_json"]
    assert list(verifier.__all__) == ["verify_copy"]
    assert callable(files.strict_json) and callable(verifier.verify_copy)
    assert review_copy.verify.__module__ == "aegis_core.team_review_copy"
    rendered = []

    def render(text):
        rendered.append(text)
        if "\n" in text:
            raise review_copy.ReviewRefusal("multiline_field")
        return "shown:" + text

    prefix = files.ProblemPrefix(1, render, lambda text: text == "fixed")
    prefix.add("fixed", proved=True)
    prefix.add("fixed", proved=True)
    prefix.add("candidate/late is writable")
    prefix.observe_past_cap("candidate/extra is writable")
    assert prefix.kept == ["shown:fixed"]
    assert prefix.count == 4
    assert rendered == ["fixed", "candidate/late is writable", "candidate/extra is writable"]
    with pytest.raises(ValueError):
        files.ProblemPrefix(-1, render, lambda text: False)
    refused = files.ProblemPrefix(0, render, lambda text: False)
    with pytest.raises(review_copy.ReviewRefusal):
        refused.add("has\nnewline")
    assert refused.kept == [] and refused.count == 1


def test_problem_cap_keeps_order_total_and_the_entry_limit(monkeypatch, tmp_path):
    _require_descriptors()
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    before = _snapshot(out)
    fds = _fds() if Path("/proc/self/fd").exists() else None
    problems_limit = review_copy.MAX_PROBLEMS
    entries_limit = review_copy.MAX_ENTRIES
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", -1)
    code, body = review_copy.verify(str(out))
    assert (code, body["code"]) == (2, "invalid_input")
    assert str(out) not in json.dumps(body) and "\n" not in json.dumps(body)
    assert _snapshot(out) == before
    if fds is not None:
        assert _fds() == fds
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", problems_limit)
    assert review_copy.verify(str(out))[0] == 0
    side = out / "candidate"
    os.chmod(side, 0o755)
    os.chmod(side / "src", 0o755)
    for index in range(4):
        (side / "src" / ("added-%s" % index)).write_bytes(b"extra")
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 1000)
    status, full = review_copy.verify(str(out))
    assert status == 3 and full["ok"] is False and full["code"] == "copy_differs"
    assert full["problem_count"] == len(full["problems"]) > 3
    order = list(full["problems"])
    for cap in (0, 1, 2, len(order) - 1, len(order)):
        monkeypatch.setattr(review_copy, "MAX_PROBLEMS", cap)
        checked, limited = review_copy.verify(str(out))
        assert checked == 3 and limited["ok"] is False
        assert limited["problem_count"] == full["problem_count"]
        assert limited["problems"] == order[:cap]
        assert limited["base"] == full["base"] and limited["candidate"] == full["candidate"]
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 1)
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", 1)
    refused, limited = review_copy.verify(str(out))
    assert (refused, limited["code"]) == (2, "limit_exceeded")
    assert "added-0" not in json.dumps(limited)
    monkeypatch.setattr(review_copy, "MAX_ENTRIES", entries_limit)
    checked, again = review_copy.verify(str(out))
    assert checked == 3 and again["problems"] == order[:1]
    assert again["problem_count"] == full["problem_count"]
    if fds is not None:
        assert _fds() == fds


def test_scaffold_summary_precedes_modes_and_proved_lines_skip_render(monkeypatch, tmp_path):
    _require_descriptors()
    calls = []

    def sanitize(text, max_len=80):
        calls.append(text)
        return text

    monkeypatch.setattr(review_copy, "sanitize_display", sanitize)
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    _chmod_tree(out, 0o755, 0o644)
    git_file = next(path for path in (out / ".git").rglob("*") if path.is_file() and not path.is_symlink())
    git_file.write_bytes(git_file.read_bytes() + b"\n")
    (out / ".git").chmod(0o755)
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 1000)
    status, full = review_copy.verify(str(out))
    assert status == 3
    texts = full["problems"]
    changed = texts.index(".git changed")
    writable = texts.index(".git is writable")
    details = [index for index, row in enumerate(texts) if row.startswith(".git/")]
    assert details and changed < writable < details[0]
    calls.clear()
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 1)
    checked, body = review_copy.verify(str(out))
    assert checked == 3 and body["problems"] == [".git changed"]
    assert body["problem_count"] == full["problem_count"] > 2
    assert ".git is writable" not in calls
    assert any(text.startswith(".git/") and text.endswith(" is writable") for text in calls)
    calls.clear()
    shutil.rmtree(out / ".git")
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 0)
    checked, hidden = review_copy.verify(str(out))
    assert checked == 3 and hidden["problems"] == [] and hidden["ok"] is False
    assert hidden["problem_count"] >= 2
    assert ".git is missing" not in calls
    assert "candidate is writable" not in calls
    assert any(text.startswith("candidate/") and text.endswith(" is writable") for text in calls)


def test_late_multiline_refusal_survives_the_cap_and_retries_clean(monkeypatch, tmp_path):
    _require_descriptors()
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    _chmod_tree(out, 0o755, 0o644)
    side = out / "candidate"
    for index in range(5):
        (side / ("a-filler-%s" % index)).write_bytes(b"x")
    late = side / "z-late"
    late.mkdir()
    symlink_or_skip("target", late / "has\nnewline")
    monkeypatch.setattr(review_copy, "MAX_PROBLEMS", 1)
    fds = _fds() if Path("/proc/self/fd").exists() else None
    code, result = review_copy.verify(str(out))
    assert (code, result["code"]) == (2, "multiline_field")
    rendered = json.dumps(result)
    assert "\n" not in rendered and "has newline" not in rendered and "has\\nnewline" not in rendered
    if fds is not None:
        assert _fds() == fds
    again, repeated = review_copy.verify(str(out))
    assert (again, repeated["code"]) == (2, "multiline_field")
    (late / "has\nnewline").unlink()
    _chmod_tree(out, 0o555, 0o444)
    for index in range(5):
        os.chmod(side, 0o755)
        (side / ("a-filler-%s" % index)).unlink()
    os.chmod(late, 0o755)
    os.chmod(side, 0o755)
    late.rmdir()
    _chmod_tree(out, 0o555, 0o444)
    checked, body = review_copy.verify(str(out))
    assert checked == 0 and body["ok"] is True and body["problems"] == []
    if fds is not None:
        assert _fds() == fds


def test_concurrent_verify_stays_read_only_and_a_stat_swap_stays_typed(monkeypatch, tmp_path):
    _require_descriptors()
    repo, base, _base_tree, candidate, _candidate_tree = make_repo(tmp_path)
    out = tmp_path / "review"
    assert _prepare(repo, base, candidate, out)[0] == 0
    before = _snapshot(out)
    fds = _fds() if Path("/proc/self/fd").exists() else None
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def run():
        try:
            barrier.wait(timeout=30)
            results.append(review_copy.verify(str(out)))
        except Exception as exc:
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert errors == [] and sorted(thread.is_alive() for thread in threads) == [False, False]
    assert [item[0] for item in results] == [0, 0]
    assert _snapshot(out) == before
    if fds is not None:
        assert _fds() == fds
    _chmod_tree(out, 0o755, 0o644)
    armed = {"go": True}

    def swap_stat(path, *args, **kwargs):
        info = os.stat(path, *args, **kwargs)
        dir_fd = kwargs.get("dir_fd")
        if armed["go"] and dir_fd is not None and stat.S_ISREG(info.st_mode):
            armed["go"] = False
            os.unlink(path, dir_fd=dir_fd)
            os.symlink("replaced-leaf", path, dir_fd=dir_fd)
        return info

    support = review_copy.descriptor_support
    monkeypatch.setattr(review_copy, "os", SimpleNamespace(**{**vars(os), "stat": swap_stat}))
    monkeypatch.setattr(review_copy, "descriptor_support", lambda: True)
    outcome = review_copy.verify(str(out))
    assert isinstance(outcome, tuple) and len(outcome) == 2
    code, body = outcome
    assert armed["go"] is False
    assert code == 2 and isinstance(body, dict) and isinstance(body.get("code"), str)
    rendered = json.dumps(body)
    assert "replaced-leaf" not in rendered and "\n" not in rendered
    if fds is not None:
        assert _fds() == fds
    monkeypatch.setattr(review_copy, "os", os)
    monkeypatch.setattr(review_copy, "descriptor_support", support)
    fresh = tmp_path / "fresh"
    assert _prepare(repo, base, candidate, fresh)[0] == 0
    assert review_copy.verify(str(fresh))[0] == 0
    if fds is not None:
        assert _fds() == fds
