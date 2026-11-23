"""Source witness and export parity, refusal recovery and confinement."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from threading import Barrier
from types import SimpleNamespace
import zlib

import pytest

from aegis_core import gitsafe, pathlookup, storage_confined, team_git
from aegis_core import team_jobs_source as source_module
from conftest import symlink_or_skip
from tests.helpers_team_git import git
from tools import hierarchy_jobs as legacy


def make_store(path):
    if not storage_confined.descriptor_supported() or os.name != "posix":
        pytest.skip("descriptor-relative source and export require POSIX capabilities")
    return path.resolve()


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs Git")
    path = tmp_path.resolve() / "repo"
    path.mkdir()
    git(path, "init", "-q")
    (path / "dir").mkdir()
    (path / "dir/file").write_bytes(b"committed\n")
    (path / "other").write_bytes(b"second blob\n")
    git(path, "add", "--", ".")
    git(path, "commit", "-qm", "fixture")
    return SimpleNamespace(path=path, parent=path.parent,
                           commit=git(path, "rev-parse", "HEAD").decode().strip(),
                           tree=git(path, "rev-parse", "HEAD^{tree}").decode().strip())


def remove_blob(repo):
    oid = git(repo.path, "rev-parse", "HEAD:other").decode().strip()
    path = repo.path / ".git" / "objects" / oid[:2] / oid[2:]
    saved = path.read_bytes()
    path.unlink()
    return path, saved


def dirty(repo):
    git(repo.path, "mv", "--", "other", "renamed")
    (repo.path / "dir/file").write_bytes(b"dirty\n")
    (repo.path / "extra").write_bytes(b"untracked\n")


def snapshot(root):
    return {str(item.relative_to(root)): item.read_bytes()
            for item in root.rglob("*") if item.is_file()}


def test_legacy_measure_source_and_path_refusals(repo):
    dirty(repo)
    before = snapshot(repo.path)
    expected = legacy.source_digest(str(repo.path))
    assert expected == legacy.source_digest(str(repo.path))
    assert expected[1]["dirty_entries"] == 3
    assert snapshot(repo.path) == before
    assert legacy.refuse_paths_outside_commit(repo.path, repo.commit, [".", "dir/", "other::case"]) is None
    with pytest.raises(ValueError, match=r"^path outside is not in commit "):
        legacy.refuse_paths_outside_commit(repo.path, repo.commit, ["outside"])
    with pytest.raises(ValueError, match=r"^could not read the status"):
        legacy.uncommitted_content(repo.parent)
    git(repo.path, "config", "remote.fixture.promisor", "true")
    with pytest.raises(ValueError, match=r"^a partial clone cannot be exported"):
        legacy.refuse_paths_outside_commit(repo.path, repo.commit, ["."])


def test_legacy_measure_export_refusals(repo):
    make_store(repo.parent)
    target = repo.parent / "output"
    with pytest.raises(ValueError, match=r"has tree"):
        legacy.export_commit(repo.path, repo.commit, "0" * 40, target)
    target.mkdir()
    with pytest.raises(FileExistsError):
        legacy.export_commit(repo.path, repo.commit, repo.tree, target)
    target.rmdir()
    location, saved = remove_blob(repo)
    with pytest.raises(ValueError, match=r"^the commit lacks the object"):
        legacy.export_commit(repo.path, repo.commit, repo.tree, target)
    assert not target.exists()
    location.write_bytes(saved)
    git(repo.path, "update-index", "--add", "--cacheinfo", "160000", repo.commit, "fixture-submodule")
    with pytest.raises(ValueError, match=r"^submodules are not supported"):
        legacy.uncommitted_content(repo.path)


@pytest.fixture
def source():
    return source_module


class GitReads:
    """Real Git fixture adapter for the metadata port."""

    def __init__(self, source):
        self.source = source
        self.program = shutil.which("git")
        self.commands = []
        self.environments = []
        self.timeouts = []
        self.override = None

    def run(self, checkout, argv, env, *, timeout, limit, stdin):
        self.commands.append(tuple(argv))
        self.environments.append(env)
        self.timeouts.append(timeout)
        if self.override:
            result = self.override(checkout, argv)
            if result is not None:
                return result
        result = gitsafe.run(argv, checkout, timeout=timeout, stdin=stdin)
        if len(result.stdout) > limit:
            raise self.source.GitReadError("output_limit")
        return result.returncode, result.stdout


@pytest.fixture
def service(source):
    reads = GitReads(source)
    api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                           object_read_env=team_git.object_read_env, child_environment=lambda env, _: env,
                           program=reads.program)
    return api, reads


def refused(source, reason):
    return pytest.raises(source.JobSourceRefusal, match="^job source refused: " + reason + "$")


def test_dirty_digest_parity_and_nonmutation(repo, service):
    make_store(repo.path)
    api, _ = service
    dirty(repo)
    before = snapshot(repo.path)
    old = legacy.source_digest(str(repo.path))
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(api.source_digest, [repo.path] * 2)) == [old, old]
    assert api.uncommitted_content(repo.path) == (old[1]["dirty_content_sha256"], 3)
    assert api.source_state(repo.path) == legacy.source_state(None, repo.path)
    assert snapshot(repo.path) == before


def test_path_refusal_and_retry(source, repo, service):
    api, _ = service
    with refused(source, "path_outside_commit") as failure:
        api.refuse_paths_outside_commit(repo.path, repo.commit, [".", "missing::private-selection"])
    assert failure.value.path_index == 1
    assert failure.value.as_dict() == {
        "status": "refused", "code": 1, "reason": "path_outside_commit",
        "next_action": "Choose a recipe path present in the pinned commit.",
    }
    paths = [".", "dir/", "other::case"]
    assert api.refuse_paths_outside_commit(repo.path, repo.commit, paths) == (
        legacy.refuse_paths_outside_commit(repo.path, repo.commit, paths))


@pytest.mark.parametrize("nested", [False, True])
def test_membership_uses_injected_program_without_ambient_search(source, repo, service, nested):
    api, reads = service
    previous = os.environ.get("PATH")
    scope = gitsafe.custody(scratch=repo.parent, env=team_git.object_read_env(), replace_env=True,
                            program=reads.program) if nested else nullcontext()
    try:
        os.environ["PATH"] = os.devnull
        with scope:
            assert api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file"]) is None
            with refused(source, "path_outside_commit") as failure:
                api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file", "missing"])
            assert failure.value.path_index == 1
    finally:
        if previous is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous


def test_job_source_validates_an_injected_program_at_construction(source, tmp_path):
    reads = GitReads(source)
    invalid = ["git", 123, str(tmp_path / "missing"), str(tmp_path)]
    if os.name == "posix":
        nonexecutable = tmp_path / "not-executable"
        nonexecutable.write_bytes(b"fixture\n")
        nonexecutable.chmod(0o600)
        invalid.append(str(nonexecutable))
    for program in invalid:
        with refused(source, "invalid_input"):
            source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                             object_read_env=team_git.object_read_env, child_environment=lambda env, _: env,
                             program=program)
    assert reads.commands == []


def test_job_source_keeps_the_injected_program_when_path_changes(source, repo):
    make_store(repo.path)
    reads = GitReads(source)
    folder = repo.parent / "owner-bin"
    folder.mkdir()
    selected = folder / "git"
    selected.write_text(f'#!/bin/sh\nexec {shlex.quote(reads.program)} "$@"\n', encoding="utf-8")
    selected.chmod(0o700)
    previous = os.environ.get("PATH")
    root_token = pathlookup.ordinary_root.set(str(repo.path))
    try:
        os.environ["PATH"] = str(folder)
        api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                               object_read_env=team_git.object_read_env, child_environment=lambda env, _: env,
                               program=str(selected))
        os.environ["PATH"] = os.devnull
        assert api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file"]) is None
    finally:
        pathlookup.ordinary_root.reset(root_token)
        if previous is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous


@contextmanager
def _temporary_environment(*names):
    saved = {name: os.environ.get(name) for name in names}
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_job_source_requires_an_injected_program_without_executing_path(source, repo):
    make_store(repo.path)
    reads = GitReads(source)
    controller = repo.parent / "controller"
    controller.mkdir()
    git(controller, "init", "-q")
    folder = repo.path / "bin"
    folder.mkdir()
    marker = repo.path / "invoked"
    candidate = folder / "git"
    candidate.write_text(f"#!/bin/sh\nprintf invoked > {shlex.quote(str(marker))}\n", encoding="utf-8")
    candidate.chmod(0o700)
    original_cwd = Path.cwd()
    root_token = pathlookup.ordinary_root.set(str(controller))
    try:
        with _temporary_environment("PATH"):
            os.chdir(controller)
            os.environ["PATH"] = str(folder)
            with refused(source, "invalid_input"):
                source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                                 object_read_env=team_git.object_read_env, child_environment=lambda env, _: env)
    finally:
        pathlookup.ordinary_root.reset(root_token)
        os.chdir(original_cwd)
        assert not marker.exists()


def writable_exports(*targets):
    for directory in targets:
        for current, _, _ in os.walk(directory):
            Path(current).chmod(0o700)


def test_export_missing_blob_retry_and_parity(source, repo, service):
    make_store(repo.path)
    api, reads = service
    target = repo.parent / "output"
    location, saved = remove_blob(repo)
    with refused(source, "missing_object"):
        api.export_commit(repo.path, repo.commit, repo.tree, target)
    assert set(repo.parent.iterdir()) == {repo.path}
    assert not any("fetch" in argv or "--batch" in argv for argv in reads.commands)
    location.write_bytes(saved)
    record = api.export_commit(repo.path, repo.commit, repo.tree, target, git_stub=True)
    comparison = repo.parent / "legacy"
    try:
        assert record == legacy.export_commit(repo.path, repo.commit, repo.tree, comparison, git_stub=True)
        assert snapshot(target) == snapshot(comparison)
        assert (target / "dir/file").stat().st_mode & 0o777 == 0o444
        assert target.stat().st_mode & 0o777 == 0o555
    finally:
        writable_exports(target, comparison)


def test_partial_clone_refused_before_object_reads(source, repo, service):
    api, reads = service
    git(repo.path, "config", "remote.fixture.promisor", "true")
    git(repo.path, "config", "remote.fixture.url", "ext::false")
    with refused(source, "partial_clone"):
        api.refuse_paths_outside_commit(repo.path, repo.commit, ["."])
    assert len(reads.commands) == 2 and all("config" in argv for argv in reads.commands)
    git(repo.path, "config", "remote.fixture.promisor", "false")
    assert api.refuse_paths_outside_commit(repo.path, repo.commit, ["."]) is None


def test_unsupported_platform_has_typed_refusal(source, tmp_path, service, monkeypatch):
    api, reads = service
    monkeypatch.setattr(source_module, "descriptor_supported", lambda: False)
    with refused(source, "unsupported_platform"):
        api.uncommitted_content(tmp_path.resolve())
    with refused(source, "unsupported_platform"):
        api.export_commit(tmp_path.resolve(), "0" * 40, "0" * 40, tmp_path.resolve() / "output")
    assert reads.commands == []


def test_symlink_swap_does_not_witness_outside_file(source, repo, service):
    make_store(repo.path)
    api, reads = service
    dirty_dir = repo.path / "dir"
    (dirty_dir / "file").write_bytes(b"dirty\n")
    outside = repo.parent / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"private\n")
    saved = repo.parent / "saved"

    def swap(checkout, argv):
        if "ls-files" in argv:
            dirty_dir.rename(saved)
            symlink_or_skip(outside, dirty_dir, target_is_directory=True)

    reads.override = swap
    with refused(source, "unsafe_checkout_entry"):
        api.uncommitted_content(repo.path)
    assert (outside / "file").read_bytes() == b"private\n"
    dirty_dir.unlink()
    saved.rename(dirty_dir)
    reads.override = None
    assert api.uncommitted_content(repo.path) == legacy.uncommitted_content(repo.path)


def test_invalid_status_and_timeout_refuse_then_retry(source, repo, service):
    make_store(repo.path)
    api, reads = service
    dirty(repo)

    def malformed(checkout, argv):
        if "status" in argv:
            return 0, b"R  renamed\0"

    reads.override = malformed
    with refused(source, "git_protocol"):
        api.uncommitted_content(repo.path)

    def timed_out(checkout, argv):
        raise source.GitReadError("timeout")

    reads.override = timed_out
    with refused(source, "git_timeout"):
        api.source_digest(repo.path)
    reads.override = None
    assert api.source_digest(repo.path) == legacy.source_digest(str(repo.path))


def test_lost_blob_after_listing_has_no_partial_export(source, repo, service):
    make_store(repo.path)
    api, reads = service
    listing = git(repo.path, "ls-tree", "-r", "-z", "-l", "--full-tree", repo.tree)
    location, saved = remove_blob(repo)
    target = repo.parent / "output"

    def previous_listing(checkout, argv):
        if "ls-tree" in argv:
            return 0, listing

    reads.override = previous_listing
    with refused(source, "missing_object"):
        api.export_commit(repo.path, repo.commit, repo.tree, target)
    assert set(repo.parent.iterdir()) == {repo.path}
    location.write_bytes(saved)
    reads.override = None
    try:
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
    finally:
        writable_exports(target)


def test_export_publishers_leave_one_complete_winner(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    target = repo.parent / "output"
    first = git(repo.path, "rev-parse", "HEAD:dir/file").decode().strip()
    ready = Barrier(2, timeout=10)

    def synchronized_blobs(cwd, oids, **kwargs):
        wanted = list(oids)
        if kwargs.get("kind", "blob") == "blob" and first in wanted:
            ready.wait()
        return gitsafe.read_blobs(cwd, wanted, **kwargs)

    def export():
        try:
            return api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"]
        except source.JobSourceRefusal as exc:
            return exc.reason

    monkeypatch.setattr(source_module, "gitsafe", SimpleNamespace(
        run=gitsafe.run, custody=gitsafe.custody, GitError=gitsafe.GitError,
        blob_sizes=gitsafe.blob_sizes, read_blobs=synchronized_blobs, iter_objects=gitsafe.iter_objects))
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: export(), range(2), timeout=15))
        assert set(results) == {2, "export_exists"}
        assert snapshot(target) == {"dir/file": b"committed\n", "other": b"second blob\n"}
        assert set(repo.parent.iterdir()) == {repo.path, target}
    finally:
        writable_exports(target)


def test_symlink_escape_refusal_and_internal_link_parity(source, repo, service):
    make_store(repo.path)
    api, _ = service
    link = repo.path / "link"
    target = repo.parent / "output"
    old_target = repo.parent / "legacy"
    symlink_or_skip("../outside", link)
    git(repo.path, "add", "--", "link")
    git(repo.path, "commit", "-qm", "escaping link")
    commit = git(repo.path, "rev-parse", "HEAD").decode().strip()
    tree = git(repo.path, "rev-parse", "HEAD^{tree}").decode().strip()
    with pytest.raises(ValueError, match=r"^the commit has a symlink that leaves it"):
        legacy.export_commit(repo.path, commit, tree, old_target)
    assert old_target.is_dir()
    with refused(source, "unsafe_link"):
        api.export_commit(repo.path, commit, tree, target)
    assert not target.exists()
    link.unlink()
    symlink_or_skip("dir/file", link)
    git(repo.path, "add", "--", "link")
    git(repo.path, "commit", "-qm", "confined link")
    commit = git(repo.path, "rev-parse", "HEAD").decode().strip()
    tree = git(repo.path, "rev-parse", "HEAD^{tree}").decode().strip()
    try:
        assert api.export_commit(repo.path, commit, tree, target)["entries"] == 3
        assert os.readlink(target / "link") == "dir/file"
    finally:
        writable_exports(target)


def test_size_limit_precedes_batch_open(source, repo, service):
    make_store(repo.path)
    api, reads = service
    target = repo.parent / "output"
    oid = git(repo.path, "rev-parse", "HEAD:other").strip()

    def oversized(checkout, argv):
        if "ls-tree" in argv:
            return 0, b"100644 blob " + oid + b" 2147483649\tother\0"

    reads.override = oversized
    with refused(source, "export_limit"):
        api.export_commit(repo.path, repo.commit, repo.tree, target)
    assert set(repo.parent.iterdir()) == {repo.path}
    assert not any("--batch" in argv for argv in reads.commands)
    reads.override = None
    try:
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
    finally:
        writable_exports(target)


def test_measured_corrupt_object_refusal_and_recovery(source, repo, service):
    make_store(repo.path)
    api, _ = service
    location, original = remove_blob(repo)
    location.write_bytes(zlib.compress(b"blob 12\0wrong bytes\n"))
    target = repo.parent / "output"
    legacy_target = repo.parent / "legacy-output"
    try:
        assert legacy.export_commit(repo.path, repo.commit, repo.tree, legacy_target)["entries"] == 2
        assert (legacy_target / "other").read_bytes() == b"wrong bytes\n"
        with refused(source, "invalid_object"):
            api.export_commit(repo.path, repo.commit, repo.tree, target)
        assert set(repo.parent.iterdir()) == {repo.path, legacy_target}
        location.write_bytes(original)
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
        assert (target / "other").read_bytes() == b"second blob\n"
    finally:
        writable_exports(legacy_target, target)


def test_export_refuses_sparse_blob_over_public_reader_limit(source, repo, service):
    make_store(repo.path)
    api, _ = service
    oversized = repo.path / "oversized"
    with oversized.open("xb") as stream:
        stream.truncate(134217729)
    git(repo.path, "add", "--", "oversized")
    git(repo.path, "commit", "-qm", "oversized fixture")
    commit = git(repo.path, "rev-parse", "HEAD").decode().strip()
    tree = git(repo.path, "rev-parse", "HEAD^{tree}").decode().strip()
    target = repo.parent / "output"
    try:
        with refused(source, "export_blob_limit") as refusal:
            api.export_commit(repo.path, commit, tree, target)
        assert refusal.value.code == 1 and refusal.value.next_action
        assert set(repo.parent.iterdir()) == {repo.path}
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
    finally:
        writable_exports(target)


@pytest.mark.parametrize("object_format,ceiling", [("sha1", 134217671), ("sha256", 134217647)])
def test_export_accepts_framed_blob_ceiling_and_refuses_one_byte_over(
        source, tmp_path, service, monkeypatch, object_format, ceiling):
    parent = make_store(tmp_path)
    if shutil.which("git") is None:
        pytest.skip("needs Git")
    checkout = parent / "repo"
    checkout.mkdir()
    try:
        git(checkout, "init", "-q", "--object-format=" + object_format)
    except subprocess.CalledProcessError as error:
        if b"unknown option" in error.stderr or b"unknown hash algorithm" in error.stderr:
            pytest.skip("Git does not support explicit " + object_format + " repositories")
        raise
    api, _ = service
    blob, target = checkout / "large", parent / "output"
    repo = SimpleNamespace(path=checkout)
    opened = []
    stage = source_module._staged_export

    def observe_stage(*args, **kwargs):
        opened.append(True)
        return stage(*args, **kwargs)

    monkeypatch.setattr(source_module, "_staged_export", observe_stage)
    with blob.open("xb") as stream:
        stream.truncate(ceiling + 1)
    commit, tree = _commit(repo, "one byte over the framed limit")
    with refused(source, "export_blob_limit") as failure:
        api.export_commit(checkout, commit, tree, target)
    assert failure.value.code == 1 and failure.value.next_action
    assert not opened and set(parent.iterdir()) == {checkout}

    with blob.open("r+b") as stream:
        stream.truncate(ceiling)
    commit, tree = _commit(repo, "at the framed limit")
    try:
        result = api.export_commit(checkout, commit, tree, target)
        assert result == {"commit": commit, "tree": tree, "entries": 1, "bytes": ceiling}
        assert opened == [True]
        exported = target / blob.name
        assert exported.stat().st_size == ceiling
        with exported.open("rb") as stream:
            stream.seek(-1, os.SEEK_END)
            assert stream.read(1) == b"\0"
    finally:
        writable_exports(target)


def test_public_reader_census_with_real_export(repo, service):
    from tests.unit.core.test_gitsafe import test_no_package_module_reaches_gitsafe_private_names as check_reader_census

    make_store(repo.path)
    api, _ = service
    target = repo.parent / "output"
    try:
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
        assert (target / "dir/file").read_bytes() == b"committed\n"
        check_reader_census()
    finally:
        writable_exports(target)


def test_measured_outside_detour_refused(source, repo, service):
    make_store(repo.path)
    api, _ = service
    symlink_or_skip("../output/dir/file", repo.path / "link")
    git(repo.path, "add", "--", "link")
    git(repo.path, "commit", "-qm", "outside detour")
    commit = git(repo.path, "rev-parse", "HEAD").decode().strip()
    tree = git(repo.path, "rev-parse", "HEAD^{tree}").decode().strip()
    target = repo.parent / "output"
    try:
        assert legacy.export_commit(repo.path, commit, tree, target)["entries"] == 3
        assert (target / "link").read_bytes() == b"committed\n"
    finally:
        writable_exports(target)
    shutil.rmtree(target)
    with refused(source, "unsafe_link"):
        api.export_commit(repo.path, commit, tree, target)
    assert set(repo.parent.iterdir()) == {repo.path}


def _reader(monkeypatch, source):
    """Count public-reader calls on this module's gitsafe binding, not the global."""
    calls = []

    def blob_sizes(cwd, oids, **kwargs):
        wanted = list(oids)
        calls.append(("blob_sizes", kwargs.get("kind", "blob"), len(wanted)))
        return gitsafe.blob_sizes(cwd, wanted, **kwargs)

    def read_blobs(cwd, oids, **kwargs):
        wanted = list(oids)
        calls.append(("read_blobs", kwargs.get("kind", "blob"), len(wanted)))
        return gitsafe.read_blobs(cwd, wanted, **kwargs)

    def run(*args, **kwargs):
        calls.append(("run", tuple(args[0]) if args else ()))
        return gitsafe.run(*args, **kwargs)

    monkeypatch.setattr(source_module, "gitsafe", SimpleNamespace(
        run=run, custody=gitsafe.custody, GitError=gitsafe.GitError,
        blob_sizes=blob_sizes, read_blobs=read_blobs, iter_objects=gitsafe.iter_objects))
    return calls


def _commit(repo, message):
    git(repo.path, "add", "--", ".")
    git(repo.path, "commit", "-qm", message)
    return (git(repo.path, "rev-parse", "HEAD").decode().strip(),
            git(repo.path, "rev-parse", "HEAD^{tree}").decode().strip())


def _build_commit(repo, files):
    """Commit path bytes without creating those spellings on the fixture filesystem."""

    def tree(entries):
        folders, blobs = {}, []
        for path, mode, payload in entries:
            head, sep, tail = path.partition(b"/")
            if sep:
                folders.setdefault(head, []).append((tail, mode, payload))
            else:
                oid = git(repo, "hash-object", "-w", "--stdin", data=payload).decode().strip()
                blobs.append((mode.encode(), head, oid))
        rows = [(mode, name, oid, False) for mode, name, oid in blobs]
        for name, nested in folders.items():
            rows.append((b"40000", name, tree(nested), True))
        body = bytearray()
        for mode, name, oid, is_tree in sorted(rows, key=lambda row: row[1] + (b"/" if row[3] else b"")):
            body += mode + b" " + name + b"\0" + bytes.fromhex(oid)
        return git(repo, "hash-object", "-t", "tree", "-w", "--stdin", data=bytes(body)).decode().strip()

    root = tree(files)
    return git(repo, "commit-tree", root, "-m", "alias fixture").decode().strip(), root


def _probe_directory(parent):
    probe = parent / ("alias-probe-%s" % os.urandom(4).hex())
    probe.mkdir()
    return probe


def _directory_aliases(parent, first, second):
    """True when the destination treats the two directory spellings as one entry."""
    probe = _probe_directory(parent)
    try:
        os.mkdir(probe / first)
        try:
            os.mkdir(probe / second)
        except FileExistsError:
            return True
        left, right = os.stat(probe / first), os.stat(probe / second)
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    finally:
        shutil.rmtree(probe)


def _name_aliases(parent, first, second):
    """True when a symlink created as first is visible as second."""
    probe = _probe_directory(parent)
    try:
        os.symlink(".", probe / first)
        try:
            found = os.readlink(probe / second)
        except FileNotFoundError:
            return False
        return found == "."
    finally:
        shutil.rmtree(probe)


def test_export_uses_public_reader_batches_not_one_process_per_path(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    for index in range(6):
        (repo.path / ("same-%d" % index)).write_bytes(b"shared\n")
    (repo.path / "unique-a").write_bytes(b"aaa\n")
    (repo.path / "unique-b").write_bytes(b"bbb\n")
    commit, tree = _commit(repo, "many paths")
    calls = _reader(monkeypatch, source)
    target = repo.parent / "output"
    try:
        record = api.export_commit(repo.path, commit, tree, target)
    finally:
        writable_exports(target)
    facade = [item for item in calls if item[0] != "run"]
    blob_reads = [count for kind, name, count in facade if (kind, name) == ("read_blobs", "blob")]
    blob_sizes = [count for kind, name, count in facade if (kind, name) == ("blob_sizes", "blob")]
    assert blob_sizes and blob_reads
    assert sum(blob_reads) < record["entries"]
    assert max(blob_reads) < record["entries"]
    assert ("blob_sizes", "commit", 1) in facade
    assert ("read_blobs", "commit", 1) in facade
    assert not any(item[0] == "run" and tuple(item[1][:2]) == ("cat-file", "blob") for item in calls)
    assert (target / "same-0").read_bytes() == b"shared\n"
    assert record["entries"] > len(blob_reads)


def test_blob_preflight_refuses_underreported_oversize_before_read(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    oversized = repo.path / "oversized"
    ceiling = {40: 134217671, 64: 134217647}[len(repo.commit)]
    with oversized.open("xb") as stream:
        stream.truncate(ceiling + 1)
    commit, tree = _commit(repo, "underreported")
    oid = git(repo.path, "rev-parse", "HEAD:oversized").strip()
    calls = _reader(monkeypatch, source)

    def lie(checkout, argv):
        if "ls-tree" in argv:
            return 0, b"100644 blob " + oid + b" 4\toversized\0"

    service[1].override = lie
    target = repo.parent / "output"
    with refused(source, "export_blob_limit"):
        api.export_commit(repo.path, commit, tree, target)
    assert not target.exists()
    assert not any(kind == "read_blobs" and name == "blob" for kind, name, _count in calls)
    service[1].override = None
    try:
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
    finally:
        writable_exports(target)


def test_corrupt_commit_is_refused_before_publication(source, repo, service):
    make_store(repo.path)
    api, _ = service
    oid = repo.commit
    location = repo.path / ".git" / "objects" / oid[:2] / oid[2:]
    original = location.read_bytes()
    payload = b"tree " + b"0" * 40 + b"\n"
    location.unlink()
    location.write_bytes(zlib.compress(b"commit %d\0%s" % (len(payload), payload)))
    target = repo.parent / "output"
    try:
        with refused(source, "invalid_object"):
            api.export_commit(repo.path, repo.commit, repo.tree, target)
        assert not target.exists()
        location.unlink()
        location.write_bytes(original)
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
    finally:
        writable_exports(target)


def test_case_folded_paths_are_refused_and_retry_exports(source, repo, service):
    """Directory spellings collide only when the destination reports one identity."""
    make_store(repo.path)
    api, _ = service
    commit, tree = _build_commit(repo.path, [
        (b"Dir/a", "100644", b"a\n"),
        (b"dir/b", "100644", b"b\n"),
    ])
    target = repo.parent / "output"
    aliases = _directory_aliases(repo.parent, "dir", "Dir")
    try:
        if aliases:
            with refused(source, "unsafe_tree"):
                api.export_commit(repo.path, commit, tree, target)
            assert not target.exists()
        else:
            assert api.export_commit(repo.path, commit, tree, target)["entries"] == 2
            assert (target / "Dir" / "a").read_bytes() == b"a\n"
            assert (target / "dir" / "b").read_bytes() == b"b\n"
    finally:
        writable_exports(target)
        if target.exists():
            shutil.rmtree(target)
    repaired, repaired_tree = _build_commit(repo.path, [(b"Dir/a", "100644", b"a\n")])
    try:
        assert api.export_commit(repo.path, repaired, repaired_tree, target)["bytes"] > 0
        assert (target / "Dir" / "a").read_bytes() == b"a\n"
    finally:
        writable_exports(target)


def test_case_insensitive_link_escape_is_refused(source, repo, service):
    """A case alias is an escaping link only when the destination equates the names."""
    make_store(repo.path)
    api, _ = service
    commit, tree = _build_commit(repo.path, [
        (b"d", "120000", b"."),
        (b"escape", "120000", b"D/../outside"),
    ])
    target = repo.parent / "output"
    aliases = _name_aliases(repo.parent, "d", "D")
    try:
        if aliases:
            with refused(source, "unsafe_link"):
                api.export_commit(repo.path, commit, tree, target)
            assert not target.exists()
        else:
            assert api.export_commit(repo.path, commit, tree, target)["entries"] == 2
            assert os.readlink(target / "escape") == "D/../outside"
    finally:
        writable_exports(target)
        if target.exists():
            shutil.rmtree(target)
    repaired, repaired_tree = _build_commit(repo.path, [
        (b"dir/file", "100644", b"committed\n"),
        (b"escape", "120000", b"dir/file"),
    ])
    try:
        assert api.export_commit(repo.path, repaired, repaired_tree, target)["entries"] == 2
        assert os.readlink(target / "escape") == "dir/file"
        assert (target / "escape").read_bytes() == b"committed\n"
    finally:
        writable_exports(target)


class _OwnerHome:
    """Point Git at a test-owned home, then put the process environment back."""

    _CLEAR = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")
    _KEYS = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME") + _CLEAR

    def __init__(self, home, xdg=None, drop_xdg=False):
        self._home = str(home)
        self._xdg = None if xdg is None else str(xdg)
        self._drop_xdg = drop_xdg
        self._saved = None

    def __enter__(self):
        self._saved = {key: os.environ.get(key) for key in self._KEYS}
        for key in self._CLEAR:
            os.environ.pop(key, None)
        os.environ["HOME"] = self._home
        os.environ["USERPROFILE"] = self._home
        if self._drop_xdg or self._xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        if self._xdg is not None:
            os.environ["XDG_CONFIG_HOME"] = self._xdg
        return self

    def __exit__(self, *_exc):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


def test_witnesses_keep_owner_ignore_view_and_transport_pins(source, repo):
    make_store(repo.path)
    reads = GitReads(source)
    from aegis_core import team_host_registry
    api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                           object_read_env=team_git.object_read_env,
                           child_environment=team_host_registry.child_environment, program=reads.program)
    home = repo.parent / "global-config-home"
    home.mkdir()
    ignores = home / "ignore"
    ignores.write_text("global-hidden\n")
    (home / ".gitconfig").write_text("[core]\n\texcludesFile = " + str(ignores) + "\n")
    # Default excludes survive a config-suppression view even when global config is nulled.
    default_ignore = home / ".config" / "git" / "ignore"
    default_ignore.parent.mkdir(parents=True)
    default_ignore.write_text("global-hidden\n")
    (repo.path / "global-hidden").write_text("ignored worktree data\n")
    with _OwnerHome(home, drop_xdg=True):
        for planned in (None, False):
            assert api.source_digest(repo.path, planned=planned) == legacy.source_digest(str(repo.path), planned=planned)
            assert api.uncommitted_content(repo.path, planned=planned)[1] == 0
            assert api.source_state(repo.path, planned=planned) == legacy.source_state(None, repo.path, planned=planned)
        suppressed = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        assert legacy.uncommitted_content(repo.path, suppressed)[1] == 0
        assert api.uncommitted_content(repo.path, suppressed)[1] == 0
        assert api.uncommitted_content(repo.path, suppressed, planned=False)[1] == 0
        assert api.source_state(repo.path, suppressed)["dirty_entries"] == 0
        assert api.source_state(repo.path, suppressed, planned=False)["dirty_entries"] == 0
        # Caller home and config locations are not a witness view. The owner excludes stay.
        assert api.uncommitted_content(repo.path, legacy.MERGE_VIEW_ENV)[1] == 0
        assert api.source_state(repo.path, legacy.MERGE_VIEW_ENV, planned=False)["dirty_entries"] == 0
    empty = repo.parent / "empty-home"
    empty.mkdir()
    xdg = repo.parent / "xdg"
    (xdg / "git").mkdir(parents=True)
    (xdg / "git" / "config").write_text("[core]\n\texcludesFile = " + str(ignores) + "\n")
    with _OwnerHome(empty, xdg=xdg):
        assert api.source_digest(repo.path)[1]["dirty_entries"] == 0
        assert api.uncommitted_content(repo.path, planned=False)[1] == 0
        assert api.source_state(repo.path, planned=False)["dirty_entries"] == 0
        hostile = {"GIT_ALLOW_PROTOCOL": "https", "GIT_NO_LAZY_FETCH": "0", "GIT_NO_REPLACE_OBJECTS": "0",
                   "HOME": str(empty), "XDG_CONFIG_HOME": str(xdg)}
        assert api.uncommitted_content(repo.path, hostile)[1] == 0
        status_envs = [env for argv, env in zip(reads.commands, reads.environments) if "status" in argv]
        assert status_envs
        for env in status_envs:
            assert env.get("GIT_ALLOW_PROTOCOL") == ""
            assert env.get("GIT_NO_LAZY_FETCH") == "1"
            assert env.get("GIT_NO_REPLACE_OBJECTS") == "1"
        assert status_envs[-1].get("HOME") == str(empty)
        assert status_envs[-1].get("XDG_CONFIG_HOME") == str(xdg)


def _check_attr_source_supported(repo):
    """The repository's Git 2.40 check for check-attr --source."""
    from aegis_core.team_git_snapshot import GitRefusal, attribute_version
    try:
        attribute_version(git(repo.path, "--version"))
    except GitRefusal:
        return False
    return True


def test_head_ref_accepts_unicode_line_separator_and_refuses_a_second_record(source, repo, service):
    api, reads = service
    ref = "refs/heads/line\u2028sep"
    git(repo.path, "check-ref-format", ref)
    git(repo.path, "symbolic-ref", "HEAD", ref)
    assert ref.splitlines() != [ref]
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(api.head_ref, [repo.path, repo.path])) == [ref, ref]
    assert api.head_ref(repo.path) == legacy.head_ref(repo.path) == ref
    trailing = "refs/heads/trail\u2028"
    probe = subprocess.run(["git", "check-ref-format", trailing], cwd=repo.path, capture_output=True)
    if probe.returncode == 0:
        git(repo.path, "symbolic-ref", "HEAD", trailing)
        # Legacy str.strip drops a trailing U+2028. The core record keeps it (parity exception).
        assert api.head_ref(repo.path) == trailing
        assert legacy.head_ref(repo.path) == trailing.strip()
        assert api.head_ref(repo.path) != legacy.head_ref(repo.path)
        git(repo.path, "symbolic-ref", "HEAD", ref)
        assert api.head_ref(repo.path) == ref

    def second_record(_checkout, argv):
        if "symbolic-ref" in argv:
            return 0, b"refs/heads/one\nrefs/heads/two\n"
        return None

    reads.override = second_record
    with refused(source, "git_protocol"):
        api.head_ref(repo.path)
    reads.override = None
    assert api.head_ref(repo.path) == ref


def test_merge_preflight_and_detached_head_parity(source, repo, service):
    api, _ = service
    assert api.head_ref(repo.path) == legacy.head_ref(repo.path)
    with refused(source, "merge_contained"):
        api.merge_refusals(repo.path, repo.commit, repo.commit)
    with pytest.raises(ValueError, match="already contained"):
        legacy.merge_refusals(repo.path, repo.commit, repo.commit)
    git(repo.path, "checkout", "-qb", "side")
    (repo.path / "other").write_bytes(b"side\n")
    git(repo.path, "commit", "-qam", "side")
    side = git(repo.path, "rev-parse", "HEAD").decode().strip()
    git(repo.path, "checkout", "-q", "--detach", repo.commit)
    assert api.head_ref(repo.path) is legacy.head_ref(repo.path) is None
    if _check_attr_source_supported(repo):
        assert api.merge_refusals(repo.path, repo.commit, side) is None


def test_absolute_link_must_match_the_export_root_bytewise(source, repo, service):
    """OUTPUT is a different path from output, including through a nested link."""
    make_store(repo.path)
    api, _ = service
    target = repo.parent / "output"
    root = os.fsencode(os.fspath(target))
    parent, name = root.rsplit(b"/", 1)
    assert name == b"output"
    hostile = parent + b"/OUTPUT/secret"
    symlink_or_skip(os.fsdecode(hostile), repo.path / "direct")
    symlink_or_skip("direct", repo.path / "hop")
    commit, tree = _commit(repo, "absolute aliases")
    with refused(source, "unsafe_link"):
        api.export_commit(repo.path, commit, tree, target)
    assert not target.exists()
    (repo.path / "direct").unlink()
    (repo.path / "hop").unlink()
    symlink_or_skip(os.fsdecode(root + b"/dir/file"), repo.path / "direct")
    symlink_or_skip("direct", repo.path / "hop")
    commit, tree = _commit(repo, "absolute repaired")
    try:
        assert api.export_commit(repo.path, commit, tree, target)["entries"] >= 3
        assert os.readlink(target / "direct") == os.fsdecode(root + b"/dir/file")
        assert (target / "direct").read_bytes() == b"committed\n"
        assert (target / "hop").read_bytes() == b"committed\n"
    finally:
        writable_exports(target)


def _export_os(*, fstat=os.fstat, scandir=os.scandir, mkdir=os.mkdir):
    return SimpleNamespace(
        O_RDONLY=os.O_RDONLY, O_WRONLY=os.O_WRONLY, O_DIRECTORY=os.O_DIRECTORY,
        O_NOFOLLOW=os.O_NOFOLLOW, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL,
        path=os.path, fsencode=os.fsencode, fspath=os.fspath, open=os.open, close=os.close, write=os.write,
        stat=os.stat, fstat=fstat, scandir=scandir, mkdir=mkdir, fchmod=os.fchmod,
        rename=os.rename, unlink=os.unlink, rmdir=os.rmdir)


@pytest.mark.parametrize("fault", ["fstat", "scandir"])
def test_export_directory_observation_failure_refuses_then_retries(
        source, repo, service, monkeypatch, fault):
    make_store(repo.path)
    api, _ = service
    target = repo.parent / "output"
    commit, tree = _build_commit(repo.path, [
        (b"shared/a", "100644", b""),
        (b"shared/b", "100644", b""),
    ])
    real = os.fstat if fault == "fstat" else os.scandir
    failed = []

    def observe(fd):
        if not failed:
            failed.append(True)
            raise OSError("private fixture diagnostic")
        return real(fd)

    fixture_os = _export_os(fstat=observe) if fault == "fstat" else _export_os(scandir=observe)
    monkeypatch.setattr(source_module, "descriptor_supported", lambda: True)
    monkeypatch.setattr(source_module, "os", fixture_os)
    with refused(source, "unsafe_tree") as failure:
        api.export_commit(repo.path, commit, tree, target)
    assert failed
    assert "private fixture diagnostic" not in str(failure.value)
    assert not target.exists()
    assert not list(repo.parent.glob(".aegis-job-export-*"))
    try:
        assert api.export_commit(repo.path, commit, tree, target)["entries"] == 2
        assert (target / "shared" / "a").read_bytes() == b""
        assert (target / "shared" / "b").read_bytes() == b""
    finally:
        writable_exports(target)


@pytest.mark.parametrize("git_stub", [False, True])
def test_export_refuses_unowned_directory_identity_then_retries(
        source, repo, service, monkeypatch, git_stub):
    make_store(repo.path)
    api, _ = service
    commit, tree = _build_commit(repo.path, [
        (b"shared/a", "100644", b""),
        (b"shared/b", "100644", b""),
    ])
    selected = b".git" if git_stub else b"shared"
    calls = []

    def mkdir(name, mode, *, dir_fd):
        if name == selected:
            calls.append(name)
            if len(calls) == (1 if git_stub else 2):
                if not git_stub:
                    os.rename(name, b"previous", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                os.mkdir(name, mode, dir_fd=dir_fd)
        os.mkdir(name, mode, dir_fd=dir_fd)

    target = repo.parent / "output"
    monkeypatch.setattr(source_module, "descriptor_supported", lambda: True)
    monkeypatch.setattr(source_module, "os", _export_os(mkdir=mkdir))
    with refused(source, "unsafe_tree"):
        api.export_commit(repo.path, commit, tree, target, git_stub)
    assert calls and not target.exists()
    assert not list(repo.parent.glob(".aegis-job-export-*"))
    try:
        assert api.export_commit(repo.path, commit, tree, target, git_stub)["entries"] == 2
    finally:
        writable_exports(target)


def test_normalization_aliases_follow_destination_identity(source, repo, service):
    """Composed and decomposed spellings collide only when the destination equates them."""
    make_store(repo.path)
    api, _ = service
    composed, decomposed = "é".encode(), "e\u0301".encode()
    commit, tree = _build_commit(repo.path, [
        (composed, "120000", b"."),
        (b"escape", "120000", decomposed + b"/../outside"),
    ])
    target = repo.parent / "output"
    aliases = _name_aliases(repo.parent, composed.decode(), decomposed.decode())
    try:
        if aliases:
            with refused(source, "unsafe_link"):
                api.export_commit(repo.path, commit, tree, target)
            assert not target.exists()
        else:
            assert api.export_commit(repo.path, commit, tree, target)["entries"] == 2
            assert os.readlink(target / "escape") == (decomposed + b"/../outside").decode()
    finally:
        writable_exports(target)
        if target.exists():
            shutil.rmtree(target)
    directories, directory_tree = _build_commit(repo.path, [
        (composed + b"/a", "100644", b"a\n"),
        (decomposed + b"/b", "100644", b"b\n"),
    ])
    merged = _directory_aliases(repo.parent, composed.decode(), decomposed.decode())
    try:
        if merged:
            with refused(source, "unsafe_tree"):
                api.export_commit(repo.path, directories, directory_tree, target)
            assert not target.exists()
        else:
            assert api.export_commit(repo.path, directories, directory_tree, target)["entries"] == 2
            assert (target / composed.decode() / "a").read_bytes() == b"a\n"
            assert (target / decomposed.decode() / "b").read_bytes() == b"b\n"
    finally:
        writable_exports(target)


def test_corrupt_commit_is_refused_before_recipe_membership(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    location = repo.path / ".git" / "objects" / repo.commit[:2] / repo.commit[2:]
    original = location.read_bytes()
    payload = b"tree " + b"0" * 40 + b"\n"
    location.unlink()
    location.write_bytes(zlib.compress(b"commit %d\0%s" % (len(payload), payload)))
    membership = []

    def run(argv, checkout, **kwargs):
        membership.append((tuple(argv), checkout))
        return gitsafe.run(argv, checkout, **kwargs)

    monkeypatch.setattr(source_module, "gitsafe", SimpleNamespace(
        run=run, custody=gitsafe.custody, GitError=gitsafe.GitError,
        blob_sizes=gitsafe.blob_sizes, read_blobs=gitsafe.read_blobs))
    try:
        with refused(source, "invalid_object"):
            api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file"])
        assert membership == []
    finally:
        if location.exists():
            location.unlink()
        location.write_bytes(original)
    assert api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file"]) is None
    assert len(membership) == 1
    with refused(source, "path_outside_commit"):
        api.refuse_paths_outside_commit(repo.path, repo.commit, ["missing"])


def test_public_reads_stay_in_bounded_custody_for_the_checkout(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    foreign = repo.parent / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-q")
    (foreign / "foreign").write_bytes(b"other-repo\n")
    git(foreign, "add", "--", ".")
    git(foreign, "commit", "-qm", "foreign")
    events = []

    @contextmanager
    def custody(**kwargs):
        events.append(("custody", kwargs))
        with gitsafe.custody(**kwargs):
            yield

    def blob_sizes(cwd, oids, **kwargs):
        events.append(("blob_sizes", kwargs.get("kind", "blob"), os.fspath(cwd)))
        assert events[-2][0] == "custody"
        return gitsafe.blob_sizes(cwd, list(oids), **kwargs)

    def read_blobs(cwd, oids, **kwargs):
        events.append(("read_blobs", kwargs.get("kind", "blob"), os.fspath(cwd)))
        assert events[-2][0] == "custody"
        return gitsafe.read_blobs(cwd, list(oids), **kwargs)

    def run(argv, cwd, **kwargs):
        assert events[-1][0] == "custody"
        scope = events[-1][1]
        assert scope["stdout_limit"] == 0
        assert scope["replace_env"] is True
        assert scope["env"]["GIT_CONFIG_GLOBAL"] == os.devnull
        assert "GIT_DIR" not in scope["env"]
        assert tuple(argv[-3:-1]) == ("cat-file", "-e")
        events.append(("membership", "commit", os.fspath(cwd)))
        return gitsafe.run(argv, cwd, **kwargs)

    monkeypatch.setattr(source_module, "gitsafe", SimpleNamespace(
        run=run, custody=custody, GitError=gitsafe.GitError,
        blob_sizes=blob_sizes, read_blobs=read_blobs, iter_objects=gitsafe.iter_objects))
    saved = os.environ.get("GIT_DIR")
    os.environ["GIT_DIR"] = str(foreign / ".git")
    target = repo.parent / "output"
    try:
        assert api.export_commit(repo.path, repo.commit, repo.tree, target)["entries"] == 2
        assert (target / "dir/file").read_bytes() == b"committed\n"
        assert api.refuse_paths_outside_commit(repo.path, repo.commit, ["dir/file"]) is None
    finally:
        if saved is None:
            os.environ.pop("GIT_DIR", None)
        else:
            os.environ["GIT_DIR"] = saved
        writable_exports(target)
    reader_events = [item for item in events if item[0] != "custody"]
    kinds = [(item[0], item[1]) for item in reader_events]
    assert ("blob_sizes", "commit") in kinds
    assert ("read_blobs", "commit") in kinds
    assert ("blob_sizes", "blob") in kinds
    assert ("read_blobs", "blob") in kinds
    held = [item[1] for item in events if item[0] == "custody"]
    limits = [item["stdout_limit"] for item in held]
    assert limits and all(type(limit) is int and 0 <= limit <= 134217728 for limit in limits)
    assert all(item["env"].get("GIT_DIR") is None and item["env"].get("GIT_NO_REPLACE_OBJECTS") == "1"
               for item in held)
    assert all(item[2] == str(repo.path) for item in reader_events)
    assert ("membership", "commit") in kinds


@pytest.mark.parametrize("planned", [True, False])
def test_export_isolates_all_reader_children(source, repo, service, planned):
    make_store(repo.path)
    _, reads = service
    foreign = repo.parent / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-q")
    ambient = {
        "OPENAI_" + "API_KEY": "synthetic-fixture",
        "GIT_DIR": str(foreign / ".git"),
        "GIT_WORK_TREE": str(foreign),
        "GIT_INDEX_FILE": str(foreign / ".git" / "index"),
        "GIT_OBJECT_DIRECTORY": str(foreign / ".git" / "objects"),
        "GIT_CONFIG_PARAMETERS": "'core.abbrev=12'",
    }
    keys = tuple(ambient)
    ambient["GIT_CONFIG_GLOBAL"] = str(foreign / ".git" / "config")
    real_git = shutil.which("git")
    observer = repo.parent / "git-observer"
    script = repo.parent / "observe_git.py"
    observations = repo.parent / "readers.log"
    script.write_text(
        "import os, sys\n"
        f"flags = [key in os.environ for key in {keys!r}]\n"
        "flags.append(os.environ.get('GIT_CONFIG_GLOBAL') != os.devnull)\n"
        "if 'cat-file' in sys.argv[1:]:\n"
        "    kind = 'size' if '--batch-check' in sys.argv[1:] else 'payload'\n"
        f"    with open({str(observations)!r}, 'a', encoding='ascii') as log:\n"
        "        log.write(kind + ' ' + ''.join('1' if present else '0' for present in flags) + '\\n')\n"
        f"os.execv({real_git!r}, [{real_git!r}, *sys.argv[1:]])\n",
        encoding="utf-8",
    )
    observer.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I {shlex.quote(str(script))} "$@"\n',
        encoding="utf-8",
    )
    observer.chmod(0o700)
    api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                           object_read_env=team_git.object_read_env, child_environment=lambda env, _: env,
                           program=str(observer))
    saved = {key: os.environ.get(key) for key in ambient}
    target = repo.parent / "output"
    root_token = pathlookup.ordinary_root.set(str(repo.path))
    try:
        os.environ.update(ambient)
        assert api.export_commit(repo.path, repo.commit, repo.tree, target, planned=planned)["entries"] == 2
        assert (target / "dir" / "file").read_bytes() == b"committed\n"
        absent = "0" * (len(keys) + 1)
        assert observations.read_text(encoding="ascii").splitlines() == [
            "size " + absent, "payload " + absent, "size " + absent, "payload " + absent,
        ]
    finally:
        pathlookup.ordinary_root.reset(root_token)
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        writable_exports(target)


def test_owner_excludes_file_survives_a_caller_config_view(source, repo):
    make_store(repo.path)
    reads = GitReads(source)
    from aegis_core import team_host_registry
    api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                           object_read_env=team_git.object_read_env,
                           child_environment=team_host_registry.child_environment, program=reads.program)
    home = repo.parent / "excludes-home"
    home.mkdir()
    excludes = home / "excludes"
    excludes.write_text("env-hidden\n")
    (repo.path / "env-hidden").write_text("hidden by owner policy\n")
    caller_config = repo.parent / "caller.gitconfig"
    caller_config.write_text("[core]\n\texcludesFile = %s\n" % os.devnull, encoding="utf-8")
    (repo.path / "dir/file").write_bytes(b"changed-for-filter\n")
    keys = ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0")
    saved = {key: os.environ.get(key) for key in keys}
    try:
        with _OwnerHome(home, drop_xdg=True):
            os.environ["GIT_CONFIG_COUNT"] = "1"
            os.environ["GIT_CONFIG_KEY_0"] = "core.excludesFile"
            os.environ["GIT_CONFIG_VALUE_0"] = str(excludes)
            for planned in (None, False):
                assert api.uncommitted_content(repo.path, planned=planned)[1] == 1
                assert api.source_digest(repo.path, planned=planned)[1]["dirty_entries"] == 1
                assert api.source_state(repo.path, planned=planned)["dirty_entries"] == 1
                assert legacy.uncommitted_content(repo.path, planned=planned)[1] == 1
            view = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.excludesFile",
                    "GIT_CONFIG_VALUE_0": os.devnull, "GIT_CONFIG_GLOBAL": str(caller_config),
                    "GIT_CONFIG_NOSYSTEM": "1", "HOME": os.devnull}
            assert api.uncommitted_content(repo.path, view)[1] == 1
            assert api.source_state(repo.path, view, planned=False)["dirty_entries"] == 1
            status_envs = [env for argv, env in zip(reads.commands, reads.environments) if "status" in argv]
            assert status_envs
            assert status_envs[-1].get("GIT_CONFIG_VALUE_0") == str(excludes)
            assert status_envs[-1].get("GIT_CONFIG_GLOBAL") != str(caller_config)
            assert status_envs[-1].get("HOME") == str(home)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.mark.parametrize("planned", [True, False])
@pytest.mark.parametrize("malformed", [False, True])
def test_witness_owner_git_parameters_match_legacy(source, repo, service, planned, malformed):
    make_store(repo.path)
    api, _ = service
    ignores = repo.parent / "owner's ignores"
    ignores.write_bytes(b"hidden\n")
    (repo.path / "hidden").write_bytes(b"only the owner excludes this\n")
    git(repo.path, "config", "core.excludesFile", os.devnull)
    parameters = "'core.excludesFile'='" + str(ignores).replace("'", "'\\''") + "'"
    settings = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.excludesFile",
                "GIT_CONFIG_VALUE_0": os.devnull,
                "GIT_CONFIG_PARAMETERS": "malformed" if malformed else parameters}
    saved = {name: os.environ.get(name) for name in settings}
    try:
        os.environ.update(settings)
        pairs = (
            (lambda: api.uncommitted_content(repo.path, planned=planned),
             lambda: legacy.uncommitted_content(repo.path, planned=planned), "^could not read the status of "),
            (lambda: api.source_digest(repo.path, planned=planned),
             lambda: legacy.source_digest(str(repo.path), planned=planned), "^could not read the status of "),
            (lambda: api.source_state(repo.path, planned=planned),
             lambda: legacy.source_state(None, repo.path, planned=planned), "^git identity check failed$"),
        )
        for core, old, legacy_reason in pairs:
            if malformed:
                with pytest.raises(ValueError, match=legacy_reason):
                    old()
                with refused(source, "git_failed"):
                    core()
            else:
                assert core() == old()
        if malformed:
            os.environ["GIT_CONFIG_PARAMETERS"] = parameters
            for core, old, _ in pairs:
                assert core() == old()
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.mark.parametrize("planned", [True, False])
@pytest.mark.parametrize("channel", [
    "parameters", "numbered", "mixed-parameters", "mixed-numbered", "batched", "batched-mixed",
])
@pytest.mark.parametrize("include_key", ["INCLUDE.Path", "includeIf.onbranch:no-such-branch.PATH"],
                         ids=["unconditional", "conditional"])
def test_witness_refuses_owner_command_config_includes(source, repo, service, planned, channel, include_key):
    make_store(repo.path)
    api, reads = service
    home = repo.parent / "owner-config"
    home.mkdir()
    include = home / "owner.cfg"
    include.write_text("[core]\nexcludesFile = ~/ignores\n", encoding="utf-8")
    (home / "ignores").write_text("include-hidden\n", encoding="utf-8")
    (repo.path / "include-hidden").write_bytes(b"excluded by the direct policy\n")
    git(repo.path, "config", "core.excludesFile", os.devnull)
    count = {"parameters": 0, "numbered": 2, "mixed-parameters": 1,
             "mixed-numbered": 1, "batched": 64, "batched-mixed": 64}[channel]
    index = count - 2 if count == 64 and include_key.startswith("includeIf") else 0
    numbered_keys = [f"GIT_CONFIG_{kind}_{idx}" for idx in range(count) for kind in ("KEY", "VALUE")]
    key = f"GIT_CONFIG_KEY_{index}"
    value = f"GIT_CONFIG_VALUE_{index}"
    direct = "'core.excludesFile=~/ignores'"
    include_parameter = f"'{include_key}'='" + str(include).replace("'", "'\\''") + "'"

    def configure(with_include):
        if channel in ("numbered", "batched"):
            os.environ.pop("GIT_CONFIG_PARAMETERS", None)
            os.environ[f"GIT_CONFIG_VALUE_{count - 1}"] = "~/ignores"
        else:
            os.environ["GIT_CONFIG_PARAMETERS"] = direct
        if channel in ("parameters", "mixed-parameters"):
            if with_include:
                os.environ["GIT_CONFIG_PARAMETERS"] = include_parameter + " " + direct
        else:
            os.environ[key] = include_key if with_include else "core.excludesFile"
            os.environ[value] = str(include) if with_include else os.devnull

    pairs = (
        (lambda: api.uncommitted_content(repo.path, planned=planned),
         lambda: legacy.uncommitted_content(repo.path, planned=planned)),
        (lambda: api.source_digest(repo.path, planned=planned),
         lambda: legacy.source_digest(str(repo.path), planned=planned)),
        (lambda: api.source_state(repo.path, planned=planned),
         lambda: legacy.source_state(None, repo.path, planned=planned)),
    )
    with _OwnerHome(home, drop_xdg=True), _temporary_environment(
            "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", *numbered_keys):
        os.environ["GIT_CONFIG_COUNT"] = str(count)
        for idx in range(count):
            os.environ[f"GIT_CONFIG_KEY_{idx}"] = "core.excludesFile"
            os.environ[f"GIT_CONFIG_VALUE_{idx}"] = os.devnull
        for core, old in pairs:
            configure(True)
            reads.commands.clear()
            with refused(source, "git_failed"):
                core()
            assert reads.commands == []
            configure(False)
            assert core() == old()


@pytest.mark.parametrize("planned", [True, False])
@pytest.mark.parametrize("malformed", ["invalid-key", "missing-key", "missing-value"])
def test_witness_refuses_malformed_numbered_config_then_retries(source, repo, service, planned, malformed):
    make_store(repo.path)
    api, reads = service
    pairs = (
        (lambda: api.uncommitted_content(repo.path, planned=planned),
         lambda: legacy.uncommitted_content(repo.path, planned=planned), "^could not read the status of "),
        (lambda: api.source_digest(repo.path, planned=planned),
         lambda: legacy.source_digest(str(repo.path), planned=planned), "^could not read the status of "),
        (lambda: api.source_state(repo.path, planned=planned),
         lambda: legacy.source_state(None, repo.path, planned=planned), "^git identity check failed$"),
    )
    key, value = "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"
    with _temporary_environment("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", key, value):
        os.environ.pop("GIT_CONFIG_PARAMETERS", None)
        os.environ["GIT_CONFIG_COUNT"] = "1"
        for core, old, legacy_reason in pairs:
            os.environ[key] = "malformed" if malformed == "invalid-key" else "core.filemode"
            os.environ[value] = "false"
            if malformed != "invalid-key":
                os.environ.pop(key if malformed == "missing-key" else value)
            with pytest.raises(ValueError, match=legacy_reason):
                old()
            reads.commands.clear()
            with refused(source, "git_failed"):
                core()
            assert reads.commands == []
            os.environ.update(GIT_CONFIG_KEY_0="core.excludesFile", GIT_CONFIG_VALUE_0=os.devnull)
            assert core() == old()


def test_witness_reuses_one_unchanged_projection_and_preserves_identity_timeout(repo, service, monkeypatch):
    make_store(repo.path)
    api, reads = service
    projections = []

    def run(argv, cwd, **options):
        projections.append((tuple(argv), cwd))
        return gitsafe.run(argv, cwd, **options)

    monkeypatch.setattr(source_module, "gitsafe", SimpleNamespace(
        run=run, custody=gitsafe.custody, GitError=gitsafe.GitError))
    with _temporary_environment("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
                                "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"):
        os.environ.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.excludesFile",
                          GIT_CONFIG_VALUE_0=os.devnull, GIT_CONFIG_PARAMETERS="'core.excludesFile='")
        for witness in (api.source_digest, api.source_state, api.uncommitted_content):
            projections.clear()
            reads.commands.clear()
            reads.timeouts.clear()
            witness(repo.path)
            assert len(projections) == 1
            args, cwd = projections[0]
            assert "--no-includes" in args and cwd == repo.path
            identity_timeouts = [timeout for argv, timeout in zip(reads.commands, reads.timeouts)
                                 if "rev-parse" in argv]
            assert identity_timeouts == ([] if witness == api.uncommitted_content else [5, 5])


@pytest.mark.parametrize("planned", [True, False])
@pytest.mark.parametrize("channel", ["parameters", "numbered"])
@pytest.mark.parametrize("order", ["only", "first", "last"])
@pytest.mark.parametrize("late", [False, True], ids=["initial-status", "content-status"])
def test_valueless_owner_excludes_refuses_then_retries(source, repo, service, planned, channel, order, late):
    make_store(repo.path)
    api, reads = service
    (repo.path / "valueless-fixture").write_bytes(b"untracked data\n")
    key = "core.excludesFile"

    def configure(valueless):
        values = [None if valueless else ""]
        if order == "first":
            values.append("")
        elif order == "last":
            values.insert(0, "")
        if channel == "parameters":
            os.environ["GIT_CONFIG_COUNT"] = "0"
            os.environ["GIT_CONFIG_PARAMETERS"] = " ".join(
                f"'{key}'" if value is None else f"'{key}={value}'" for value in values)
        else:
            os.environ.pop("GIT_CONFIG_PARAMETERS", None)
            os.environ["GIT_CONFIG_COUNT"] = str(len(values))
            for index, value in enumerate(values):
                os.environ[f"GIT_CONFIG_KEY_{index}"] = key
                name = f"GIT_CONFIG_VALUE_{index}"
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def after_identity(_, argv):
        if argv[-2:] == ["rev-parse", "HEAD^{tree}"]:
            # The identity read already holds its own replacement environment.
            configure(True)

    pairs = [(lambda: api.source_state(repo.path, planned=planned),
              lambda: legacy.source_state(None, repo.path, planned=planned), "^git identity check failed$")]
    if not late:
        pairs.extend([
            (lambda: api.uncommitted_content(repo.path, planned=planned),
             lambda: legacy.uncommitted_content(repo.path, planned=planned), "^could not read the status of "),
            (lambda: api.source_digest(repo.path, planned=planned),
             lambda: legacy.source_digest(str(repo.path), planned=planned), "^could not read the status of "),
        ])
    with _temporary_environment("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_KEY_0",
                                "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_VALUE_1"):
        for core, old, legacy_reason in pairs:
            configure(True)
            with pytest.raises(ValueError, match=legacy_reason):
                old()
            reads.commands.clear()
            if late:
                configure(False)
                reads.override = after_identity
            with refused(source, "git_failed"):
                core()
            if late:
                assert [argv[-1] for argv in reads.commands] == ["--untracked-files=all", "HEAD", "HEAD^{tree}"]
            reads.override = None
            configure(False)
            assert core() == old()


@pytest.mark.parametrize("planned", [True, False])
def test_owner_system_config_applies_to_status_and_identity(repo, service, planned):
    make_store(repo.path)
    api, reads = service
    ignores = repo.parent / "system-ignore"
    ignores.write_bytes(b"system-hidden\n")
    system = repo.parent / "owner.gitconfig"
    system.write_text("[core]\n\texcludesFile = " + str(ignores) + "\n", encoding="utf-8")
    (repo.path / "system-hidden").write_bytes(b"ignored by the owner system config\n")
    with _temporary_environment("GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM"):
        os.environ.update(GIT_CONFIG_SYSTEM=str(system), GIT_CONFIG_NOSYSTEM="0")
        expected = legacy.source_state(None, repo.path, planned=planned)
        assert expected["dirty_entries"] == 0
        assert api.source_state(repo.path, planned=planned) == expected
    for command, count in (("status", 2), ("rev-parse", 2)):
        scopes = [env for argv, env in zip(reads.commands, reads.environments) if command in argv]
        assert len(scopes) == count
        assert all(env.get("GIT_CONFIG_SYSTEM") == str(system) for env in scopes)
        assert all(env.get("GIT_CONFIG_NOSYSTEM") == "0" for env in scopes)


@pytest.mark.parametrize("name,value", [
    ("HOME", 65537),
    ("XDG_CONFIG_HOME", 65537),
    ("GIT_CONFIG_GLOBAL", 65537),
    ("GIT_CONFIG_COUNT", "invalid"),
    ("GIT_CONFIG_COUNT", "²"),
    ("GIT_CONFIG_KEY_0", 257),
    ("GIT_CONFIG_VALUE_0", 65537),
], ids=["home", "xdg", "global", "count", "unicode-count", "key", "value"])
def test_owner_ignore_policy_refuses_invalid_environment_then_retries(
        source, repo, service, name, value):
    make_store(repo.path)
    api, reads = service
    baseline = api.uncommitted_content(repo.path)
    settings = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.excludesFile",
                "GIT_CONFIG_VALUE_0": os.devnull, name: "x" * value if type(value) is int else value}
    saved = {key: os.environ.get(key) for key in settings}
    try:
        os.environ.update(settings)
        reads.commands.clear()
        for witness in (api.uncommitted_content, api.source_state, api.source_digest):
            with refused(source, "invalid_input"):
                witness(repo.path, planned=False)
        assert reads.commands == []
    finally:
        for key, initial in saved.items():
            if initial is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = initial
    assert api.uncommitted_content(repo.path) == baseline


def test_witness_view_locations_never_reach_the_owner_policy(source, repo):
    make_store(repo.path)
    home = repo.parent / "owner-home"
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".config" / "git" / "ignore").write_text("owner-hidden\n", encoding="utf-8")
    (repo.path / "owner-hidden").write_bytes(b"ignored fixture\n")
    supplied = []
    owner_home = str(home)

    def owner_policy(view, *, inherit_config):
        supplied.append(view)
        env = team_git.object_read_env(inherit_config=inherit_config)
        return {**env, "HOME": owner_home, "XDG_CONFIG_HOME": str(home / ".config"), **(view or {})}

    reads = GitReads(source)
    api = source.JobSource(run=reads.run, object_read_argv=team_git.object_read_argv,
                           object_read_env=owner_policy, child_environment=lambda env, _: env,
                           program=reads.program)
    caller = {"GIT_CONFIG_GLOBAL": str(repo.parent / "caller.gitconfig"), "HOME": os.devnull}
    assert api.uncommitted_content(repo.path, caller, planned=False)[1] == 0
    assert api.source_state(repo.path, caller)["dirty_entries"] == 0
    assert supplied and all(view is None for view in supplied)
    owner_home = None
    with refused(source, "invalid_input"):
        api.uncommitted_content(repo.path, caller)


def test_deadline_covers_empty_files_repeated_links_and_directory_creation(source, repo, service, monkeypatch):
    make_store(repo.path)
    api, _ = service
    state = {"empty_clocks": 0, "place_clocks": 0, "create_clocks": 0,
             "in_write": False, "empty": False, "in_place": False, "in_create": False,
             "fail_empty": False}
    real_clock, real_write = source_module._clock, source_module._write_file
    real_place, real_descend = source_module._place_entry, source_module._descend

    def clock(deadline):
        if state["fail_empty"] and state["in_write"] and state["empty"]:
            raise source_module.JobSourceRefusal("git_timeout")
        if state["in_write"] and state["empty"]:
            state["empty_clocks"] += 1
        if state["in_place"] and not state["in_write"] and not state["in_create"]:
            state["place_clocks"] += 1
        if state["in_create"]:
            state["create_clocks"] += 1
        return real_clock(deadline)

    def write(parent, name, mode, data, deadline):
        state["in_write"] = True
        state["empty"] = len(data) == 0
        try:
            return real_write(parent, name, mode, data, deadline)
        finally:
            state["in_write"] = False
            state["empty"] = False

    def place(*args, **kwargs):
        state["in_place"] = True
        try:
            return real_place(*args, **kwargs)
        finally:
            state["in_place"] = False

    @contextmanager
    def descend(*args, **kwargs):
        state["in_create"] = bool(kwargs.get("create"))
        try:
            with real_descend(*args, **kwargs) as parent:
                yield parent
        finally:
            state["in_create"] = False

    monkeypatch.setattr(source_module, "_clock", clock)
    monkeypatch.setattr(source_module, "_write_file", write)
    monkeypatch.setattr(source_module, "_place_entry", place)
    monkeypatch.setattr(source_module, "_descend", descend)
    symlink_or_skip("dir/file", repo.path / "link-a")
    symlink_or_skip("dir/file", repo.path / "link-b")
    (repo.path / "nested").mkdir()
    (repo.path / "nested" / "empty").write_bytes(b"")
    commit, tree = _commit(repo, "deadline placements")
    target = repo.parent / "output"
    try:
        record = api.export_commit(repo.path, commit, tree, target)
        assert state["empty_clocks"] >= 1
        assert state["place_clocks"] >= record["entries"]
        assert state["create_clocks"] >= 1
        writable_exports(target)
        shutil.rmtree(target)
        state["fail_empty"] = True
        with refused(source, "git_timeout"):
            api.export_commit(repo.path, commit, tree, target)
        assert not target.exists()
        state["fail_empty"] = False
        assert api.export_commit(repo.path, commit, tree, target)["entries"] == record["entries"]
    finally:
        writable_exports(target)
