"""Public tree and insight identity APIs retain Git record path spellings."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Barrier
from types import SimpleNamespace

import pytest

from aegis_core import gitops_fds, gitsafe, gitsafe_run, pathlookup_fence, storage_confined, treeid
from aegis_core.insights import keys
from aegis_core.workspace import hooks
from tests.helpers_reviewed_sources import git as census_git

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(root, *args):
    return subprocess.run(["git", "-c", "user.name=Writer", "-c", "user.email=writer@example.invalid",
        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
        "-c", "core.fsmonitor=false", *args], cwd=root, check=True,
        capture_output=True, timeout=15).stdout


def _layout(tmp_path, record, *, absolute=False, spaces=False, sibling=False, external=False):
    root = tmp_path / "root"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / ".gitignore").write_bytes(b"/ admin*/\n/admin/\n/alternate/\n")
    (root / "tracked.txt").write_bytes(b"owner content\n")
    _git(root, "add", ".gitignore", "tracked.txt")
    _git(root, "commit", "-qm", "owner")
    expected_tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").removesuffix("\n")
    admin_parent = tmp_path if external else root
    admin = admin_parent / (" admin " if spaces and record == "gitdir" else "admin")
    _git(root, "init", "-q", "--separate-git-dir", str(admin))
    (root / ".aegis").mkdir()
    if record == "gitdir":
        common, selected, base, prefix = admin, root / ".git", root, b"gitdir: "
        target = admin
    else:
        common_parent = tmp_path if external else admin
        common = common_parent / (" common " if spaces else "common")
        common.mkdir()
        for name in ("objects", "refs", "config"):
            (admin / name).rename(common / name)
        selected, base, prefix, target = admin / "commondir", admin, b"", common
    spelling = str(target) if absolute else os.path.relpath(target, base)
    good = prefix + os.fsencode(spelling) + b"\n"
    selected.write_bytes(good)
    if sibling:
        # Construct the exact spelling the old strip-based parser would select.
        neighbor = Path(spelling.strip()) if absolute else base / spelling.strip()
        assert neighbor != target
        _git(root, "init", "-q", "--bare", str(neighbor))
    assert _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").removesuffix("\n") == expected_tree
    return root, admin, common, selected, good, expected_tree


def _effect_layout(root):
    return gitops_fds.effect_environment({}, root, error=gitsafe.GitError,
        worktree_root=root, transport=gitsafe_run.transport_services())


def _require_descriptor_api(api):
    if api == "effect" and not (gitops_fds.descriptor_supported() and storage_confined.descriptor_supported()):
        pytest.skip("effect discovery requires descriptor custody")
    if api == "review" and not storage_confined.descriptor_supported():
        pytest.skip("review preparation requires descriptor custody")


def _review_preflight(root, preparation):
    def walk(inspect):
        with ExitStack() as ancestors:
            parent = None
            for part in root.parts:
                parent = pathlookup_fence.open_directory(parent, part)
                ancestors.callback(os.close, parent)
            # The fixture is the repository boundary for this walk port.
            inspect(parent, len(root.parts))
            return os.dup(parent)

    with ExitStack() as stack:
        gitsafe_run.validate_review_preparation(root, preparation, stack, walk=walk,
            read_open=lambda name, parent: pathlookup_fence.open_leaf(parent, name))


def _reject_review_preflight(root, preparation):
    with pytest.raises(gitsafe.GitError) as caught:
        _review_preflight(root, preparation)
    assert (caught.value.code, str(caught.value)) == (
        "record_required", "invalid review preparation boundary")
    assert caught.value.process_started is False


def _output_directory(root, stdout):
    return (root / os.fsdecode(stdout.removesuffix(b"\n"))).resolve()


def _observe(api, root, admin, common, expected_tree):
    if api == "treeid":
        with treeid.bind(root) as bound:
            assert bound.gitdir == admin.resolve()
            assert bound.env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] == str(common.resolve() / "objects")
            assert bound.binding.status == "ok", bound.binding.reason
            assert bound.binding.tree == expected_tree
    elif api == "insights":
        canonical = common.resolve().as_posix() + "\x00."
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        assert keys.insight_workspace_id(root) == expected
    elif api == "hooks":
        assert hooks._find_git_dirs(root) == (admin.resolve(), common.resolve())
    else:
        assert _effect_layout(root).repository["dirs"] == (str(admin.resolve()), str(common.resolve()))


@pytest.mark.skipif(os.name == "nt", reason="Windows normalizes trailing whitespace in directory names")
@pytest.mark.parametrize("record", ["gitdir", "commondir"])
@pytest.mark.parametrize("absolute", [False, True])
@pytest.mark.parametrize("sibling", [False, True])
def test_record_paths_preserve_spaces_without_selecting_siblings(tmp_path, record, absolute, sibling):
    root, admin, common, _, _, expected = _layout(tmp_path, record,
        absolute=absolute, spaces=True, sibling=sibling)
    gate = Barrier(2, timeout=15)
    def observe(_):
        gate.wait()
        for api in ("treeid", "insights", "hooks"):
            _observe(api, root, admin, common, expected)
        return True
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(observe, range(2), timeout=30)) == [True, True]


@pytest.mark.parametrize("api", ["treeid", "insights"])
@pytest.mark.parametrize("record", ["gitdir", "commondir"])
@pytest.mark.parametrize("bad, code, message", [
    ("undecodable", "git_path_encoding", "Git path is not decodable."),
    ("nul", "git_path_record_invalid", "Git path record must contain one nonempty line."),
    ("oversize", "git_path_limit", "Git path output exceeds its byte limit."),
])
def test_bad_record_refuses_with_fixed_error_and_recovers(tmp_path, monkeypatch, api, record, bad, code, message):
    root, admin, common, selected, good, expected = _layout(tmp_path, record)
    if api == "treeid":
        # Git setup can refuse first; hold its external discovery answer fixed to
        # exercise the record parser and its public TreeError conversion.
        monkeypatch.setattr(treeid, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "toplevel": lambda *_: root}))
    prefix = b"gitdir: " if record == "gitdir" else b""
    payload = {"undecodable": b"private-\xff", "nul": b"private\0record", "oversize": b"x" * 65537}[bad]
    selected.write_bytes(prefix + payload + b"\n")
    error_type = treeid.TreeError if api == "treeid" else gitsafe.GitError
    for _ in range(2):
        with pytest.raises(error_type) as caught:
            _observe(api, root, admin, common, expected)
        assert (caught.value.code, str(caught.value)) == (code, message)
    selected.write_bytes(good)
    for _ in range(2):
        _observe(api, root, admin, common, expected)


@pytest.mark.parametrize(("api", "record"), [
    ("treeid", "gitdir"),
    ("treeid", "commondir"),
    ("insights", "gitdir"),
    ("insights", "commondir"),
    ("hooks", "gitdir"),
    ("effect", "gitdir"),
    ("effect", "commondir"),
])
@pytest.mark.parametrize("bad", ["multiline", "cr", "nul", "empty"])
def test_record_value_refuses_before_path_selection(tmp_path, monkeypatch, api, record, bad):
    if api == "effect" and not (gitops_fds.descriptor_supported() and storage_confined.descriptor_supported()):
        pytest.skip("effect discovery requires descriptor custody")
    root, admin, common, selected, good, expected = _layout(tmp_path, record)
    if api == "treeid":
        monkeypatch.setattr(treeid, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "toplevel": lambda *_: root}))
    base = root if record == "gitdir" else admin
    _git(base, "init", "-q", "--bare", str(base / "alternate"))
    value = {"multiline": b"fixture\n/../alternate", "cr": b"fixture\r/../alternate",
             "nul": b"alternate\0", "empty": b""}[bad]
    prefix = b"gitdir: " if record == "gitdir" else b""
    selected.write_bytes(prefix + value + b"\n")
    error = treeid.TreeError if api == "treeid" else gitsafe.GitError
    refusal = ("git_path_record_invalid", "Git path record must contain one nonempty line.")
    if api == "effect":
        refusal = ("effect_environment_unavailable", "Git operation effect roots unavailable.")
    def reject(_):
        with pytest.raises(error) as caught:
            _observe(api, root, admin, common, expected)
        assert (caught.value.code, str(caught.value)) == refusal
        if api == "effect":
            assert caught.value.process_started is False
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(reject, range(2), timeout=30))
    selected.write_bytes(good)
    for _ in range(2):
        _observe(api, root, admin, common, expected)


@pytest.mark.parametrize("api", ["treeid", "insights", "hooks", "effect", "review", "census"])
@pytest.mark.parametrize("record", ["gitdir", "commondir"])
@pytest.mark.parametrize("ending", [b"\r\n", b"\n\r\r\n"], ids=["crlf", "trailing-run"])
@pytest.mark.parametrize("sibling", [
    False, pytest.param(True, marks=pytest.mark.skipif(os.name == "nt",
        reason="Windows does not support CR in directory names")),
], ids=["plain", "with-cr-sibling"])
def test_record_framing_selects_the_same_directory_as_git(tmp_path, api, record, ending, sibling):
    _require_descriptor_api(api)
    root, admin, common, selected, good, expected_tree = _layout(tmp_path.resolve(), record, external=True)
    target = admin if record == "gitdir" else common
    decoy = target.with_name(target.name + "\r") if sibling else tmp_path / "other"
    _git(root, "init", "-q", "--bare", str(decoy))
    selected.write_bytes(good[:-1] + ending)
    git_admin = _output_directory(root, _git(root, "rev-parse", "--git-dir"))
    git_common = _output_directory(root, _git(root, "rev-parse", "--git-common-dir"))
    assert (git_admin, git_common) == (admin, common)

    if api == "review":
        expected_target = git_admin if record == "gitdir" else git_common
        inside, outside = expected_target / "private", decoy / "private"
        inside.mkdir(mode=0o700)
        outside.mkdir(mode=0o700)
        _reject_review_preflight(root, inside)
        _review_preflight(root, outside)
    elif api == "census":
        for flag, expected in (("--git-dir", git_admin), ("--git-common-dir", git_common)):
            actual = census_git(root, "rev-parse", flag).stdout
            assert _output_directory(root, actual) == expected
    else:
        _observe(api, root, git_admin, git_common, expected_tree)


@pytest.mark.parametrize(("api", "record"), [
    ("review", "gitdir"), ("review", "commondir"), ("census", "gitdir"),
])
@pytest.mark.parametrize("embedded", [b"\r", b"\n"], ids=["cr", "lf"])
def test_review_and_census_refuse_embedded_record_breaks(tmp_path, api, record, embedded):
    _require_descriptor_api(api)
    root, admin, _, selected, good, _ = _layout(tmp_path.resolve(), record)
    preparation = tmp_path.resolve() / "private"
    if api == "review":
        preparation.mkdir(mode=0o700)
    prefix = b"gitdir: " if record == "gitdir" else b""
    value = b"private" + embedded + b"-git"
    if os.name != "nt":
        parent = root if record == "gitdir" else admin
        _git(root, "init", "-q", "--bare", str(parent / os.fsdecode(value)))
    selected.write_bytes(prefix + value + b"\r\n")
    if api == "review":
        _reject_review_preflight(root, preparation)
    else:
        with pytest.raises(subprocess.CalledProcessError) as caught:
            census_git(root, "rev-parse", "--git-dir")
        assert (caught.value.returncode, caught.value.stdout, caught.value.stderr) == (128, b"", b"invalid Git marker\n")
    selected.write_bytes(good)
    if api == "review":
        _review_preflight(root, preparation)
    else:
        assert _output_directory(root, census_git(root, "rev-parse", "--git-dir").stdout) == admin


def test_review_preflight_refuses_when_descriptor_probe_is_false(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    preparation = tmp_path / "private"
    preparation.mkdir()
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    _reject_review_preflight(root, preparation)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not support CR in directory names")
def test_git_command_output_keeps_a_trailing_cr_in_the_name(tmp_path):
    admin = tmp_path / "admin\r"
    _git(tmp_path, "init", "-q", "--bare", str(admin))
    stdout = _git(tmp_path, "--git-dir=" + str(admin), "rev-parse", "--git-dir")
    assert stdout.endswith(b"\r\n")
    assert gitsafe_run.path_text(stdout) == str(admin)


@pytest.mark.parametrize("api", ["treeid", "insights", "hooks", "effect"])
def test_linked_worktree_accepts_one_line_parent_commondir(tmp_path, api):
    if api == "effect" and not (gitops_fds.descriptor_supported() and storage_confined.descriptor_supported()):
        pytest.skip("effect discovery requires descriptor custody")
    repo = tmp_path / "shared repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "commit", "--allow-empty", "-qm", "owner")
    expected_tree = _git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").removesuffix("\n")
    root = tmp_path / "linked"
    _git(repo, "worktree", "add", "--detach", str(root))
    (root / ".aegis").mkdir()
    common = repo / ".git"
    admin = common / "worktrees" / "linked"
    assert (admin / "commondir").read_bytes() == b"../..\n"
    _observe(api, root, admin, common, expected_tree)


@pytest.mark.parametrize("content", [b"not a gitfile\n", b"", b"\xff", b"bad\0marker", b"x" * 65537,
    b"gitdir:missing-space\n"], ids=["text", "empty", "encoding", "nul", "limit", "missing-space"])
def test_insight_non_gitfile_keeps_the_standalone_fallthrough(tmp_path, content):
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".git").write_bytes(content)
    expected = hashlib.sha256(tmp_path.resolve().as_posix().encode("utf-8")).hexdigest()[:16]
    assert keys.insight_workspace_id(tmp_path) == expected

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    odd = repo / "odd"
    nested = odd / "nested"
    nested.mkdir(parents=True)
    (odd / ".git").write_bytes(content)
    assert hooks._find_git_dirs(nested) == (repo.resolve() / ".git",) * 2
    expected = hashlib.sha256(nested.resolve().as_posix().encode("utf-8")).hexdigest()[:16]
    assert keys.insight_workspace_id(nested) == expected


@pytest.mark.parametrize("raw, gitfile, expected", [
    (None, False, None),
    (b"", False, ""),
    (b" leading \n", False, " leading "),
    (b"gitdir:  leading \n", True, " leading "),
    (b"trailing\n\n", False, "trailing\n"),
    (b"trailing\r\n", False, "trailing\r"),
])
def test_transport_path_decoder_preserves_shared_results(raw, gitfile, expected):
    from aegis_core import git_path_codec
    assert gitsafe_run.path_text(raw, gitfile=gitfile) == expected
    assert git_path_codec.path_text(raw, gitfile=gitfile) == expected


@pytest.mark.parametrize("raw, code, message", [
    (b"private-\xff", "git_path_encoding", "Git path is not decodable."),
    (b"private\0path", "git_path_invalid", "Git path framing is invalid."),
    (b"x" * 65537, "git_path_limit", "Git path output exceeds its byte limit."),
], ids=["encoding", "nul", "limit"])
def test_transport_path_decoder_preserves_fixed_refusals_and_recovers(raw, code, message):
    for _ in range(2):
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe_run.path_text(raw)
        assert (caught.value.code, str(caught.value)) == (code, message)
        assert gitsafe_run.path_text(b" repaired \n") == " repaired "


@pytest.mark.parametrize("record", [
    "directory",
    pytest.param("gitdir", marks=pytest.mark.skipif(os.name == "nt",
        reason="Windows normalizes trailing whitespace in directory names")),
    pytest.param("commondir", marks=pytest.mark.skipif(os.name == "nt",
        reason="Windows normalizes trailing whitespace in directory names")),
])
def test_hooks_load_codec_only_when_decoding_records(tmp_path, record):
    base = tmp_path.resolve()
    ordinary = base / "ordinary"
    (ordinary / ".git").mkdir(parents=True)
    (ordinary / ".aegis").mkdir()
    home = base / "home"
    home.mkdir()
    linked = base / "linked"
    linked.mkdir()
    admin = linked / " admin "
    common = admin / " common "
    if record != "directory":
        _git(linked, "init", "-q", "-b", "main", "--separate-git-dir", str(admin))
        (linked / ".git").write_bytes(b"gitdir:  admin \n")
        if record == "commondir":
            common.mkdir()
            for name in ("objects", "refs", "config"):
                (admin / name).rename(common / name)
            (admin / "commondir").write_bytes(b" common \n")
    script = """
import sys
from pathlib import Path
from aegis_core.workspace.hooks import _git_dirs_at
from aegis_core import treeid

root = Path(sys.argv[1])
assert "aegis_core.git_path_codec" not in sys.modules
import aegis_core.insights as insights
assert "aegis_core.git_path_codec" not in sys.modules
for prompt, excerpts in (("Please run the tests.", False),
                         ("No, stop breaking the build again.", True)):
    row = insights.record_hook_prompt("claude-code", {
        "prompt": prompt, "session_id": "s1", "cwd": str(root / "ordinary")},
        workspace=root / "ordinary", home=root / "home", excerpts=excerpts)
    if excerpts:
        assert row.get("event") == "insight", row
    assert "aegis_core.git_path_codec" not in sys.modules
for _ in range(2):
    dotgit = root / "ordinary" / ".git"
    assert _git_dirs_at(dotgit.parent) == (dotgit, dotgit)
    assert "aegis_core.git_path_codec" not in sys.modules
if sys.argv[2] != "directory":
    admin = root / "linked" / " admin "
    common = admin / " common " if sys.argv[2] == "commondir" else admin
    for _ in range(2):
        assert _git_dirs_at(root / "linked") == (admin, common)
        assert "aegis_core.git_path_codec" in sys.modules
"""
    child_env = {"HOME": str(home), "USERPROFILE": str(home),
        "PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / ".gitconfig")}
    proc = subprocess.run([sys.executable, "-c", script, str(base), record],
        capture_output=True, env=child_env, timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
