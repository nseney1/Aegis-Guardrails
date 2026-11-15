"""What bounds a mutation run's pytest: its rootdir/confcutdir and the sys.path it inherits (R-checks-59).

Pure path logic on tmp paths, so it runs on every OS; the temp root is tmp_path/"tmp" through
a patched tempfile.gettempdir, with a pyproject.toml above it the walk must never reach.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import aegis_core.workspace.binding as git_binding

from aegis_core.verification import mutation_tester
from tests.helpers_popen import install_fake_popen


@pytest.fixture
def temp_root(tmp_path, monkeypatch) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(root))
    return root


def _file(path: Path, text: str = "def test_ok():\n    assert True\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _same(a: object, b: Path) -> bool:
    return a is not None and os.path.samefile(str(a), str(b))


def test_a_config_marker_wins_over_a_nearer_conftest(temp_root):
    _file(temp_root / "proj" / "setup.cfg", "")
    _file(temp_root / "proj" / "tests" / "conftest.py", "")
    test = _file(temp_root / "proj" / "tests" / "unit" / "test_a.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(test)]), temp_root / "proj")


def test_without_a_marker_the_nearest_conftest_directory_is_the_root(temp_root):
    _file(temp_root / "proj" / "conftest.py", "")
    _file(temp_root / "proj" / "tests" / "conftest.py", "")
    test = _file(temp_root / "proj" / "tests" / "unit" / "test_a.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(test)]), temp_root / "proj" / "tests")


def test_with_neither_the_common_test_directory_is_the_root_and_the_walk_stops_at_the_temp_root(temp_root):
    one = _file(temp_root / "proj" / "tests" / "a" / "test_a.py")
    two = _file(temp_root / "proj" / "tests" / "b" / "test_b.py")
    assert _same(mutation_tester._resolve_test_rootdir([str(one), str(two)]), temp_root / "proj" / "tests")


def test_a_missing_test_file_has_no_root(temp_root):
    assert mutation_tester._resolve_test_rootdir([str(temp_root / "nowhere" / "test_x.py"), ""]) is None


def test_a_temp_path_entry_is_dropped_unless_it_holds_a_test_file(temp_root, tmp_path):
    test = _file(temp_root / "proj" / "tests" / "test_a.py")
    holder = temp_root / "proj"
    stray = temp_root / "other"
    stray.mkdir()
    outside = tmp_path / "site"
    outside.mkdir()
    missing = tmp_path / "gone"
    entries = ["", str(stray), str(holder), str(outside), str(missing)]
    assert mutation_tester._filter_sys_path(entries, [str(test)], str(temp_root)) == [str(holder), str(outside)]


def test_with_no_test_file_every_temp_entry_is_dropped(temp_root, tmp_path):
    inside = temp_root / "proj"
    inside.mkdir()
    assert mutation_tester._filter_sys_path([str(inside), str(tmp_path)], [], str(temp_root)) == [str(tmp_path)]


@pytest.mark.parametrize("exists", [True, False], ids=["root", "no-root"])
def test_the_pytest_command_is_bounded_only_when_a_root_is_found(temp_root, monkeypatch, exists):
    _file(temp_root / "proj" / "pyproject.toml", "")
    test = temp_root / "proj" / "tests" / "test_a.py"
    if exists:
        _file(test)
    spawns = install_fake_popen(monkeypatch)
    with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
        mutation_tester._check_tests([str(test)], timeout=60)
    (spawn,) = spawns
    bounds = [a for a in spawn["args"] if a.startswith(("--rootdir=", "--confcutdir="))]
    if exists:
        assert [a.split("=", 1)[0] for a in bounds] == ["--rootdir", "--confcutdir"]
        assert all(_same(a.split("=", 1)[1], temp_root / "proj") for a in bounds)
    else:
        assert bounds == []


# Public check() names the Git-layout failure. Allocation stays forbidden, and a
# secret-looking GIT_* value or raw OS/Git text never appears in the detail.
_SECRET = "SECRET-GIT-LAYOUT-VALUE"
_INSIDE_DETAIL = "could not assess: mutation scratch root is not outside the checkout"
_UNUSABLE_DETAIL = (
    "could not assess: mutation scratch root is not usable: "
    "choose an existing, accessible directory outside the checkout"
)
_INVALID_DETAIL = (
    "could not assess: invalid explicit Git layout: "
    "GIT_DIR requires GIT_WORK_TREE; "
    "GIT_DIR, GIT_WORK_TREE and GIT_COMMON_DIR must name existing directories"
)
_BOUNDARY_DETAIL = (
    "could not assess: Git boundary could not be verified: "
    "confirm GIT_DIR and GIT_WORK_TREE describe one checkout"
)
_LAYOUT_CASES = {
    "bad-empty": _INVALID_DETAIL,
    "bad-nul": _INVALID_DETAIL,
    "bad-oversized": _INVALID_DETAIL,
    "bad-expanded": _INVALID_DETAIL,
    "newline-component": _INVALID_DETAIL,
    "dir-without-worktree": _INVALID_DETAIL,
    "missing-component": _INVALID_DETAIL,
    "git-refuses": _BOUNDARY_DETAIL,
    "toplevel-mismatch": _BOUNDARY_DETAIL,
    "os-error": _BOUNDARY_DETAIL,
    "containment": _INSIDE_DETAIL,
}


def _layout_pair(root: Path) -> tuple[Path, Path]:
    target = root / "pkg" / "target.py"
    target.parent.mkdir(parents=True)
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = target.parent / "test_target.py"
    test.write_text("def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    return target, test


def _install_layout(monkeypatch, layout: dict) -> None:
    """Publish one layout mapping on every module this check reads.

    Windows putenv rejects NUL and oversized values, so the mapping replaces
    the imported ``os`` binding. Discovery reads its own module global.
    """
    fake = SimpleNamespace(**{**vars(os), "environ": dict(layout)})
    monkeypatch.setattr(mutation_tester, "os", fake)
    monkeypatch.setattr(git_binding, "os", fake)


@pytest.mark.parametrize("case", list(_LAYOUT_CASES))
def test_check_names_the_git_layout_failure_category(tmp_path, monkeypatch, case):
    """Each refusal category is exact, stable on retry, and allocated nothing.

    Bad GIT_* values are rejected before path parsing or the Git runner. Other
    layout failures still parse the declared paths, and every refusal returns
    before scratch allocation.
    """
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    metadata = tmp_path / "metadata.git"
    metadata.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    if case == "containment":
        target, test = _layout_pair(checkout)
        candidate = checkout / _SECRET
    else:
        target, test = _layout_pair(work)
        candidate = tmp_path / "scratch"
    candidate.mkdir()
    events = []
    secret_value = _SECRET
    layout: dict = {}

    class RecordingPath(type(tmp_path)):
        def __truediv__(self, part):
            events.append(("parse", part))
            return super().__truediv__(part)

    def forbid_allocation(**kwargs):
        events.append(("allocate", kwargs.get("dir")))
        raise AssertionError("refused layout reached scratch allocation")

    monkeypatch.setattr(mutation_tester, "Path", RecordingPath)
    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbid_allocation,
    ))
    if case == "bad-empty":
        secret_value = ""
    elif case == "bad-nul":
        secret_value = _SECRET + "\x00hidden"
    elif case == "bad-oversized":
        secret_value = _SECRET + ("x" * 65537)
    elif case == "bad-expanded":
        secret_value = _SECRET + ("y" * (65536 - len(_SECRET)))
        assert len(secret_value) == 65536 and "\n" not in secret_value and "\x00" not in secret_value
    elif case == "dir-without-worktree":
        secret_value = str(metadata / _SECRET)
        (metadata / _SECRET).mkdir()
    elif case == "missing-component":
        secret_value = str(tmp_path / _SECRET)
    elif case == "newline-component":
        # A newline is a path character. The component does not exist, so the
        # value is parsed and refused as an invalid layout. It is not rejected
        # before Path sees it.
        secret_value = _SECRET + "\njoined-line"
    if case.startswith("bad-") or case in ("dir-without-worktree", "newline-component"):
        layout = {"GIT_DIR": secret_value}
    elif case == "missing-component":
        layout = {"GIT_DIR": secret_value, "GIT_WORK_TREE": str(work)}
    elif case in ("git-refuses", "toplevel-mismatch", "os-error"):
        layout = {"GIT_DIR": str(metadata), "GIT_WORK_TREE": str(work)}

    real_gitsafe = mutation_tester.gitsafe

    def custody(**kwargs):
        events.append(("custody", True))
        if case.startswith("bad-"):
            raise AssertionError("invalid Git value reached the runner")
        return real_gitsafe.custody(**kwargs)

    def run(args, cwd, *unused, **kwargs):
        events.append(("git", tuple(args)))
        if case == "os-error":
            raise OSError(secret_value)
        if case == "git-refuses":
            return subprocess.CompletedProcess(list(args), 128, b"", secret_value.encode())
        if case == "toplevel-mismatch":
            return subprocess.CompletedProcess(list(args), 0, b"", b"")
        return real_gitsafe.run(args, cwd, *unused, **kwargs)

    def toplevel(start):
        events.append(("toplevel", str(start)))
        if case == "toplevel-mismatch":
            return other
        return real_gitsafe.toplevel(start)

    monkeypatch.setattr(mutation_tester, "gitsafe", SimpleNamespace(
        **{**vars(real_gitsafe), "custody": custody, "run": run, "toplevel": toplevel},
    ))
    _install_layout(monkeypatch, layout)
    seen = []
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.lines == [-1]
        assert result.detail == _LAYOUT_CASES[case]
        assert "\n" not in result.detail and "\r" not in result.detail
        if secret_value:
            assert secret_value not in result.detail
        assert _SECRET not in result.detail
        seen.append(result.detail)
    assert seen[0] == seen[1]
    assert not [event for event in events if event[0] == "allocate"]
    if case.startswith("bad-"):
        assert not [event for event in events if event[0] in ("parse", "custody", "git")]
    if case in ("dir-without-worktree", "missing-component", "newline-component"):
        assert any(event[0] == "parse" for event in events)
        assert not [event for event in events if event[0] in ("custody", "git", "allocate")]
    if case in ("git-refuses", "os-error", "toplevel-mismatch"):
        assert [event[0] for event in events].index("parse") < [event[0] for event in events].index("git")


def test_invalid_layout_refusal_is_stable_across_overlapping_calls(tmp_path, monkeypatch):
    """Overlapping callers each get the same fixed refusal and allocate nothing."""
    target, test = _layout_pair(tmp_path)
    secret = str(tmp_path / _SECRET)
    _install_layout(monkeypatch, {"GIT_DIR": secret, "GIT_WORK_TREE": str(tmp_path)})
    allocated = []

    def forbid_allocation(**kwargs):
        allocated.append(kwargs)
        raise AssertionError("overlapping refusal reached scratch allocation")

    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(tmp_path), TemporaryDirectory=forbid_allocation,
    ))
    barrier = threading.Barrier(4)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=0)
            results.append((result.verdict, result.detail, tuple(result.lines)))
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    assert errors == []
    assert results == [(False, _INVALID_DETAIL, (-1,))] * 4
    assert allocated == []
    assert _SECRET not in results[0][1]


def _assert_stable_refusal(monkeypatch, target, test, candidate, detail):
    """Two public checks, the same fixed sentence, and no scratch allocation."""
    allocated = []

    def forbid_allocation(**kwargs):
        allocated.append(kwargs)
        raise AssertionError("boundary refusal reached scratch allocation")

    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbid_allocation,
    ))
    _install_layout(monkeypatch, {})
    seen = []
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.lines == [-1]
        assert result.detail == detail
        assert "\n" not in result.detail and "\r" not in result.detail
        assert _SECRET not in result.detail
        seen.append(result.detail)
    assert seen[0] == seen[1]
    assert allocated == []


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("case", ["missing", "file", "nul", "permission", "os-error", "unresolved-key"])
def test_unusable_scratch_names_the_failed_check(tmp_path, monkeypatch, case, suffix):
    """Candidate failures refuse on retry before allocation, without echoing input."""
    class NoOverwritePath(type(tmp_path)):
        def rename(self, destination):
            # Exercise Windows' existing-destination refusal on every platform.
            if Path(destination).exists():
                raise FileExistsError("rename destination already exists")
            return super().rename(destination)

    target, test = _layout_pair(tmp_path / "work")
    target = NoOverwritePath(target)
    if target.suffix != suffix:
        target = target.rename(target.with_suffix(suffix))
    candidate = tmp_path / _SECRET
    if case == "file":
        candidate.write_text("regular file", encoding="utf-8")
    elif case == "nul":
        candidate = _SECRET + "\x00hidden\nline"
    elif case != "missing":
        candidate.mkdir()

    class RefusingPath(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            if os.fspath(self) == str(candidate):
                if case == "permission":
                    raise PermissionError(_SECRET + "\nprivate diagnostic")
                if case == "os-error":
                    raise OSError(_SECRET + "\nprivate diagnostic")
            return super().resolve(*args, **kwargs)

    original_key = mutation_tester.real_key

    def candidate_key(path):
        if case == "unresolved-key" and os.fspath(path) == str(candidate):
            return None
        return original_key(path)

    monkeypatch.setattr(mutation_tester, "Path", RefusingPath)
    monkeypatch.setattr(mutation_tester, "real_key", candidate_key)
    _assert_stable_refusal(monkeypatch, target, test, candidate, _UNUSABLE_DETAIL)


def test_scratch_removed_during_overlapping_checks_is_unusable(tmp_path, monkeypatch):
    """Concurrent checks refuse a candidate removed just before strict resolution."""
    target, test = _layout_pair(tmp_path / "work")
    candidate = tmp_path / _SECRET
    candidate.mkdir()
    barrier = threading.Barrier(4, action=candidate.rmdir)
    allocated, results, errors = [], [], []

    class RemovedPath(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            if self == candidate and kwargs.get("strict"):
                barrier.wait(timeout=5)
            return super().resolve(*args, **kwargs)

    def forbid_allocation(**kwargs):
        allocated.append(kwargs)
        raise AssertionError("removed scratch reached allocation")

    def worker():
        try:
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            results.append((result.verdict, result.detail, tuple(result.lines)))
        except Exception as exc:
            errors.append(repr(exc))

    monkeypatch.setattr(mutation_tester, "Path", RemovedPath)
    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbid_allocation,
    ))
    _install_layout(monkeypatch, {})
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    assert errors == []
    assert results == [(False, _UNUSABLE_DETAIL, (-1,))] * 4
    assert allocated == []
    assert not candidate.exists()


def test_removed_cwd_is_an_unverified_boundary(tmp_path, monkeypatch):
    """A deleted invocation directory is not containment. cwd stays process-wide."""
    work = tmp_path / "work"
    target, test = _layout_pair(work)
    candidate = tmp_path / "scratch"
    candidate.mkdir()

    class MissingCwd(type(tmp_path)):
        @classmethod
        def cwd(cls):
            raise FileNotFoundError(_SECRET)

    monkeypatch.setattr(mutation_tester, "Path", MissingCwd)
    _assert_stable_refusal(monkeypatch, target, test, candidate, _BOUNDARY_DETAIL)


def test_unresolved_checkout_key_is_an_unverified_boundary(tmp_path, monkeypatch):
    """No resolved checkout contains scratch, and a checkout key does not resolve."""
    checkout = tmp_path / "checkout"
    target, test = _layout_pair(checkout)
    (checkout / ".git").mkdir()
    candidate = tmp_path / "scratch"
    candidate.mkdir()
    original = mutation_tester.real_key

    def hide_checkouts(path):
        try:
            if os.path.samefile(os.fspath(path), os.fspath(candidate)):
                return original(path)
        except OSError:
            return None
        return None

    monkeypatch.setattr(mutation_tester, "real_key", hide_checkouts)
    _assert_stable_refusal(monkeypatch, target, test, candidate, _BOUNDARY_DETAIL)


def test_containment_wins_when_another_checkout_key_is_unresolved(tmp_path, monkeypatch):
    """One resolved checkout contains scratch, so an unresolved sibling key stays inside."""
    checkout = tmp_path / "checkout"
    target, test = _layout_pair(checkout)
    (checkout / ".git").mkdir()
    candidate = target.parent / _SECRET
    candidate.mkdir()
    tool = Path(mutation_tester.__file__).resolve().parents[2]
    original = mutation_tester.real_key

    def hide_tool_checkout(path):
        try:
            if os.path.samefile(os.fspath(path), os.fspath(tool)):
                return None
        except OSError:
            return original(path)
        return original(path)

    monkeypatch.setattr(mutation_tester, "real_key", hide_tool_checkout)
    _assert_stable_refusal(monkeypatch, target, test, candidate, _INSIDE_DETAIL)


def test_newline_metadata_directory_passes_the_scratch_gate(tmp_path, monkeypatch):
    """An existing metadata directory whose name contains a newline is a supported layout."""
    probe = tmp_path / "name\nprobe"
    try:
        probe.mkdir()
    except OSError:
        pytest.skip("this platform cannot name a directory with a newline")
    probe.rmdir()
    metadata = tmp_path / "meta\ndata.git"
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(
        ["git", "init", "-q", "--separate-git-dir", str(metadata), str(work)],
        check=True, timeout=30,
    )
    target, test = _layout_pair(work)
    test.write_text(
        f"import sys\nsys.path.insert(0, {str(target.parent)!r})\nfrom target import add\n"
        "def test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    candidate = tmp_path / "scratch"
    candidate.mkdir()
    allocated = []
    real_tempfile = mutation_tester.tempfile

    def allocate(**kwargs):
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
    ))
    _install_layout(monkeypatch, {"GIT_DIR": str(metadata), "GIT_WORK_TREE": str(work)})
    result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.detail not in (_INSIDE_DETAIL, _INVALID_DETAIL, _BOUNDARY_DETAIL)
    assert "survived" in result.detail
    assert _SECRET not in result.detail
    assert str(metadata) not in result.detail
    assert "\n" not in result.detail
    assert allocated
    assert allocated[0].parent == candidate.resolve()


def test_windows_invalid_name_is_an_invalid_layout(tmp_path, monkeypatch):
    """WinError 123 is a missing component, including where a newline cannot be a name."""
    work = tmp_path / "work"
    target, test = _layout_pair(work)
    candidate = tmp_path / "scratch"
    candidate.mkdir()
    events = []
    secret = _SECRET + "\njoined-line"

    class InvalidName(type(tmp_path)):
        def __truediv__(self, part):
            events.append(("parse", part))
            return super().__truediv__(part)

        def resolve(self, *args, **kwargs):
            if "\n" in os.fspath(self):
                error = OSError(secret)
                error.winerror = 123
                raise error
            return super().resolve(*args, **kwargs)

    def forbid_allocation(**kwargs):
        events.append(("allocate", kwargs.get("dir")))
        raise AssertionError("invalid name reached scratch allocation")

    monkeypatch.setattr(mutation_tester, "Path", InvalidName)
    monkeypatch.setattr(mutation_tester, "tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbid_allocation,
    ))
    _install_layout(monkeypatch, {"GIT_DIR": secret})
    seen = []
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.lines == [-1]
        assert result.detail == _INVALID_DETAIL
        assert "\n" not in result.detail and secret not in result.detail
        assert _SECRET not in result.detail
        seen.append(result.detail)
    assert seen[0] == seen[1]
    assert any(event[0] == "parse" for event in events)
    assert not [event for event in events if event[0] == "allocate"]
