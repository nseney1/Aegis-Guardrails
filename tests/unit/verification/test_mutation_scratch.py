"""Mutation scratch placement and explicit Git layout boundaries."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture
def external_scratch_root():
    import tempfile

    with tempfile.TemporaryDirectory(prefix="rf-external-scratch-") as root:
        yield Path(root)


@contextmanager
def _git_environment(cwd=None):
    names = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES")
    saved = {name: os.environ.get(name) for name in names}
    previous_cwd = Path.cwd()
    try:
        for name in names[:3]:
            os.environ.pop(name, None)
        if cwd is not None:
            os.chdir(cwd)
        yield
    finally:
        if cwd is not None:
            os.chdir(previous_cwd)
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


_SCRATCH_INSIDE_DETAIL = "could not assess: mutation scratch root is not outside the checkout"
_INVALID_LAYOUT_DETAIL = (
    "could not assess: invalid explicit Git layout: "
    "GIT_DIR requires GIT_WORK_TREE; "
    "GIT_DIR, GIT_WORK_TREE and GIT_COMMON_DIR must name existing directories"
)
_BOUNDARY_DETAIL = (
    "could not assess: Git boundary could not be verified: "
    "confirm GIT_DIR and GIT_WORK_TREE describe one checkout"
)


def _unusable_layout_detail(layout: str) -> str:
    """A missing or non-directory component is an invalid layout; Git refusing it is not."""
    if layout == "unresolved" or "file-parent" in layout:
        return _INVALID_LAYOUT_DETAIL
    return _BOUNDARY_DETAIL


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("inside", [False, True], ids=["outside", "inside"])
def test_mutation_scratch_stays_outside_checkout(tmp_path, monkeypatch, suffix, inside, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    scratch = (checkout if inside else external_scratch_root) / "scratch"
    scratch.mkdir()
    target = checkout / "package" / ("target" + suffix)
    target.parent.mkdir()
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = checkout / "test_target.py"
    test.write_text(
        (f"import sys\nsys.path.insert(0, {str(target.parent)!r})\nfrom target import add\n"
         "def test_add():\n    assert add(2, 3) == 5\n") if suffix == ".py" else
        "def test_ok():\n    assert True\n", encoding="utf-8",
    )
    real_tempfile = mutation_tester.tempfile
    created = []

    def temporary_directory(**kwargs):
        kwargs.setdefault("dir", str(scratch))
        directory = real_tempfile.TemporaryDirectory(**kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=temporary_directory,
    ))
    # The external driver is a real boundary; no mutation-stage internals are patched.
    from aegis_core.ast.schema import MutationPoint
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
        if inside:
            assert result.verdict is False
            assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
            assert result.lines == [-1]
        else:
            assert "survived" in result.detail, result.detail
            assert result.verdict is (suffix == ".py"), result.detail
    if inside:
        assert created == []
        return
    assert len(created) == 2
    assert all(checkout.resolve() not in directory.resolve().parents for directory in created)
    assert all(REPO not in directory.resolve().parents for directory in created)
    assert all(not directory.exists() for directory in created)


@pytest.mark.parametrize("kind", ["missing", "file", "invalid", "permission"])
def test_invalid_mutation_root_refuses_before_allocation(tmp_path, monkeypatch, kind):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    target = tmp_path / "target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = tmp_path / "test_target.py"
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = tmp_path / "scratch"
    if kind == "file":
        candidate.write_text("regular file", encoding="utf-8")
    if kind == "invalid":
        candidate = "private\x00diagnostic"

    class RefusingPath(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            if self == candidate and kind == "permission":
                raise PermissionError("private diagnostic")
            return super().resolve(*args, **kwargs)

    def forbidden_allocation(**kwargs):
        pytest.fail("invalid root reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", RefusingPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    for _ in range(2):
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.detail == (
            "could not assess: mutation scratch root is not usable: "
            "choose an existing, accessible directory outside the checkout"
        )
        assert result.lines == [-1]


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("layout", ["root", "intermediate", "beside", "explicit"])
def test_target_checkout_scratch_refuses_independently_of_candidate(monkeypatch, suffix, layout):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-root-boundary-") as directory:
        checkout = Path(directory) / "checkout"
        package = checkout / "src" / "package"
        package.mkdir(parents=True)
        if layout == "explicit":
            metadata = Path(directory) / "metadata.git"
            subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True)
            os.environ["GIT_DIR"] = str(metadata)
            os.environ["GIT_WORK_TREE"] = str(checkout)
            assert not (checkout / ".git").exists()
        else:
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        assert REPO not in checkout.parents
        target = package / ("target" + suffix)
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test = package / "test_target.py"
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
        candidate = checkout / "scratch" if layout == "beside" else (
            checkout / "src" if layout == "intermediate" else checkout
        )
        candidate.mkdir(exist_ok=True)

        def forbidden_allocation(**kwargs):
            pytest.fail("target checkout reached scratch allocation")

        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
        ))
        point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
        runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
            assert result.verdict is False
            assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
            assert result.lines == [-1]


@pytest.mark.parametrize("inside", [False, True], ids=["sibling-control", "cwd-checkout"])
@pytest.mark.parametrize("boundary_owner", ["cwd", "tool"])
def test_cwd_and_tool_checkout_roots_are_scratch_boundaries(monkeypatch, inside, boundary_owner):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-cwd-boundary-") as directory:
        outer = Path(directory)
        checkout, target_checkout = outer / "cwd-checkout", outer / "target-checkout"
        subdir, package = checkout / "sub", target_checkout / "package"
        subdir.mkdir(parents=True)
        package.mkdir(parents=True)
        for repo in (checkout, target_checkout):
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
        os.environ["GIT_CEILING_DIRECTORIES"] = str(outer)
        target, test = package / "target.py", package / "test_target.py"
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test.write_text(f"import sys\nsys.path.insert(0, {str(package)!r})\nfrom target import add\n"
                        "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
        candidate = (checkout if inside else outer) / "scratch"
        candidate.mkdir()
        real_tempfile = mutation_tester.tempfile
        real_module_file = Path(mutation_tester.__file__)
        installed_module = checkout / "installed" / "aegis_core" / "verification" / "mutation_tester.py"
        installed_module.parent.mkdir(parents=True)
        installed_module.write_text("# fixture module location\n", encoding="utf-8")
        created = []

        class CwdPath(type(Path())):
            @classmethod
            def cwd(cls):
                return cls(subdir) if boundary_owner == "cwd" else super().cwd()

            def resolve(self, *args, **kwargs):
                if boundary_owner == "tool" and self == real_module_file:
                    return type(self)(installed_module)
                return super().resolve(*args, **kwargs)

        def allocate(**kwargs):
            if inside:
                pytest.fail("cwd checkout reached scratch allocation")
            manager = real_tempfile.TemporaryDirectory(**kwargs)
            created.append(Path(manager.name))
            return manager

        monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", CwdPath)
        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
        ))
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if inside:
                assert result.verdict is False
                assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
                assert result.lines == [-1]
            else:
                assert result.verdict is True, result.detail
        assert len(created) == (0 if inside else 2)
        assert all(not path.exists() for path in created)


def test_broken_git_marker_still_bounds_mutation_scratch(monkeypatch):
    import tempfile
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    with _git_environment(), tempfile.TemporaryDirectory(prefix="rf-broken-marker-") as directory:
        checkout = Path(directory) / "checkout"
        package = checkout / "package"
        package.mkdir(parents=True)
        symlink_or_skip("absent-metadata", checkout / ".git", target_is_directory=True)
        target, test = package / "target.py", package / "test_target.py"
        target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")

        def forbidden_allocation(**kwargs):
            pytest.fail("broken Git marker reached scratch allocation")

        monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
            gettempdir=lambda: str(checkout), TemporaryDirectory=forbidden_allocation,
        ))
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
        assert result.verdict is False
        assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
        assert result.lines == [-1]


def test_mutation_root_symlink_into_checkout_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").mkdir()
    target = checkout / "target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test = checkout / "test_target.py"
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    alias = tmp_path / "outside-alias"
    symlink_or_skip(checkout, alias, target_is_directory=True)

    def forbidden_allocation(**kwargs):
        pytest.fail("symlink into checkout reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(alias), TemporaryDirectory=forbidden_allocation,
    ))
    result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == "could not assess: mutation scratch root is not outside the checkout"
    assert result.lines == [-1]


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("invoked_from", ["other-checkout", "target-checkout"])
@pytest.mark.parametrize("layout", ["relative", "absolute", "unresolved", "common-relative",
                                  "parent-relative", "parent-absolute", "pointer-relative",
                                  "pointer-absolute", "pointer-file-parent-relative",
                                  "pointer-file-parent-absolute", "pointer-invalid-relative",
                                  "pointer-invalid-absolute"])
@pytest.mark.parametrize("external", [False, True], ids=["checkout-scratch", "external-scratch"])
def test_explicit_layout_keeps_invocation_paths(
    tmp_path, monkeypatch, suffix, invoked_from, layout, external, external_scratch_root,
):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = tmp_path / "B", tmp_path / "A", tmp_path / "metadata.git"
    pointer = layout.startswith("pointer-")
    unusable = layout == "unresolved" or layout.startswith(("pointer-file-parent-", "pointer-invalid-"))
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    command = ["git", "init", "-q", "--separate-git-dir", str(metadata), str(checkout)] if pointer else [
        "git", "init", "--bare", "-q", str(metadata),
    ]
    subprocess.run(command, check=True, timeout=30)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(
        (f"import sys\nsys.path.insert(0, {str(package)!r})\nfrom target import add\n"
         "def test_add():\n    assert add(2, 3) == 5\n") if suffix == ".py" else
        "def test_ok():\n    assert True\n", encoding="utf-8",
    )
    invocation = other if invoked_from == "other-checkout" else checkout

    real_tempfile = mutation_tester.tempfile
    allocated = []

    def allocate(**kwargs):
        if not external or unusable:
            pytest.fail("explicit checkout layout reached scratch allocation")
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    candidate = external_scratch_root / "scratch" if external or unusable else checkout
    candidate.mkdir(exist_ok=True)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(invocation):
        os.environ["GIT_DIR"] = str(metadata) if layout in ("absolute", "common-relative", "parent-absolute") else "../metadata.git"
        os.environ["GIT_WORK_TREE"] = str(checkout) if layout in ("absolute", "common-relative", "parent-absolute") else "../B"
        if layout == "unresolved":
            os.environ["GIT_DIR"] = "../missing.git"
        if layout == "common-relative":
            os.environ["GIT_COMMON_DIR"] = "../metadata.git"
        if pointer:
            path = str(checkout / ".git")
            assert Path(path).is_file()
            if "invalid" in layout:
                Path(path).write_text("private diagnostic\n", encoding="utf-8")
            if "file-parent" in layout:
                path += "/../.git"
            os.environ["GIT_DIR"] = path if layout.endswith("absolute") else os.path.relpath(checkout, invocation) + path[len(str(checkout)):]
            native = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=invocation,
                                    capture_output=True, timeout=30)
            assert (native.returncode != 0) is unusable
        if layout.startswith("parent-"):
            os.environ["GIT_COMMON_DIR"] = os.environ["GIT_DIR"]
            for root in (metadata, checkout):
                (root / "existing").mkdir()
            for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
                os.environ[name] += "/existing/.."
        before = {name: os.environ.get(name) for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")}
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
        if not external or unusable:
            assert result.verdict is False
            assert result.detail == (_unusable_layout_detail(layout) if unusable else _SCRATCH_INSIDE_DETAIL)
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert allocated == []
        else:
            assert "survived" in result.detail, result.detail
            assert result.verdict is (suffix == ".py"), result.detail
            assert len(allocated) == 1
            assert allocated[0].parent == candidate.resolve()
            assert not allocated[0].exists()
        assert {name: os.environ.get(name) for name in before} == before


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("shape", ["dots", "slashes", "trailing-dot", "parent"])
@pytest.mark.parametrize("long", [False, True], ids=["short", "long"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_explicit_layout_preserves_native_path_spelling(
    monkeypatch, external_scratch_root, name, shape, long, absolute,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    (metadata / "existing").mkdir()
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(f"import sys\nsys.path.insert(0, {str(checkout)!r})\nfrom target import add\n"
                    "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    suffix = {"dots": "/./", "slashes": "//", "trailing-dot": "/.", "parent": "/existing/.."}[shape]
    value = (str(metadata) if absolute else os.path.relpath(metadata, other)) + suffix * (
        4800 // len(suffix) if long else 1
    )
    assert len(value) <= 65536
    scratch = external_scratch_root / "scratch"
    scratch.mkdir()
    real_tempfile, allocated = mutation_tester.tempfile, []
    native_accepts = False

    def allocate(**kwargs):
        assert native_accepts, "native-refused Git layout reached scratch allocation"
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=allocate,
    ))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout), GIT_COMMON_DIR=str(metadata))
        os.environ[name] = value
        before = {key: os.environ[key] for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")}
        native = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, timeout=30)
        native_accepts = native.returncode == 0
        for _ in range(1 if native_accepts else 2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if native_accepts:
                assert result.verdict is True, result.detail
                assert "survived" in result.detail
                assert len(allocated) == 1
                assert allocated[0].parent == scratch.resolve()
                assert not allocated[0].exists()
            else:
                assert result.verdict is False
                assert result.detail == _BOUNDARY_DETAIL
                assert os.environ[name] not in result.detail
                assert result.lines == [-1]
                assert allocated == []
            assert {key: os.environ[key] for key in before} == before


@pytest.mark.parametrize("pointer_parent", ["declared", "canonical"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_git_pointer_file_symlink_preserves_declared_parent(
    monkeypatch, external_scratch_root, pointer_parent, absolute,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    pointer = external_scratch_root / "far" / "nested" / "gitfile"
    pointer.parent.mkdir(parents=True)
    relative = "../metadata.git" if pointer_parent == "declared" else "../../metadata.git"
    pointer.write_text("gitdir: " + relative + "\n", encoding="utf-8")
    alias = checkout / ".git"
    symlink_or_skip(pointer, alias)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text(f"import sys\nsys.path.insert(0, {str(checkout)!r})\nfrom target import add\n"
                    "def test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    scratch = external_scratch_root / "scratch"
    scratch.mkdir()
    real_tempfile, allocated = mutation_tester.tempfile, []
    native_accepts = False

    def allocate(**kwargs):
        assert native_accepts, "native-refused pointer layout reached scratch allocation"
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(scratch), TemporaryDirectory=allocate,
    ))
    with _git_environment(other):
        os.environ["GIT_DIR"] = str(alias) if absolute else os.path.relpath(alias, other)
        os.environ["GIT_WORK_TREE"] = str(checkout)
        before = {key: os.environ[key] for key in ("GIT_DIR", "GIT_WORK_TREE")}
        native = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, timeout=30)
        native_accepts = native.returncode == 0
        for _ in range(1 if native_accepts else 2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            if native_accepts:
                assert result.verdict is True, result.detail
                assert "survived" in result.detail
                assert len(allocated) == 1
                assert allocated[0].parent == scratch.resolve()
                assert not allocated[0].exists()
            else:
                assert result.verdict is False
                assert result.detail == _BOUNDARY_DETAIL
                assert result.lines == [-1]
                assert allocated == []
            assert {key: os.environ[key] for key in before} == before


@pytest.mark.parametrize("failure", ["exit", "error"])
def test_original_layout_git_probe_refuses_before_allocation(monkeypatch, external_scratch_root, failure):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    checkout, other, metadata = (external_scratch_root / part for part in ("B", "A", "metadata.git"))
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    calls = []

    def refuse(*args, **kwargs):
        calls.append(True)
        if failure == "error":
            raise AegisError("private diagnostic")
        return subprocess.CompletedProcess([], 128, b"", b"private diagnostic")

    def forbidden_allocation(**kwargs):
        raise AssertionError("failed original-layout probe reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "run": refuse},
    ))
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(external_scratch_root), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout))
        for attempt in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _BOUNDARY_DETAIL
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert len(calls) == attempt + 1


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("invalid", ["empty", "missing-parent", "file-parent"])
@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
@pytest.mark.parametrize("inside", [False, True], ids=["outside-cwd", "inside-cwd"])
@pytest.mark.parametrize("suffix", [".py", ".rs"])
def test_explicit_layout_is_validated_as_given(
    monkeypatch, external_scratch_root, name, invalid, absolute, inside, suffix,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata = external_scratch_root / "metadata.git"
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    for root in (checkout, other):
        subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    invocation = checkout / "src" if inside else other
    valid = {"GIT_DIR": metadata, "GIT_WORK_TREE": checkout / "src", "GIT_COMMON_DIR": metadata}
    base = valid[name]
    if invalid == "file-parent":
        (base / "blocked").write_text("regular file\n", encoding="utf-8")
    tail = "blocked/.." if invalid == "file-parent" else "missing/.."
    value = str(base / tail) if absolute else os.path.relpath(base, invocation) + "/" + tail
    if invalid == "empty":
        value = ""

    def forbidden_allocation(**kwargs):
        raise AssertionError("invalid original Git layout reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(checkout), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(invocation):
        os.environ.update({key: str(path) for key, path in valid.items()})
        os.environ[name] = value
        before = {key: os.environ[key] for key in valid}
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _INVALID_LAYOUT_DETAIL
            assert not value or value not in result.detail
            assert result.lines == [-1]
            assert {key: os.environ[key] for key in valid} == before


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("aliased", [False, True], ids=["physical-temp", "symlinked-temp"])
def test_explicit_layout_component_rename_refuses_and_can_be_retried(
    monkeypatch, external_scratch_root, name, aliased,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester
    from tests.conftest import symlink_or_skip

    if aliased:
        physical = external_scratch_root / "physical"
        physical.mkdir()
        alias = external_scratch_root / "alias"
        symlink_or_skip(physical, alias, target_is_directory=True)
        external_scratch_root = alias

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata = external_scratch_root / "metadata.git"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True, timeout=30)
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    target, test = checkout / "target.py", checkout / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    valid = {"GIT_DIR": metadata, "GIT_WORK_TREE": checkout, "GIT_COMMON_DIR": metadata}
    component = valid[name] / "existing"
    component.mkdir()
    canonical = component.resolve()
    moved = component.with_name("moved")
    renamed = []

    class ConcurrentPath(type(checkout)):
        def resolve(self, *args, **kwargs):
            result = super().resolve(*args, **kwargs)
            if result == canonical and not renamed:
                component.rename(moved)
                renamed.append(True)
            return result

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", ConcurrentPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(external_scratch_root),
        TemporaryDirectory=lambda **kwargs: pytest.fail("layout probe reached allocation"),
    ))
    with _git_environment(other):
        os.environ.update({key: str(path) for key, path in valid.items()})
        os.environ[name] = str(component / "..")
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=0)
        assert result.verdict is False
        assert result.detail == _INVALID_LAYOUT_DETAIL
        assert result.lines == [-1]
        assert renamed == [True]
        assert not component.exists() and moved.is_dir()
        moved.rename(component)
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=0)
            assert result.verdict is True
            assert result.detail == "0/0 survived (no mutations to apply)"


@pytest.mark.parametrize("suffix", [".py", ".rs"])
@pytest.mark.parametrize("candidate_at", ["root", "intermediate", "beside"])
@pytest.mark.parametrize("layout", ["missing", "file", "disjoint", "implicit", "valid"])
def test_explicit_worktree_must_be_established_before_allocation(
    monkeypatch, external_scratch_root, suffix, candidate_at, layout,
):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    package = checkout / "src" / "package"
    package.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / ("target" + suffix), package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    worktree = external_scratch_root / "unresolved-worktree"
    if layout == "valid":
        worktree = checkout
    elif layout == "file":
        worktree.write_text("regular file\n", encoding="utf-8")
    elif layout == "disjoint":
        worktree.mkdir()
    candidate = checkout if candidate_at == "root" else (
        checkout / "src" if candidate_at == "intermediate" else checkout / "scratch"
    )
    candidate.mkdir(exist_ok=True)

    def forbidden_allocation(**kwargs):
        pytest.fail("unestablished explicit worktree reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(other):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = "../metadata-owner/.git"
        if layout != "implicit":
            os.environ["GIT_WORK_TREE"] = "../" + worktree.name
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
    if layout == "valid":
        expected = _SCRATCH_INSIDE_DETAIL
    elif layout == "disjoint":
        expected = _BOUNDARY_DETAIL
    else:
        expected = _INVALID_LAYOUT_DETAIL
    assert result.verdict is False
    assert result.detail == expected
    assert result.lines == [-1]


@pytest.mark.parametrize("boundary_owner", ["cwd", "tool"])
def test_explicit_layout_cannot_invent_a_disjoint_context_boundary(
    monkeypatch, external_scratch_root, boundary_owner,
):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    context = external_scratch_root / "C" / "sub"
    package = checkout / "package"
    package.mkdir(parents=True)
    context.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / "target.py", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    if boundary_owner == "tool":
        installed = context / "aegis_core" / "verification" / "mutation_tester.py"
        installed.parent.mkdir(parents=True)
        installed.write_text("# fixture module location\n", encoding="utf-8")
        monkeypatch.setattr("aegis_core.verification.mutation_tester.__file__", str(installed))
    invocation = context if boundary_owner == "cwd" else other

    def forbidden_allocation(**kwargs):
        pytest.fail("disjoint context fallback reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(context.parent), TemporaryDirectory=forbidden_allocation,
    ))
    with _git_environment(invocation):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = os.path.relpath(metadata_owner / ".git", invocation)
        os.environ["GIT_WORK_TREE"] = os.path.relpath(checkout, invocation)
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert result.lines == [-1]


def test_explicit_worktree_must_match_reported_toplevel(monkeypatch, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    metadata_owner = external_scratch_root / "metadata-owner"
    package = checkout / "package"
    package.mkdir(parents=True)
    for root in (other, metadata_owner):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    target, test = package / "target.py", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = external_scratch_root / "external-scratch"
    candidate.mkdir()

    def forbidden_allocation(**kwargs):
        pytest.fail("mismatched native toplevel reached scratch allocation")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=forbidden_allocation,
    ))
    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "toplevel": lambda _: other},
    ))
    with _git_environment(other):
        os.environ["GIT_CEILING_DIRECTORIES"] = str(external_scratch_root)
        os.environ["GIT_DIR"] = "../metadata-owner/.git"
        os.environ["GIT_WORK_TREE"] = "../B"
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert result.lines == [-1]


@pytest.mark.parametrize("name", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"])
@pytest.mark.parametrize("malformed", ["oversized", "nul", "expanded"])
def test_git_layout_limits_refuse_before_path_or_runner(tmp_path, monkeypatch, name, malformed):
    from types import SimpleNamespace
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    value = "private\x00diagnostic" if malformed == "nul" else "x" * (65537 if malformed == "oversized" else 65536)

    class BoundedPath(type(tmp_path)):
        def __truediv__(self, part):
            if malformed != "expanded" and part == value:
                pytest.fail("invalid Git layout reached path parsing")
            return super().__truediv__(part)

    def forbidden_runner(**kwargs):
        pytest.fail("invalid Git layout reached the runner")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.Path", BoundedPath)
    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": forbidden_runner},
    ))
    # Model the OS boundary without putenv rejecting malformed/oversized values
    # first (Windows also bounds individual environment values).
    monkeypatch.setattr("aegis_core.verification.mutation_tester.os", SimpleNamespace(
        **{**vars(os), "environ": {name: value}},
    ))
    result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _INVALID_LAYOUT_DETAIL
    assert value not in result.detail
    assert result.lines == [-1]


def test_nonexistent_git_dir_refuses_before_custody(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    calls = []

    def refused_runner(**kwargs):
        calls.append(kwargs)
        raise AegisError("private diagnostic")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": refused_runner},
    ))
    with _git_environment():
        os.environ["GIT_DIR"] = str(tmp_path / "missing.git")
        os.environ["GIT_WORK_TREE"] = str(tmp_path)
        for _ in range(2):
            result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
            assert result.verdict is False
            assert result.detail == _INVALID_LAYOUT_DETAIL
            assert "private diagnostic" not in result.detail
            assert result.lines == [-1]
            assert calls == []


def test_git_runner_policy_refusal_has_fixed_public_message(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from aegis_core.errors import AegisError
    from aegis_core.verification import mutation_tester

    target, test = tmp_path / "target.py", tmp_path / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    metadata = tmp_path / "metadata.git"
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True, timeout=30)
    calls = []

    def refused_runner(**kwargs):
        calls.append(kwargs)
        raise AegisError("private diagnostic")

    monkeypatch.setattr("aegis_core.verification.mutation_tester.gitsafe", SimpleNamespace(
        **{**vars(mutation_tester.gitsafe), "custody": refused_runner},
    ))
    with _git_environment():
        os.environ["GIT_DIR"] = str(metadata)
        os.environ["GIT_WORK_TREE"] = str(tmp_path)
        native = subprocess.run(
            ["git", "-C", str(tmp_path), "rev-parse", "--show-toplevel"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        assert Path(native.stdout.strip()).resolve() == tmp_path.resolve()
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1)
    assert result.verdict is False
    assert result.detail == _BOUNDARY_DETAIL
    assert "private diagnostic" not in result.detail
    assert result.lines == [-1]
    assert len(calls) == 1


def test_explicit_layout_preserves_closest_marker_boundary(monkeypatch, external_scratch_root):
    from types import SimpleNamespace
    from aegis_core.ast.schema import MutationPoint
    from aegis_core.verification import mutation_tester

    checkout, other = external_scratch_root / "B", external_scratch_root / "A"
    nested = checkout / "nested"
    package = nested / "package"
    package.mkdir(parents=True)
    for root in (other, nested):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
    metadata = external_scratch_root / "metadata.git"
    subprocess.run(["git", "init", "--bare", "-q", str(metadata)], check=True)
    target, test = package / "target.rs", package / "test_target.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    test.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    candidate = checkout / "scratch"
    candidate.mkdir()
    monkeypatch.setattr("aegis_core.verification.mutation_tester.__file__",
                        str(other / "aegis_core" / "verification" / "mutation_tester.py"))
    real_tempfile = mutation_tester.tempfile
    allocated = []

    def allocate(**kwargs):
        manager = real_tempfile.TemporaryDirectory(**kwargs)
        allocated.append(Path(manager.name))
        return manager

    monkeypatch.setattr("aegis_core.verification.mutation_tester.tempfile", SimpleNamespace(
        gettempdir=lambda: str(candidate), TemporaryDirectory=allocate,
    ))
    point = MutationPoint(line=2, col=0, original_op="+", replacement_op="-")
    runner = SimpleNamespace(parse_file=lambda _: SimpleNamespace(mutation_points=[point]))
    with _git_environment(other):
        os.environ.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(checkout))
        result = mutation_tester.check(str(target), "add", str(test), max_mutations=1, ast_runner=runner)
    assert "survived" in result.detail, result.detail
    assert len(allocated) == 1
    assert allocated[0].parent == candidate.resolve()
    assert not allocated[0].exists()


