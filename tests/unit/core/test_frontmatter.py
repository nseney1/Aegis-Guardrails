"""Rule path readers refuse unsafe inputs before reading or parsing them."""
from __future__ import annotations

from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import errno
import json
import os
from pathlib import Path
import signal
import sys
from threading import local
from types import SimpleNamespace

import pytest

from aegis_core.errors import PathTraversalError, RuleNotFoundError, RuleParseError
from aegis_core.rule_inventory import MAX_RULE_BYTES, MAX_RULE_PATH_CHARS
from aegis_core.workspace.base import Workspace
from aegis_core.yaml_engine import frontmatter
from aegis_core.yaml_engine.frontmatter import (
    AegisYAML, RuleReadError, parse_rule_file, parse_rule_frontmatter,
)
from aegis_core.yaml_engine.parser import AegisYAMLError
from tests.conftest import symlink_or_skip
from aegis_core import rule_inventory


TEXT = "---\nid: bounded\n---\nbody\n"
SIZE_ADVICE = f"Rule file exceeds the {MAX_RULE_BYTES}-byte size limit"
ENTRIES = ("parse_rule_frontmatter", "parse_rule_file", "AegisYAML.parse_file")


def read_rule(entry, path, root):
    if entry == "AegisYAML.parse_file":
        document = AegisYAML.parse_file(path.relative_to(root), Workspace(root))
        return document.metadata, document.body
    reader = parse_rule_file if entry == "parse_rule_file" else parse_rule_frontmatter
    return reader(str(path))


@contextmanager
def fifo_deadline():
    """A regression must fail promptly even if a pathname open blocks."""
    def expired(_signal, _frame):
        raise AssertionError("rule reader blocked on FIFO")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 2)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("kind", ["regular", "symlink-in", "symlink-out", "fifo", "oversize", "missing"])
def test_rule_path_matrix(tmp_path, entry, kind):
    root = tmp_path / "workspace"
    root.mkdir()
    path = root / "rule.md"
    if kind in ("regular", "oversize"):
        path.write_text(TEXT + ("x" * MAX_RULE_BYTES if kind == "oversize" else ""), encoding="utf-8")
    elif kind.startswith("symlink"):
        target = (root if kind == "symlink-in" else tmp_path) / "target.md"
        target.write_text(TEXT, encoding="utf-8")
        symlink_or_skip(target, path)
    elif kind == "fifo":
        if os.name != "posix":
            pytest.skip("requires POSIX FIFO and deadline signals")
        os.mkfifo(path)

    if kind == "regular":
        metadata, body = read_rule(entry, path, root)
        expected = {"id": "bounded"}
        if entry == "AegisYAML.parse_file":
            expected.update(type="advisory", target_paths=[], decay=True)
        assert metadata == expected
        assert body == ("body" if entry == "AegisYAML.parse_file" else "body\n")
        return
    if kind == "missing":
        error = {"parse_rule_frontmatter": ValueError, "parse_rule_file": RuleNotFoundError,
                 "AegisYAML.parse_file": FileNotFoundError}[entry]
        with pytest.raises(error) as refused:
            read_rule(entry, path, root)
        message = {"parse_rule_frontmatter": "No frontmatter delimiter",
                   "parse_rule_file": f"Rule file not found: {path}",
                   "AegisYAML.parse_file": f"File does not exist: {path}"}[entry]
        assert type(refused.value) is error
        assert str(refused.value) == message
        assert getattr(refused.value, "code", None) == ("ERR_AEGIS" if entry == "parse_rule_file" else None)
        return

    error = RuleParseError if entry == "parse_rule_file" else AegisYAMLError
    message, code = "Rule file read refused", "RULE_FILE_READ_REFUSED"
    if kind == "fifo" and entry == "parse_rule_frontmatter":
        error, message, code = ValueError, "No frontmatter delimiter", None
    elif kind == "fifo" and entry == "parse_rule_file":
        error, message, code = RuleNotFoundError, f"Rule file not found: {path}", "ERR_AEGIS"
    elif kind.startswith("symlink") and entry == "AegisYAML.parse_file":
        message, code = f"Symlink parsing prohibited for security: {path}", None
    elif kind == "oversize":
        message = SIZE_ADVICE
    if kind == "fifo":
        with fifo_deadline(), pytest.raises(error) as refused:
            read_rule(entry, path, root)
    else:
        with pytest.raises(error) as refused:
            read_rule(entry, path, root)
    assert str(refused.value) == message
    assert getattr(refused.value, "code", None) == code
    if code != "RULE_FILE_READ_REFUSED":
        assert type(refused.value) is error

    # A refusal does not poison the next read after the unsafe entry is replaced.
    path.unlink()
    path.write_text(TEXT, encoding="utf-8")
    assert read_rule(entry, path, root)[0]["id"] == "bounded"


def module_os(*, o_path=True, **overrides):
    """An explicit owned OS boundary; the shared os module is never modified."""
    return SimpleNamespace(
        path=overrides.get("path", os.path), stat=overrides.get("stat", os.stat), fstat=os.fstat,
        open=overrides.get("open", os.open), close=overrides.get("close", os.close),
        read=overrides.get("read", os.read), O_RDONLY=os.O_RDONLY,
        O_BINARY=getattr(os, "O_BINARY", 0), O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0), O_NONBLOCK=getattr(os, "O_NONBLOCK", 0),
        O_DIRECTORY=getattr(os, "O_DIRECTORY", 0),
        **({"O_PATH": getattr(os, "O_PATH", os.O_RDONLY)} if o_path else {}),
    )


def make_store(root):
    if not rule_inventory.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


@pytest.mark.parametrize("kind", ["regular", "symlink-in", "symlink-out", "fifo", "oversize", "missing"])
@pytest.mark.parametrize("rooted", [False, True], ids=["rootless", "rooted"])
def test_single_file_facade_matrix(tmp_path, kind, rooted):
    from aegis_core.rule_inventory import read_rule_file, RuleInventoryError

    root = tmp_path / "workspace"
    root.mkdir()
    path = root / "rule.md"
    kwargs = {"root": root} if rooted else {}
    if kind in ("regular", "oversize"):
        path.write_bytes(TEXT.encode() + (b"x" * MAX_RULE_BYTES if kind == "oversize" else b""))
    elif kind.startswith("symlink"):
        target = (root if kind == "symlink-in" else tmp_path) / "target.md"
        target.write_text(TEXT, encoding="utf-8")
        symlink_or_skip(target, path)
    elif kind == "fifo":
        if os.name != "posix":
            pytest.skip("requires POSIX FIFO")
        os.mkfifo(path)
    if kind == "regular":
        assert read_rule_file(path, **kwargs) == TEXT.encode()
    else:
        with pytest.raises(RuleInventoryError) as refused:
            read_rule_file(path, **kwargs)
        assert str(refused.value) == (SIZE_ADVICE if kind == "oversize" else "Rule file read refused")
        assert refused.value.code == ("RULE_FILE_NOT_FOUND" if kind == "missing" else "RULE_FILE_READ_REFUSED")


def test_facade_unsupported_probe_keeps_inventory_fallback(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import read_rule_file, RuleInventoryError

    path = tmp_path / "rule.md"
    path.write_bytes(b"---\r\nid: bounded\r\n---\r\nbody\x1a\r\n")
    monkeypatch.setattr(rule_inventory, "descriptor_supported", lambda: False)
    assert read_rule_file(path, root=tmp_path) == path.read_bytes()
    path.write_bytes(b"x" * (MAX_RULE_BYTES + 1))
    with pytest.raises(RuleInventoryError) as refused:
        read_rule_file(path, root=tmp_path)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    assert str(refused.value) == SIZE_ADVICE


@pytest.mark.parametrize("rooted", [False, True], ids=["rootless", "rooted"])
def test_size_advice_remains_fixed_across_concurrent_refusals(tmp_path, rooted):
    root = tmp_path.resolve()
    path = root / "private-rule.md"
    path.write_bytes(b"x" * (MAX_RULE_BYTES + 1))
    non_file = root / "private-directory.md"
    non_file.mkdir()
    kwargs = {"root": root} if rooted else {}

    def refuse(target):
        with pytest.raises(rule_inventory.RuleInventoryError) as error:
            rule_inventory.read_rule_file(target, **kwargs)
        return error.value.code, str(error.value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        actual = list(pool.map(refuse, (path, non_file, non_file, path), timeout=15))
    assert actual == [
        ("RULE_FILE_READ_REFUSED", SIZE_ADVICE),
        ("RULE_FILE_READ_REFUSED", "Rule file read refused"),
        ("RULE_FILE_READ_REFUSED", "Rule file read refused"),
        ("RULE_FILE_READ_REFUSED", SIZE_ADVICE),
    ]
    path.write_bytes(b"x" * MAX_RULE_BYTES)
    assert rule_inventory.read_rule_file(path, **kwargs) == path.read_bytes()


@pytest.mark.parametrize("phase", ["leaf", "before-ancestor", "parent-replaced", "ancestor", "read", "growth", "io"])
@pytest.mark.parametrize("rooted", [False, True], ids=["rootless", "rooted"])
def test_facade_races_and_failures_close_descriptors(tmp_path, monkeypatch, phase, rooted):
    from aegis_core.rule_inventory import read_rule_file, RuleInventoryError

    root = make_store(tmp_path)
    parent = root / "rules"
    parent.mkdir()
    path = parent / "rule.md"
    kwargs = {"root": root} if rooted else {}
    path.write_text(TEXT, encoding="utf-8")
    outside = root / "outside"
    outside.mkdir()
    (outside / "rule.md").write_text("outside", encoding="utf-8")
    opened, closed = [], []
    changes = []

    def replace_parent():
        parent.rename(root / "old-rules")
        if phase == "parent-replaced":
            parent.mkdir()
            path.write_text("outside", encoding="utf-8")
        else:
            symlink_or_skip(outside, parent, target_is_directory=True)

    def open_owned(name, flags, *args, **kwargs):
        target = ("rules" if phase in ("before-ancestor", "parent-replaced") else "rule.md") if rooted else str(path)
        changing = (not changes and name == target and phase in ("leaf", "before-ancestor", "parent-replaced", "ancestor")
                    and (rooted or phase != "ancestor"))
        if changing:
            changes.append(phase)
            if phase == "leaf":
                path.rename(parent / "old.md")
                path.write_text(TEXT, encoding="utf-8")
            else:
                replace_parent()
        fd = os.open(name, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def close_owned(fd):
        closed.append(fd)
        os.close(fd)

    def read_owned(fd, size):
        if not changes and not rooted and phase == "ancestor":
            changes.append(phase)
            replace_parent()
        if phase == "parent-replaced":
            pytest.fail("replaced parent reached file read")
        if not changes and phase in ("read", "growth", "io"):
            changes.append(phase)
            if phase == "io":
                raise OSError("untrusted diagnostic")
            with path.open("ab") as stream:
                stream.write(b"x" * (MAX_RULE_BYTES if phase == "growth" else 1))
        return os.read(fd, size)

    monkeypatch.setattr(rule_inventory, "os", module_os(open=open_owned, close=close_owned, read=read_owned))
    with pytest.raises(RuleInventoryError, match="^Rule file read refused$") as refused:
        read_rule_file(path, **kwargs)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    assert changes == [phase]
    assert sorted(opened) == sorted(closed)
    for fd in set(opened):
        with pytest.raises(OSError):
            os.fstat(fd)
    if parent.is_symlink():
        parent.unlink()
        parent.mkdir()
    path.write_text(TEXT, encoding="utf-8")
    if phase == "parent-replaced":
        monkeypatch.setattr(rule_inventory, "os", module_os(open=open_owned, close=close_owned))
    assert read_rule_file(path, **kwargs) == TEXT.encode()
    assert sorted(opened) == sorted(closed)


def test_facade_size_limit_precedes_open_and_parsing(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import read_rule_file, RuleInventoryError

    path = tmp_path / "rule.md"
    with path.open("wb") as stream:
        stream.truncate(MAX_RULE_BYTES + 1)
    monkeypatch.setattr(rule_inventory, "os", module_os(open=lambda *a, **k: pytest.fail("oversize file opened")))
    with pytest.raises(RuleInventoryError) as refused:
        read_rule_file(path)
    assert str(refused.value) == SIZE_ADVICE


@pytest.mark.parametrize("entry", ENTRIES)
def test_ancestor_alias_follows_root_contract(tmp_path, entry):
    root = tmp_path / "workspace"
    root.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    (target / "rule.md").write_text(TEXT, encoding="utf-8")
    symlink_or_skip(target, root / "rules", target_is_directory=True)
    if entry == "AegisYAML.parse_file":
        relative = str((root / "rules" / "rule.md").relative_to(root))
        with pytest.raises(PathTraversalError) as refused:
            read_rule(entry, root / "rules" / "rule.md", root)
        assert type(refused.value) is PathTraversalError
        assert str(refused.value) == (
            f"path traversal blocked: {relative!r} resolves to {(target / 'rule.md').resolve()} "
            f"which is outside the workspace {root.resolve()}"
        )
        assert refused.value.code == "ERR_PATH_TRAVERSAL"
        return
    assert read_rule(entry, root / "rules" / "rule.md", root)[0]["id"] == "bounded"


def test_content_only_input_keeps_large_body():
    text = TEXT + "x" * MAX_RULE_BYTES
    metadata, body = parse_rule_frontmatter(text)
    assert metadata == {"id": "bounded"}
    assert body == "body\n" + "x" * MAX_RULE_BYTES


@pytest.mark.skipif(os.name != "posix", reason="POSIX permits newlines in file names")
def test_existing_newline_path_keeps_legacy_path_detection(tmp_path):
    path = tmp_path / "rule\nname.md"
    path.write_text(TEXT, encoding="utf-8")
    assert parse_rule_frontmatter(str(path)) == ({"id": "bounded"}, "body\n")


@pytest.mark.parametrize("path", [None, "\x00private", "x" * 32769], ids=["none", "nul", "long"])
def test_explicit_path_refusals_have_fixed_code(path):
    with pytest.raises(RuleParseError, match="^Rule file read refused$") as refused:
        parse_rule_file(path)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"


@pytest.mark.parametrize("slot,rooted,tuple_result", [
    ("path", False, False),
    ("root", False, False),
    ("source", False, False),
    ("workspace-root", False, False),
    ("resolved", False, False),
    ("resolved", False, True),
    ("resolved", True, False),
    ("resolved", True, True),
])
@pytest.mark.parametrize("case", ["valid", "at-limit", "over-limit", "nul", "empty", "wrong-type"])
def test_rule_path_spelling_at_read_boundaries(tmp_path, monkeypatch, slot, rooted, tuple_result, case):
    root = tmp_path.resolve()
    path = root / "rule.md"
    path.write_bytes(TEXT.encode())
    real = root if slot in ("root", "workspace-root") else path
    # The application's limit can exceed the OS limit. Redundant separators
    # name the same file. Normalize only at the test's OS boundary if needed.
    if case == "at-limit":
        extra = MAX_RULE_PATH_CHARS - len(str(real))
        if real == root:
            spelling = str(root) + os.sep * extra
        else:
            spelling = str(root) + os.sep * (extra + 1) + path.name
        boundary = module_os(
            open=lambda name, *a, **kw: os.open(real if name == spelling else name, *a, **kw),
            stat=lambda name, **kw: os.stat(real if name == spelling else name, **kw),
        )
        monkeypatch.setattr(rule_inventory, "os", boundary)
    else:
        spelling = {"valid": real, "over-limit": "x" * (MAX_RULE_PATH_CHARS + 1), "nul": "\x00rule.md",
                    "empty": "", "wrong-type": object()}[case]

    def unexpected(*args, **kwargs):
        pytest.fail("invalid spelling advanced to path lookup or filesystem access")

    diagnostic_paths = []

    def normalize_refusal(value):
        assert value == "."
        diagnostic_paths.append(value)
        return os.path.abspath(value)

    valid = case in ("valid", "at-limit")
    workspace_slot = slot in ("workspace-root", "resolved")
    queries = []
    path_checks = []
    expected_path_checks = ["construct root", "join query", "check original for symlink"] if rooted else []
    query = path.name

    class RootPath:
        def __truediv__(self, value):
            assert value is query
            path_checks.append("join query")
            return SimpleNamespace(is_symlink=check_original)

    def check_original():
        path_checks.append("check original for symlink")
        return path.is_symlink()

    def construct_root(value):
        assert rooted and value is root and not queries
        path_checks.append("construct root")
        return RootPath()

    def confine(value):
        assert value is query
        if not valid:
            assert path_checks == expected_path_checks
        queries.append(value)
        result = spelling if slot == "resolved" else path
        return (result, path) if tuple_result else result

    if workspace_slot:
        if slot == "workspace-root":
            adapter = SimpleNamespace(root=spelling, confine_path=confine if valid else unexpected)
        else:
            adapter = SimpleNamespace(root=root if rooted else None, confine_path=confine)
        read = lambda: AegisYAML.parse_file(query, adapter).id
        error, expected = RuleReadError, "bounded"
    else:
        arguments = {"path": path, "root": root, "source": path}
        arguments[slot] = spelling
        read = lambda: rule_inventory.read_rule_file(**arguments)
        error, expected = rule_inventory.RuleInventoryError, TEXT.encode()
    if valid:
        assert read() == expected
    else:
        # The inventory refusal normalizes its fixed diagnostic path, ".".
        # Joining or probing the input must still fail immediately.
        metadata = SimpleNamespace(abspath=normalize_refusal, join=unexpected, exists=unexpected,
                                   isfile=unexpected, islink=unexpected, isdir=unexpected)
        os_boundary = module_os(path=metadata, stat=unexpected, open=unexpected)
        locate_rule = rule_inventory._rule_read_location
        monkeypatch.setattr(rule_inventory, "os", os_boundary)
        monkeypatch.setattr(rule_inventory, "_rule_read_location", unexpected)
        if workspace_slot:
            monkeypatch.setattr(frontmatter, "os", os_boundary)
            monkeypatch.setattr(frontmatter, "Path", construct_root if rooted else unexpected)
            monkeypatch.setattr(frontmatter, "read_rule_file", unexpected)
        with pytest.raises(error, match="^Rule file read refused$") as refused:
            read()
        assert type(refused.value) is error
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
        assert diagnostic_paths == ([] if workspace_slot else ["."])
        assert path_checks == expected_path_checks
        monkeypatch.setattr(rule_inventory, "os", os)
        monkeypatch.setattr(rule_inventory, "_rule_read_location", locate_rule)
        if workspace_slot:
            monkeypatch.setattr(frontmatter, "os", os)
            monkeypatch.setattr(frontmatter, "Path", Path)
            monkeypatch.setattr(frontmatter, "read_rule_file", rule_inventory.read_rule_file)
        assert AegisYAML.parse_file(query, Workspace(root)).id == "bounded"
    assert queries == ([query] if slot == "resolved" or slot == "workspace-root" and valid else [])


@pytest.fixture
def rule_path_boundary(monkeypatch):
    """Allow only listed operations on the parser's own filesystem interfaces."""
    active = local()

    def check(operation, *operands):
        pending = getattr(active, "pending", None)
        if not pending:
            pytest.fail(f"unexpected rule path operation: {operation}")
        expected = pending.pop(0)
        assert (operation, *operands) == expected
        if operation == "join":
            assert operands[-1] is expected[-1]

    class DenyAccess:
        def __getattr__(self, name):
            pytest.fail(f"unexpected filesystem access: {name}")

    class ObservedPath(DenyAccess):
        def __init__(self, path):
            self.path = path

        def __str__(self):
            return str(self.path)

        def __truediv__(self, query):
            check("join", self.path, query)
            return ObservedPath(self.path / query)

        def exists(self):
            check("exists", self.path)
            return self.path.exists()

        def is_symlink(self):
            check("is_symlink", self.path)
            return self.path.is_symlink()

        def is_dir(self):
            check("is_dir", self.path)
            return self.path.is_dir()

    class PathType(type):
        def __instancecheck__(cls, value):
            return isinstance(value, Path)

    class CheckedPath(metaclass=PathType):
        def __new__(cls, value):
            check("Path", value)
            return ObservedPath(Path(value))

    def read(target, *, root, source, preserve_os_errors, canonicalize_parent):
        if isinstance(target, ObservedPath):
            target = target.path
        check("read", target, root, source, preserve_os_errors, canonicalize_parent)
        return rule_inventory.read_rule_file(target, root=root, source=source, preserve_os_errors=preserve_os_errors,
                                             canonicalize_parent=canonicalize_parent)

    @contextmanager
    def allow(*operations):
        active.pending = list(operations)
        try:
            yield
            assert active.pending == []
        finally:
            active.pending = []

    monkeypatch.setattr(frontmatter, "os", DenyAccess())
    monkeypatch.setattr(frontmatter, "Path", CheckedPath)
    monkeypatch.setattr(frontmatter, "read_rule_file", read)
    return SimpleNamespace(check=check, allow=allow)


def rule_result_probes(source):
    path = Path(source)
    return (("Path", source), ("exists", path), ("is_symlink", path), ("is_dir", path))


def rooted_rule_probe(root, query, target):
    return (("Path", root), ("join", root, query), ("is_symlink", target))


def rooted_rule_read(root, query, target, source):
    return (*rule_result_probes(source), ("Path", root), ("join", root, query),
            ("read", target, root, source, True, False))


def test_relative_rule_path_spelling_refuses_before_confinement_and_retries(tmp_path, rule_path_boundary):
    path = tmp_path / "rule.md"
    path.write_bytes(TEXT.encode())
    at_limit = "x" * MAX_RULE_PATH_CHARS

    class Adapter:
        @property
        def root(self):
            rule_path_boundary.check("root")
            return None

        def confine_path(self, spelling):
            rule_path_boundary.check("confine", spelling)
            return path

    adapter = Adapter()

    def parse_valid(query):
        with rule_path_boundary.allow(
            ("root",), ("confine", query), *rule_result_probes(path), ("read", path, None, path, True, False),
        ):
            return AegisYAML.parse_file(query, adapter).id

    def refuse_and_retry(spelling):
        with rule_path_boundary.allow():
            with pytest.raises(RuleReadError, match="^Rule file read refused$") as refused:
                AegisYAML.parse_file(spelling, adapter)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
        return parse_valid(path.name)

    invalid = ("", at_limit + "x", at_limit + "\x00", None)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(refuse_and_retry, invalid, timeout=15)) == ["bounded"] * len(invalid)
    assert parse_valid(at_limit) == "bounded"


@pytest.mark.parametrize("kind", ["native", "opaque-refuses", "opaque-accepts", "invalid-root"])
def test_bounded_nul_query_preserves_confiner_dispatch(tmp_path, rule_path_boundary, kind):
    root = tmp_path.resolve()
    path = root / "rule.md"
    path.write_bytes(TEXT.encode())
    workspace = Workspace(root)
    query = "\x00rule.md"
    roots = {"native": workspace.root, "invalid-root": ""}

    def confine(value):
        assert value is query
        rule_path_boundary.check("confine", value)
        if kind == "native":
            return workspace.confine_path(value)
        if kind == "opaque-refuses":
            raise RuleReadError("Rule file read refused")
        return path

    class Adapter:
        @property
        def root(self):
            rule_path_boundary.check("root")
            return roots.get(kind)

        confine_path = staticmethod(confine)

    adapter = Adapter()
    allowed = [("root",)]
    if kind == "native":
        allowed.extend(rooted_rule_probe(root, query, root / query))
    if kind != "invalid-root":
        allowed.append(("confine", query))
    if kind == "opaque-accepts":
        with rule_path_boundary.allow(*allowed, *rule_result_probes(path), ("read", path, None, path, True, False)):
            assert AegisYAML.parse_file(query, adapter).id == "bounded"
    else:
        error, code, message = RuleReadError, "RULE_FILE_READ_REFUSED", "Rule file read refused"
        if kind == "native":
            error, code, message = PathTraversalError, "ERR_PATH_TRAVERSAL", "null bytes are not permitted in file paths"
        with rule_path_boundary.allow(*allowed):
            with pytest.raises(error) as refused:
                AegisYAML.parse_file(query, adapter)
        assert type(refused.value) is error
        assert str(refused.value) == message
        assert refused.value.code == code
    retry = path.name
    with rule_path_boundary.allow(
        *rooted_rule_probe(root, retry, path), *rooted_rule_read(root, retry, path, str(path)),
    ):
        assert AegisYAML.parse_file(retry, workspace).id == "bounded"


@pytest.mark.parametrize("base", [str, type(Path())], ids=["str", "path"])
@pytest.mark.parametrize("rooted", [False, True], ids=["opaque", "rooted"])
def test_relative_rule_path_preserves_custom_rendering(tmp_path, rule_path_boundary, base, rooted):
    root = tmp_path.resolve()
    path = root / "rule.md"
    path.write_bytes(TEXT.encode())
    calls = []

    class Rendered(str):
        def __contains__(self, item):
            calls.append("membership")
            raise LookupError("rendered membership")

    class Query(base):
        def __str__(self):
            return Rendered("rule.md")

    query = Query(path.name)

    class Adapter:
        @property
        def root(self):
            rule_path_boundary.check("root")
            calls.append("root")
            return root if rooted else None

        def confine_path(self, value):
            assert value is query
            rule_path_boundary.check("confine", value)
            calls.append("confine")
            return path

    if rooted and base is str:
        try:
            assert root / Query(path.name) == path
        except LookupError as expected:
            assert expected.args == ("rendered membership",)
            calls.clear()
            with rule_path_boundary.allow(("root",), ("Path", root), ("join", root, query)):
                with pytest.raises(LookupError, match="^rendered membership$") as refused:
                    AegisYAML.parse_file(query, Adapter())
            assert type(refused.value) is LookupError
            assert calls == ["root", "membership"]
            return

    original_probe = rooted_rule_probe(root, query, path) if rooted else ()
    read = rooted_rule_read(root, query, path, path) if rooted else (
        *rule_result_probes(path), ("read", path, None, path, True, False),
    )
    with rule_path_boundary.allow(
        ("root",), *original_probe, ("confine", query), *read,
    ):
        document = AegisYAML.parse_file(query, Adapter())
    assert (document.id, document.source_path, calls) == ("bounded", str(path), ["root", "confine"])


@pytest.mark.parametrize("files", ["missing-rendered", "both-existing", "missing-original"])
def test_rooted_rule_path_selects_runtime_join_name(tmp_path, rule_path_boundary, files):
    root = tmp_path.resolve()
    original, rendered = root / "rule.md", root / "display.md"
    if files != "missing-original":
        original.write_bytes(TEXT.encode())
    if files != "missing-rendered":
        rendered.write_bytes(TEXT.replace("bounded", "displayed").encode())

    class Query(str):
        def __str__(self):
            return rendered.name

    query = Query(original.name)
    source = rendered if files == "missing-original" else original
    target = rendered if sys.version_info < (3, 12) else original

    def confine(value):
        assert value is query
        rule_path_boundary.check("confine", value)
        return source

    adapter = SimpleNamespace(root=root, confine_path=confine)
    with rule_path_boundary.allow(
        *rooted_rule_probe(root, query, target), ("confine", query),
        *rooted_rule_read(root, query, target, source),
    ):
        if target == source:
            document = AegisYAML.parse_file(query, adapter)
            assert document.id == ("bounded" if source == original else "displayed")
            assert document.source_path == str(source)
        elif target.exists():
            with pytest.raises(RuleReadError, match="^Rule file read refused$") as refused:
                AegisYAML.parse_file(query, adapter)
            assert type(refused.value) is RuleReadError
            assert refused.value.code == "RULE_FILE_READ_REFUSED"
        else:
            with pytest.raises(FileNotFoundError) as refused:
                AegisYAML.parse_file(query, adapter)
            assert type(refused.value) is FileNotFoundError
            assert str(refused.value) == f"File does not exist: {source}"


@pytest.mark.parametrize("link_name", ["rule.md", "display.md"], ids=["original-link", "rendered-link"])
def test_rooted_rule_path_refuses_symlink_selected_by_runtime(tmp_path, rule_path_boundary, link_name):
    root = tmp_path.resolve()
    original, rendered = root / "rule.md", root / "display.md"
    link = root / link_name
    regular = rendered if link == original else original
    regular.write_bytes(TEXT.encode())
    symlink_or_skip(regular, link)
    workspace = Workspace(root)

    class Query(str):
        def __str__(self):
            return rendered.name

    query = Query(original.name)
    target = rendered if sys.version_info < (3, 12) else original

    def confine(value):
        assert value is query
        rule_path_boundary.check("confine", value)
        return workspace.confine_path(value)

    adapter = SimpleNamespace(root=root, confine_path=confine)
    probe = rooted_rule_probe(root, query, target)
    if target == link:
        with rule_path_boundary.allow(*probe):
            with pytest.raises(AegisYAMLError) as refused:
                AegisYAML.parse_file(query, adapter)
        assert type(refused.value) is AegisYAMLError
        assert str(refused.value) == f"Symlink parsing prohibited for security: {link}"
    else:
        with rule_path_boundary.allow(
            *probe, ("confine", query), *rooted_rule_read(root, query, regular, str(regular)),
        ):
            document = AegisYAML.parse_file(query, adapter)
        assert (document.id, document.source_path) == ("bounded", str(regular))


@pytest.mark.parametrize("style", ["empty", "over-limit", "dot-components"])
def test_rooted_rule_path_preserves_rendered_length_admission(tmp_path, rule_path_boundary, style):
    root = tmp_path.resolve()
    path = root / "rule.md"
    path.write_bytes(TEXT.encode())
    spelling = {"empty": "", "over-limit": "x" * (MAX_RULE_PATH_CHARS + 1),
                "dot-components": "./" * MAX_RULE_PATH_CHARS + path.name}[style]

    class Rendering(str):
        def __len__(self):
            return 1

    class Query(str):
        def __str__(self):
            return Rendering(spelling)

    query = Query(path.name)
    workspace = Workspace(root)
    source = str(path) if style == "dot-components" else path

    def confine(value):
        assert value is query
        rule_path_boundary.check("confine", value)
        if style == "dot-components":
            return workspace.confine_path(value)
        return path

    adapter = SimpleNamespace(root=root, confine_path=confine)
    # Match the platform's join and probe before expecting confinement.
    probe = [("Path", root), ("join", root, query)]
    try:
        target = root / Query(path.name)
        probe.append(("is_symlink", target))
        assert not target.is_symlink()
    except (IndexError, TypeError, OSError) as expected:
        with rule_path_boundary.allow(*probe):
            with pytest.raises(type(expected)) as refused:
                AegisYAML.parse_file(query, adapter)
        assert type(refused.value) is type(expected)
        assert refused.value.args == expected.args
        assert getattr(refused.value, "filename", None) == getattr(expected, "filename", None)
        return

    with rule_path_boundary.allow(
        *probe, ("confine", query), *rooted_rule_read(root, query, target, source),
    ):
        if target == path:
            document = AegisYAML.parse_file(query, adapter)
            assert (document.id, document.source_path) == ("bounded", str(path))
        else:
            with pytest.raises(RuleReadError, match="^Rule file read refused$") as refused:
                AegisYAML.parse_file(query, adapter)
            assert type(refused.value) is RuleReadError
            assert refused.value.code == "RULE_FILE_READ_REFUSED"


def test_rooted_rule_path_preserves_stateful_rendering_order(tmp_path, rule_path_boundary):
    root = tmp_path.resolve()
    path = root / "rule.md"
    path.write_bytes(TEXT.encode())
    first_join = root / "probe.md"
    first_join.write_bytes(TEXT.replace("bounded", "probe").encode())
    renderings = iter(("admission.md", first_join.name, path.name))
    calls = []

    class Query(str):
        def __str__(self):
            name = next(renderings)
            calls.append(name)
            return name

    query = Query(path.name)
    older_pathlib = sys.version_info < (3, 12)

    def confine(value):
        assert value is query
        rule_path_boundary.check("confine", value)
        calls.append("confine")
        return path

    adapter = SimpleNamespace(root=root, confine_path=confine)
    with rule_path_boundary.allow(
        *rooted_rule_probe(root, query, first_join if older_pathlib else path), ("confine", query),
        *rooted_rule_read(root, query, path, path),
    ):
        document = AegisYAML.parse_file(query, adapter)
    assert (document.id, document.source_path) == ("bounded", str(path))
    expected = ["admission.md", first_join.name, "confine", path.name] if older_pathlib else ["admission.md", "confine"]
    assert calls == expected


def test_explicit_file_dispatch_uses_spelling_even_if_truthiness_is_overridden(tmp_path):
    class FalsePath(str):
        def __bool__(self):
            return False

    class TruePath(str):
        def __bool__(self):
            return True

    path = tmp_path / "rule.md"
    path.write_bytes(TEXT.encode())
    assert parse_rule_file(FalsePath(str(path))) == ({"id": "bounded"}, "body\n")
    with pytest.raises(RuleNotFoundError) as refused:
        parse_rule_file(TruePath(""))
    assert type(refused.value) is RuleNotFoundError
    assert str(refused.value) == "Rule file not found: "
    assert refused.value.code == "ERR_AEGIS"


def test_rule_path_spelling_preserves_legacy_file_and_text_dispatch(tmp_path, monkeypatch):
    path = tmp_path / "rule.md"
    path.write_bytes(TEXT.encode())
    at_limit = TEXT.ljust(MAX_RULE_PATH_CHARS, "x")
    missing = "missing-rule-path.md"
    queries = []

    def exists(value):
        queries.append(("exists", value))
        return value in (path, tmp_path, at_limit)

    def isfile(value):
        queries.append(("isfile", value))
        return value == path

    monkeypatch.setattr(frontmatter, "os", SimpleNamespace(path=SimpleNamespace(exists=exists, isfile=isfile)))
    assert parse_rule_frontmatter(path) == ({"id": "bounded"}, "body\n")
    assert parse_rule_file(path) == ({"id": "bounded"}, "body\n")
    for content in (at_limit, at_limit + "x", TEXT + "\x00"):
        assert parse_rule_frontmatter(content) == ({"id": "bounded"}, content.split("---\n")[2])
    with pytest.raises(ValueError, match="^No frontmatter delimiter$"):
        parse_rule_frontmatter("")
    with pytest.raises(ValueError, match="^No frontmatter delimiter$"):
        parse_rule_frontmatter(missing)
    with pytest.raises(RuleNotFoundError) as refused:
        parse_rule_file(tmp_path)
    assert str(refused.value) == f"Rule file not found: {tmp_path}"
    with pytest.raises(RuleNotFoundError, match="^Rule file not found: $") as refused:
        parse_rule_file("")
    assert refused.value.code == "ERR_AEGIS"
    with pytest.raises(RuleNotFoundError) as refused:
        parse_rule_file(at_limit)
    assert str(refused.value) == "Rule file not found: [diagnostic omitted: too_large]"
    assert refused.value.code == "ERR_AEGIS"
    for spelling in (at_limit + "x", "\x00rule.md"):
        with pytest.raises(RuleParseError, match="^Rule file read refused$") as refused:
            parse_rule_file(spelling)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
    assert queries == [
        ("exists", path), ("isfile", path), ("isfile", path),
        ("exists", at_limit), ("isfile", at_limit), ("exists", missing),
        ("isfile", tmp_path), ("isfile", at_limit),
    ]


@pytest.mark.parametrize("entry", [parse_rule_frontmatter, parse_rule_file], ids=["mixed", "explicit"])
@pytest.mark.parametrize("existing", [False, True], ids=["missing", "existing"])
@pytest.mark.parametrize("rendering", ["empty", "nul", "over-limit", "valid"])
def test_rule_dispatch_preserves_underlying_filename(tmp_path, monkeypatch, entry, existing, rendering):
    rendered = {"empty": "", "nul": "shown\x00.md", "over-limit": "x" * (MAX_RULE_PATH_CHARS + 1),
                "valid": "shown.md"}[rendering]

    class RenderedPath(str):
        def __str__(self):
            return rendered

    path = tmp_path / "rule.md"
    if existing:
        path.write_bytes(TEXT.encode())
    original = RenderedPath(path)
    calls = []
    read_rule_file = frontmatter.read_rule_file

    def exists(value):
        assert value is original
        calls.append("exists")
        return os.path.exists(value)

    def isfile(value):
        assert value is original
        calls.append("isfile")
        return os.path.isfile(value)

    def read(value, **kwargs):
        assert value is original
        calls.append("read")
        return read_rule_file(value, **kwargs)

    monkeypatch.setattr(frontmatter, "os", SimpleNamespace(path=SimpleNamespace(exists=exists, isfile=isfile)))
    monkeypatch.setattr(frontmatter, "read_rule_file", read)
    if existing and rendering == "valid":
        assert entry(original) == ({"id": "bounded"}, "body\n")
        expected_calls = ["isfile", "read"] if entry is parse_rule_file else ["exists", "isfile", "read"]
    else:
        if entry is parse_rule_frontmatter:
            if rendering == "over-limit":
                expected_calls = []
            elif existing:
                expected_calls = ["exists", "isfile", "read"]
            else:
                expected_calls = ["exists"]
            if "read" in expected_calls:
                error, code, message = RuleReadError, "RULE_FILE_READ_REFUSED", "Rule file read refused"
            else:
                error, code, message = ValueError, None, "No frontmatter delimiter"
        elif rendering in ("empty", "valid") and not existing:
            expected_calls = ["isfile"]
            error, code, message = RuleNotFoundError, "ERR_AEGIS", f"Rule file not found: {rendered}"
        else:
            expected_calls = ["isfile", "read"] if rendering == "empty" else ["read"]
            error, code, message = RuleParseError, "RULE_FILE_READ_REFUSED", "Rule file read refused"
        with pytest.raises(error) as refused:
            entry(original)
        assert type(refused.value) is error
        assert getattr(refused.value, "code", None) == code
        assert str(refused.value) == message
    assert calls == expected_calls


@pytest.mark.parametrize("entry", [parse_rule_frontmatter, parse_rule_file], ids=["mixed", "explicit"])
@pytest.mark.parametrize("length", [0, MAX_RULE_PATH_CHARS, MAX_RULE_PATH_CHARS + 1],
                         ids=["empty", "at-limit", "over-limit"])
def test_custom_string_dispatch_preserves_rendering_protocol(monkeypatch, entry, length):
    calls = []
    renderings = []

    class Rendering(str):
        def __len__(self):
            calls.append(("length", len(renderings)))
            return super().__len__()

        def __contains__(self, value):
            assert value == "\x00" and self is renderings[-1]
            calls.append(("membership", len(renderings)))
            raise LookupError("rendered membership")

    class CustomType(type):
        def __eq__(self, other):
            calls.append("compare type")
            return NotImplemented

    class Markdown(str, metaclass=CustomType):
        def __str__(self):
            spelling = Rendering("x" * length)
            renderings.append(spelling)
            calls.append("render")
            return spelling

    original = Markdown(TEXT)
    read_rule_file = frontmatter.read_rule_file

    def exists(value):
        assert value is original
        calls.append("exists")
        return False

    def isfile(value):
        pytest.fail("unexpected isfile probe for custom markdown")

    def read(value, **kwargs):
        assert value is original
        calls.append("read")
        return read_rule_file(value, **kwargs)

    monkeypatch.setattr(frontmatter, "os", SimpleNamespace(path=SimpleNamespace(exists=exists, isfile=isfile)))
    monkeypatch.setattr(frontmatter, "read_rule_file", read)
    expected = ["render", ("length", 1)]
    if entry is parse_rule_frontmatter:
        if length <= MAX_RULE_PATH_CHARS:
            expected.append("exists")
        assert entry(original) == ({"id": "bounded"}, "body\n")
    elif length <= MAX_RULE_PATH_CHARS:
        expected.extend(["render", ("membership", 2)])
        with pytest.raises(LookupError, match="^rendered membership$"):
            entry(original)
    else:
        expected.extend(["read", "render", ("length", 2)])
        with pytest.raises(RuleParseError, match="^Rule file read refused$") as refused:
            entry(original)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
    assert calls == expected


@pytest.mark.parametrize("entry", [parse_rule_frontmatter, parse_rule_file], ids=["mixed", "explicit"])
def test_custom_path_dispatch_preserves_filesystem_conversion_order(tmp_path, monkeypatch, entry):
    path = tmp_path / "rule.md"
    path.write_bytes(TEXT.encode())
    calls = []
    mixed = entry is parse_rule_frontmatter
    available_conversions = 2 if mixed else 1

    class StatefulPath(type(tmp_path)):
        def __str__(self):
            calls.append("render")
            return ""

        def __fspath__(self):
            calls.append("fspath")
            return str(path if calls.count("fspath") <= available_conversions else tmp_path / "missing.md")

    original = StatefulPath(path)
    read_rule_file = frontmatter.read_rule_file

    def probe(operation, predicate):
        def check(value):
            assert value is original
            calls.append(operation)
            return predicate(os.fspath(value))
        return check

    def read(value, **kwargs):
        assert value is original
        calls.append("read")
        return read_rule_file(value, **kwargs)

    monkeypatch.setattr(frontmatter, "os", SimpleNamespace(path=SimpleNamespace(
        exists=probe("exists", os.path.exists), isfile=probe("isfile", os.path.isfile),
    )))
    monkeypatch.setattr(frontmatter, "read_rule_file", read)
    error = RuleReadError if mixed else RuleParseError
    with pytest.raises(error, match="^Rule file read refused$") as refused:
        entry(original)
    assert type(refused.value) is error
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    expected = ["render", "exists", "fspath"] if mixed else ["render", "render"]
    assert calls == expected + ["isfile", "fspath", "read", "render"]


@pytest.mark.parametrize("entry", [parse_rule_frontmatter, parse_rule_file], ids=["mixed", "explicit"])
@pytest.mark.parametrize("make_path", [str, Path], ids=["str", "path"])
def test_standard_rule_dispatch_classifies_at_limit_once(monkeypatch, entry, make_path):
    original = make_path("x" * MAX_RULE_PATH_CHARS)
    calls = []

    def classify(value):
        assert value is original
        calls.append("classify")
        return rule_inventory.classify_rule_path_spelling(value)

    def exists(value):
        assert value is original
        calls.append("exists")
        return True

    def isfile(value):
        assert value is original
        calls.append("isfile")
        return True

    def read(value, **kwargs):
        assert value is original
        calls.append("read")
        return TEXT.encode()

    monkeypatch.setattr(frontmatter, "classify_rule_path_spelling", classify)
    monkeypatch.setattr(frontmatter, "os", SimpleNamespace(path=SimpleNamespace(exists=exists, isfile=isfile)))
    monkeypatch.setattr(frontmatter, "read_rule_file", read)
    assert entry(original) == ({"id": "bounded"}, "body\n")
    expected = ["classify", "exists"] if entry is parse_rule_frontmatter else ["classify"]
    assert calls == expected + ["isfile", "read"]


@pytest.mark.parametrize("entry", ENTRIES)
def test_file_parse_refusal_preserves_legacy_diagnostic(tmp_path, entry):
    path = tmp_path / "rule.md"
    path.write_text("---\nPRIVATE_KEY_NAME: 1\nPRIVATE_KEY_NAME: 2\n---\nbody\n", encoding="utf-8")
    error = RuleParseError if entry == "parse_rule_file" else AegisYAMLError
    diagnostic = "Duplicate key 'PRIVATE_KEY_NAME' detected at line 2"
    message = f"Error parsing rule {path}: Invalid YAML frontmatter" if entry == "parse_rule_file" else diagnostic
    with pytest.raises(error) as refused:
        read_rule(entry, path, tmp_path)
    assert type(refused.value) is error
    assert str(refused.value) == message
    assert getattr(refused.value, "code", None) == ("ERR_AEGIS" if entry == "parse_rule_file" else None)


def test_migration_skips_oversize_rule_before_parsing(tmp_path):
    from aegis_core import migrate

    path = tmp_path / ".aegis/rules/traps/rule.md"
    path.parent.mkdir(parents=True)
    text = "---\nid: bounded\ntype: trap\nscore: 1\n---\nbody\n"
    path.write_text(text + "x" * MAX_RULE_BYTES, encoding="utf-8")
    planned = migrate.plan(tmp_path)
    assert not planned.refusal
    assert planned.strips == []
    assert planned.skipped == [{"path": ".aegis/rules/traps/rule.md", "reason": SIZE_ADVICE}]
    path.write_text(text, encoding="utf-8")
    retried = migrate.plan(tmp_path)
    assert not retried.skipped
    assert len(retried.strips) == 1


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("kind", ["oversize", "symlink", "unreadable", "not-file"])
def test_migration_reports_rule_read_advice(tmp_path, monkeypatch, capsys, kind, as_json):
    from aegis_cli.migrate import run_migrate

    relative_path = ".aegis/rules/traps/private-rule.md"
    path = tmp_path / relative_path
    path.parent.mkdir(parents=True)
    (path.parent / "legacy.md").write_text(
        "---\nid: legacy\ntype: trap\nscore: 1\n---\nbody\n", encoding="utf-8",
    )
    if kind == "oversize":
        path.write_bytes(b"x" * (MAX_RULE_BYTES + 1))
        advice = SIZE_ADVICE
    elif kind == "symlink":
        target = tmp_path / "private-target.md"
        target.write_text(TEXT, encoding="utf-8")
        symlink_or_skip(target, path)
        advice = "a symlink or outside the workspace; not followed"
    elif kind == "unreadable":
        path.write_text(TEXT, encoding="utf-8")

        def deny_rule(name, flags, *args, **kwargs):
            if Path(name).name == path.name:
                raise PermissionError(errno.EACCES, "private OS diagnostic", str(path))
            return os.open(name, flags, *args, **kwargs)

        monkeypatch.setattr(rule_inventory, "os", module_os(open=deny_rule))
        with pytest.raises(rule_inventory.RuleInventoryError) as refused:
            rule_inventory.read_rule_file(path, root=tmp_path)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
        assert str(refused.value) == "Rule file read refused"
        advice = None
    else:
        if os.name != "posix":
            pytest.skip("requires a POSIX FIFO")
        os.mkfifo(path)
        advice = "Rule file read refused"

    with fifo_deadline() if kind == "not-file" else nullcontext():
        assert run_migrate(Namespace(workspace=tmp_path, json=as_json)) == 0
    output = capsys.readouterr().out
    assert "private OS diagnostic" not in output
    assert "private-target.md" not in output
    if as_json:
        report = json.loads(output)
        assert report["skipped"] == ([] if advice is None else [{"path": relative_path, "reason": advice}])
        assert report["unreadable"] == ([relative_path] if advice is None else [])
    elif advice is None:
        assert f"  ! cannot read {relative_path}: left in place" in output.splitlines()
    else:
        assert f"  ! {relative_path}: {advice}" in output.splitlines()


def test_migration_recheck_and_backup_use_rule_reader(tmp_path, monkeypatch):
    from aegis_core import migrate

    root = make_store(tmp_path)
    path = root / ".aegis/rules/traps/rule.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nid: bounded\ntype: trap\nscore: 1\n---\nbody\n", encoding="utf-8")
    planned = migrate.plan(root)
    original = path.read_bytes()
    reads = []
    def capture(name, flags, *args, **kwargs):
        if name == "rule.md":
            reads.append(name)
        return os.open(name, flags, *args, **kwargs)

    monkeypatch.setattr(rule_inventory, "os", module_os(open=capture))
    result = migrate.apply(planned)
    assert reads == ["rule.md", "rule.md"]
    assert (result.backup / ".aegis/rules/traps/rule.md").read_bytes() == original

ALL_PATH_ENTRIES = (*ENTRIES, "AegisYAML.parse_file-rootless")


def read_path_entry(entry, path, root):
    if entry == "AegisYAML.parse_file-rootless":
        workspace = SimpleNamespace(confine_path=lambda value: str(value.resolve()))
        document = AegisYAML.parse_file(path, workspace)
        return document.metadata, document.body
    return read_rule(entry, path, root)


def require_permissions():
    if os.name != "posix" or os.geteuid() == 0:
        pytest.skip("requires non-root POSIX permissions")


@pytest.mark.parametrize("entry", ALL_PATH_ENTRIES)
def test_search_only_trusted_ancestor_without_o_path(tmp_path, monkeypatch, entry):
    require_permissions()
    root = make_store(tmp_path) / "trusted" / "workspace"
    path = root / ".aegis/rules/rule.md"
    path.parent.mkdir(parents=True)
    path.write_text(TEXT, encoding="utf-8")
    ancestor = root.parent
    monkeypatch.setattr(rule_inventory, "os", module_os(o_path=False))
    original_mode = ancestor.stat().st_mode
    try:
        ancestor.chmod(0o100)
        try:
            os.listdir(ancestor)
        except PermissionError:
            pass
        else:
            pytest.skip("platform does not enforce search-only directory permissions")
        assert path.read_text(encoding="utf-8") == TEXT
        def read(_):
            return read_path_entry(entry, path, root)[0]["id"]
        assert read(None) == "bounded"
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(read, range(3), timeout=15)) == ["bounded"] * 3
        assert read(None) == "bounded"
    finally:
        ancestor.chmod(original_mode)
    assert read_path_entry(entry, path, root)[0]["id"] == "bounded"


@pytest.mark.parametrize("entry", ALL_PATH_ENTRIES)
def test_symlink_before_parent_component_follows_root_contract(tmp_path, monkeypatch, entry):
    root = make_store(tmp_path)
    rules = root / ".aegis/rules"
    (rules / "nested/child").mkdir(parents=True)
    (rules / "r.md").write_text(TEXT, encoding="utf-8")
    (rules / "nested/r.md").write_text(TEXT.replace("bounded", "different"), encoding="utf-8")
    link = rules / "link"
    symlink_or_skip(rules / "nested/child", link, target_is_directory=True)
    path = link / "../r.md"
    if entry == "AegisYAML.parse_file":
        monkeypatch.setattr(rule_inventory, "os", module_os(
            read=lambda *a, **k: pytest.fail("rooted symlink path reached file read")))
        with pytest.raises(AegisYAMLError, match="^Rule file read refused$") as refused:
            read_path_entry(entry, path, root)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
        monkeypatch.setattr(rule_inventory, "os", os)
    else:
        assert read_path_entry(entry, path, root)[0]["id"] == "different"
    link.unlink()
    link.mkdir()
    assert read_path_entry(entry, path, root)[0]["id"] == "bounded"


@pytest.mark.parametrize("entry", ALL_PATH_ENTRIES)
def test_permission_error_keeps_legacy_os_contract(tmp_path, entry):
    require_permissions()
    root = tmp_path / "workspace"
    path = root / ".aegis/rules/rule.md"
    path.parent.mkdir(parents=True)
    path.write_text(TEXT, encoding="utf-8")
    original_mode = path.stat().st_mode
    try:
        path.chmod(0)
        try:
            path.read_text(encoding="utf-8")
        except PermissionError as exc:
            expected = (type(exc), str(exc), exc.errno, exc.filename)
        else:
            pytest.skip("platform does not enforce unreadable file permissions")
        def refuse(_):
            with pytest.raises(PermissionError) as refused:
                read_path_entry(entry, path, root)
            actual = refused.value
            assert (type(actual), str(actual), actual.errno, actual.filename) == expected
        for _ in range(2):
            refuse(None)
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(refuse, range(3), timeout=15)) == [None] * 3
    finally:
        path.chmod(original_mode)
    assert read_path_entry(entry, path, root)[0]["id"] == "bounded"


def test_migration_permission_error_is_unreadable(tmp_path):
    from aegis_core import migrate

    require_permissions()
    path = tmp_path / ".aegis/rules/traps/rule.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nid: bounded\ntype: trap\nscore: 1\n---\nbody\n", encoding="utf-8")
    original_mode = path.stat().st_mode
    try:
        path.chmod(0)
        try:
            path.read_bytes()
        except PermissionError:
            pass
        else:
            pytest.skip("platform does not enforce unreadable file permissions")
        for _ in range(2):
            planned = migrate.plan(tmp_path)
            assert planned.unreadable == [".aegis/rules/traps/rule.md"]
            assert planned.skipped == []
            assert not planned.strips
    finally:
        path.chmod(original_mode)
    retried = migrate.plan(tmp_path)
    assert not retried.unreadable
    assert len(retried.strips) == 1


def test_recorded_source_must_match_captured_file(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    path = root / "rule.md"
    other = root / "other.md"
    path.write_text(TEXT, encoding="utf-8")
    other.write_text(TEXT, encoding="utf-8")
    workspace = SimpleNamespace(root=root, confine_path=lambda value: str(other))
    monkeypatch.setattr(rule_inventory, "os", module_os(
        read=lambda *a, **k: pytest.fail("mismatched source reached file read")))
    with pytest.raises(AegisYAMLError, match="^Rule file read refused$") as refused:
        AegisYAML.parse_file("rule.md", workspace)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    monkeypatch.setattr(rule_inventory, "os", os)
    workspace.confine_path = lambda value: str(path)
    assert AegisYAML.parse_file("rule.md", workspace).source_path == str(path)


@pytest.mark.parametrize("rooted", [False, True], ids=["rootless", "rooted"])
def test_facade_parent_components_follow_root_contract(tmp_path, rooted):
    root = make_store(tmp_path)
    rules = root / "rules"
    (rules / "child").mkdir(parents=True)
    (rules / "nested/child").mkdir(parents=True)
    (rules / "r.md").write_text(TEXT, encoding="utf-8")
    different = TEXT.replace("bounded", "different")
    (rules / "nested/r.md").write_text(different, encoding="utf-8")
    path = rules / "child/../r.md"
    kwargs = {"root": root} if rooted else {}
    assert rule_inventory.read_rule_file(path, **kwargs) == TEXT.encode()
    (rules / "child").rmdir()
    symlink_or_skip(rules / "nested/child", rules / "child", target_is_directory=True)
    if rooted:
        with pytest.raises(rule_inventory.RuleInventoryError, match="^Rule file read refused$") as refused:
            rule_inventory.read_rule_file(path, **kwargs)
        assert refused.value.code == "RULE_FILE_READ_REFUSED"
    else:
        assert rule_inventory.read_rule_file(path, **kwargs) == different.encode()
    (rules / "child").unlink()
    (rules / "child").mkdir()
    assert rule_inventory.read_rule_file(path, **kwargs) == TEXT.encode()


def test_source_swap_during_capture_closes_descriptors_and_retries(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    path, source, other = root / "rule.md", root / "source.md", root / "other.md"
    path.write_text(TEXT, encoding="utf-8")
    other.write_text(TEXT.replace("bounded", "different"), encoding="utf-8")
    os.link(path, source)
    opened, closed, changes = [], [], []

    def open_owned(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close_owned(fd):
        closed.append(fd)
        os.close(fd)

    def read_owned(fd, size):
        if not changes:
            changes.append("source")
            other.replace(source)
        return os.read(fd, size)

    monkeypatch.setattr(rule_inventory, "os", module_os(
        open=open_owned, close=close_owned, read=read_owned))
    workspace = SimpleNamespace(root=root, confine_path=lambda value: str(source))
    with pytest.raises(AegisYAMLError, match="^Rule file read refused$") as refused:
        AegisYAML.parse_file("rule.md", workspace)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    assert changes == ["source"]
    assert sorted(opened) == sorted(closed)
    for fd in set(opened):
        with pytest.raises(OSError):
            os.fstat(fd)
    source.unlink()
    os.link(path, source)
    assert AegisYAML.parse_file("rule.md", workspace).source_path == str(source)
    assert sorted(opened) == sorted(closed)


def test_rootless_relative_path_records_confined_source(tmp_path):
    root = make_store(tmp_path)
    rules = root / ".aegis/rules"
    (rules / "nested/child").mkdir(parents=True)
    (rules / "r.md").write_text(TEXT, encoding="utf-8")
    (rules / "nested/r.md").write_text(TEXT.replace("bounded", "different"), encoding="utf-8")
    symlink_or_skip(rules / "nested/child", rules / "link", target_is_directory=True)
    workspace = SimpleNamespace(confine_path=lambda value: str((root / value).resolve()))
    def read(_):
        document = AegisYAML.parse_file(".aegis/rules/link/../r.md", workspace)
        assert document.id == "different"
        assert document.source_path == str((rules / "nested/r.md").resolve())
        return document.body
    assert read(None) == "body"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(read, range(3), timeout=15)) == ["body"] * 3
    (rules / "link").unlink()
    (rules / "link").mkdir()
    retried = AegisYAML.parse_file(".aegis/rules/link/../r.md", workspace)
    assert retried.id == "bounded"
    assert retried.source_path == str((rules / "r.md").resolve())


@pytest.mark.parametrize("aliased", [False, True], ids=["plain", "parent-alias"])
def test_rootless_file_is_opened_once_and_closed(tmp_path, monkeypatch, aliased):
    root = make_store(tmp_path)
    parent = root / "actual"
    parent.mkdir()
    path = parent / "rule.md"
    path.write_text(TEXT, encoding="utf-8")
    if aliased:
        alias = root / "alias"
        symlink_or_skip(parent, alias, target_is_directory=True)
        path = alias / "rule.md"
    opened, closed, flags_seen = [], [], []

    def open_owned(name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        opened.append((name, kwargs.get("dir_fd"), fd))
        flags_seen.append(flags)
        return fd

    def close_owned(fd):
        closed.append(fd)
        os.close(fd)

    monkeypatch.setattr(rule_inventory, "os", module_os(
        o_path=False, open=open_owned, close=close_owned))
    for _ in range(2):
        start = len(opened)
        assert rule_inventory.read_rule_file(path) == TEXT.encode()
        calls = opened[start:]
        assert [(name, relative) for name, relative, fd in calls] == [(str(parent / "rule.md"), None)]
        assert flags_seen[-1] & os.O_NOFOLLOW
        assert flags_seen[-1] & os.O_NONBLOCK
        assert sorted(fd for name, relative, fd in opened) == sorted(closed)


def test_opaque_confiner_parent_alias_records_returned_source(tmp_path):
    root = make_store(tmp_path)
    parent = root / "actual"
    parent.mkdir()
    path = parent / "rule.md"
    path.write_text(TEXT, encoding="utf-8")
    alias = root / "alias"
    symlink_or_skip(parent, alias, target_is_directory=True)
    workspace = SimpleNamespace(confine_path=lambda value: str(alias / "rule.md"))
    for _ in range(2):
        document = AegisYAML.parse_file("rule.md", workspace)
        assert document.id == "bounded"
        assert document.source_path == str(alias / "rule.md")


def test_rootless_confiner_alias_keeps_permission_error_path(tmp_path):
    require_permissions()
    parent = tmp_path / "actual"
    parent.mkdir()
    path = parent / "rule.md"
    path.write_text(TEXT, encoding="utf-8")
    alias = tmp_path / "alias"
    symlink_or_skip(parent, alias, target_is_directory=True)
    supplied = alias / "rule.md"
    workspace = SimpleNamespace(confine_path=lambda value: str(supplied))
    original_mode = path.stat().st_mode
    try:
        path.chmod(0)
        try:
            supplied.read_text(encoding="utf-8")
        except PermissionError as exc:
            expected = (type(exc), str(exc), exc.errno, exc.filename)
        else:
            pytest.skip("platform does not enforce unreadable file permissions")
        with pytest.raises(PermissionError) as refused:
            AegisYAML.parse_file("rule.md", workspace)
        actual = refused.value
        assert (type(actual), str(actual), actual.errno, actual.filename) == expected
    finally:
        path.chmod(original_mode)
    document = AegisYAML.parse_file("rule.md", workspace)
    assert document.id == "bounded"
    assert document.source_path == str(supplied)


@pytest.mark.parametrize("entry", ALL_PATH_ENTRIES)
@pytest.mark.parametrize("o_path", [False, True], ids=["without-o-path", "with-o-path"])
def test_search_only_rule_parent_follows_root_contract(tmp_path, monkeypatch, entry, o_path):
    require_permissions()
    root = make_store(tmp_path)
    parent = root / ".aegis/rules"
    parent.mkdir(parents=True)
    path = parent / "rule.md"
    path.write_text(TEXT, encoding="utf-8")
    monkeypatch.setattr(rule_inventory, "os", module_os(o_path=o_path))
    original = parent.stat().st_mode
    try:
        parent.chmod(0o100)
        try:
            os.listdir(parent)
        except PermissionError:
            pass
        else:
            pytest.skip("platform does not enforce search-only directory permissions")
        assert path.read_text(encoding="utf-8") == TEXT

        def read(_):
            if entry == "AegisYAML.parse_file":
                expected = PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(path))
                with pytest.raises(PermissionError) as refused:
                    read_path_entry(entry, path, root)
                actual = refused.value
                assert type(actual) is PermissionError
                assert actual.filename == expected.filename
                assert str(actual) == str(expected)
            else:
                assert read_path_entry(entry, path, root)[0]["id"] == "bounded"
        read(None)
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(read, range(3), timeout=15)) == [None] * 3
        read(None)
    finally:
        parent.chmod(original)
    assert read_path_entry(entry, path, root)[0]["id"] == "bounded"


@pytest.mark.parametrize("entry", ALL_PATH_ENTRIES)
@pytest.mark.parametrize("spelling", ["dotdot", "dot", "separator", "all"])
def test_os_refusal_preserves_legacy_filename_spelling(tmp_path, entry, spelling):
    require_permissions()
    root = tmp_path / "workspace"
    path = root / ".aegis/rules/r.md"
    (path.parent / "d").mkdir(parents=True)
    path.write_text(TEXT, encoding="utf-8")
    relative = {
        "dotdot": ".aegis/rules/d/../r.md",
        "dot": ".aegis/rules/./r.md",
        "separator": ".aegis//rules//r.md",
        "all": ".aegis//rules/./d/../r.md",
    }[spelling]
    supplied = str(root) + "/" + relative
    if entry == "AegisYAML.parse_file":
        workspace = Workspace(root)
        expected_filename = str(Path(workspace.confine_path(relative)[0]))
        def parse():
            return AegisYAML.parse_file(relative, workspace).id
    elif entry == "AegisYAML.parse_file-rootless":
        workspace = SimpleNamespace(confine_path=lambda value: supplied)
        expected_filename = str(Path(supplied))
        def parse():
            return AegisYAML.parse_file(relative, workspace).id
    else:
        reader = parse_rule_file if entry == "parse_rule_file" else parse_rule_frontmatter
        expected_filename = supplied
        def parse():
            return reader(supplied)[0]["id"]
    original = path.stat().st_mode
    try:
        path.chmod(0)
        try:
            with open(expected_filename, "r", encoding="utf-8"):
                pass
        except PermissionError as error:
            expected = (type(error), str(error), error.errno, error.filename)
        else:
            pytest.skip("platform does not enforce unreadable file permissions")

        def refuse(_):
            with pytest.raises(PermissionError) as refused:
                parse()
            actual = refused.value
            assert (type(actual), str(actual), actual.errno, actual.filename) == expected
        refuse(None)
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(refuse, range(3), timeout=15)) == [None] * 3
        refuse(None)
    finally:
        path.chmod(original)
    assert parse() == "bounded"


@pytest.mark.parametrize("spelling,allowed", [
    ("./rule.md", True),
    ("d/../rule.md", True),
    ("d/./../rule.md", True),
    ("./d/.././rule.md", True),
    ("d/sub/./../../rule.md", True),
    ("../secret.md", False),
    ("./../secret.md", False),
    ("d/../../secret.md", False),
    ("d/./../../secret.md", False),
    ("./d/./.././../secret.md", False),
    ("d/sub/./../../../secret.md", False),
], ids=["dot", "parent", "mixed", "leading-mixed", "nested",
        "escape", "dot-escape", "parent-escape", "reported-escape", "mixed-escape", "nested-escape"])
def test_root_depth_refuses_escape_before_read(tmp_path, monkeypatch, spelling, allowed):
    root = tmp_path / "workspace"
    (root / "d/sub").mkdir(parents=True)
    (root / "rule.md").write_text(TEXT, encoding="utf-8")
    (tmp_path / "secret.md").write_text("outside", encoding="utf-8")
    path = str(root) + "/" + spelling
    if not allowed:
        monkeypatch.setattr(rule_inventory, "os", module_os(
            read=lambda *args: pytest.fail("root escape reached file read")))

    def read(_):
        if allowed:
            assert rule_inventory.read_rule_file(path, root=root) == TEXT.encode()
        else:
            with pytest.raises(rule_inventory.RuleInventoryError, match="^Rule file read refused$") as refused:
                rule_inventory.read_rule_file(path, root=root)
            assert refused.value.code == "RULE_FILE_READ_REFUSED"
    read(None)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(read, range(3), timeout=15)) == [None] * 3
    monkeypatch.setattr(rule_inventory, "os", os)
    assert rule_inventory.read_rule_file(root / "rule.md", root=root) == TEXT.encode()


def test_rooted_walk_retains_zero_depth_dot(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    (root / "d").mkdir()
    (root / "rule.md").write_text(TEXT, encoding="utf-8")
    names = []

    def open_owned(name, flags, *args, **kwargs):
        names.append(name)
        return os.open(name, flags, *args, **kwargs)

    monkeypatch.setattr(rule_inventory, "os", module_os(open=open_owned))
    assert rule_inventory.read_rule_file(str(root) + "/d/./../rule.md", root=root) == TEXT.encode()
    assert names == [str(root), "d", ".", "..", "rule.md"]


@pytest.mark.parametrize("spelling", ["d/./../rule.md", "d/.././rule.md", "./d/../rule.md"],
                         ids=["before-parent", "after-parent", "leading-dot"])
def test_rooted_dot_chains_never_erase_symlink(tmp_path, monkeypatch, spelling):
    root = make_store(tmp_path) / "workspace"
    root.mkdir()
    outside = tmp_path / "outside"
    (outside / "child").mkdir(parents=True)
    (outside / "rule.md").write_text("outside", encoding="utf-8")
    (root / "rule.md").write_text(TEXT, encoding="utf-8")
    symlink_or_skip(outside / "child", root / "d", target_is_directory=True)
    monkeypatch.setattr(rule_inventory, "os", module_os(
        read=lambda *args: pytest.fail("symlink component reached file read")))
    with pytest.raises(rule_inventory.RuleInventoryError, match="^Rule file read refused$") as refused:
        rule_inventory.read_rule_file(str(root) + "/" + spelling, root=root)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"
    monkeypatch.setattr(rule_inventory, "os", os)
    (root / "d").unlink()
    (root / "d").mkdir()
    assert rule_inventory.read_rule_file(str(root) + "/" + spelling, root=root) == TEXT.encode()


@pytest.mark.parametrize("entry", ["parse_rule_frontmatter", "parse_rule_file", "AegisYAML.parse_file"])
@pytest.mark.parametrize("outside", [False, True], ids=["inside", "outside"])
def test_final_symlink_is_unfollowed_at_enforced_boundary(tmp_path, monkeypatch, entry, outside):
    root = make_store(tmp_path) / "workspace"
    parent = root / ".aegis/rules"
    parent.mkdir(parents=True)
    target = (tmp_path if outside else root) / "secret.md"
    target.write_text(TEXT.replace("bounded", "secret"), encoding="utf-8")
    path = parent / "link.md"
    symlink_or_skip(target, path)
    workspace = SimpleNamespace(root=root, confine_path=lambda value: str((root / value).resolve()))
    monkeypatch.setattr(rule_inventory, "os", module_os(
        read=lambda *args: pytest.fail("final symlink reached file read")))
    error = RuleParseError if entry == "parse_rule_file" else AegisYAMLError
    message = f"Symlink parsing prohibited for security: {path}" if entry == "AegisYAML.parse_file" else "Rule file read refused"
    with pytest.raises(error) as refused:
        if entry == "AegisYAML.parse_file":
            AegisYAML.parse_file(".aegis/rules/link.md", workspace)
        else:
            read_path_entry(entry, path, root)
    assert str(refused.value) == message
    assert getattr(refused.value, "code", None) == (None if entry == "AegisYAML.parse_file" else "RULE_FILE_READ_REFUSED")
    monkeypatch.setattr(rule_inventory, "os", os)
    path.unlink()
    path.write_text(TEXT, encoding="utf-8")
    if entry == "AegisYAML.parse_file":
        document = AegisYAML.parse_file(".aegis/rules/link.md", workspace)
        assert document.id == "bounded"
        assert document.source_path == str(path)
    else:
        assert read_path_entry(entry, path, root)[0]["id"] == "bounded"


def root_aware_adapter(root, binding):
    workspace = Workspace(root)
    if binding == "workspace":
        return workspace
    if binding == "bound":
        return SimpleNamespace(confine_path=workspace.confine_path)
    return SimpleNamespace(root=root, confine_path=lambda value: str((root / value).resolve()))


@pytest.mark.parametrize("relative", ["r.md", "sub/r.md"], ids=["at-root", "subdirectory"])
@pytest.mark.parametrize("binding", ["workspace", "bound", "root-attribute"])
def test_root_aware_file_only_confiner_parses_regular_rule(tmp_path, relative, binding):
    confinement = tmp_path / ".aegis/rules"
    path = confinement / relative
    path.parent.mkdir(parents=True)
    path.write_text(TEXT, encoding="utf-8")
    adapter = root_aware_adapter(confinement, binding)
    for _ in range(2):
        document = AegisYAML.parse_file(relative, adapter)
        assert document.id == "bounded"
        assert document.source_path == str(path.resolve())


@pytest.mark.parametrize("tuple_result", [False, True], ids=["string", "tuple"])
def test_file_only_confiner_receives_only_original_rule_query(tmp_path, tuple_result):
    path = tmp_path / "selected/r.md"
    path.parent.mkdir()
    path.write_text(TEXT, encoding="utf-8")
    queries = []

    def confine(value):
        queries.append(str(value))
        resolved = str(path.resolve())
        return (resolved, "r.md") if tuple_result else resolved

    adapter = SimpleNamespace(confine_path=confine)
    document = AegisYAML.parse_file("r.md", adapter)
    assert document.id == "bounded"
    assert document.source_path == str(path)
    assert queries == ["r.md"]


@pytest.mark.parametrize("tuple_result", [False, True], ids=["string", "tuple"])
@pytest.mark.parametrize("outside", [False, True], ids=["inside", "outside"])
def test_opaque_file_only_confiner_owns_resolution(tmp_path, tuple_result, outside):
    root = make_store(tmp_path) / "workspace"
    parent = root / ".aegis/rules"
    parent.mkdir(parents=True)
    target = (tmp_path / "outside" if outside else root / "selected") / "r.md"
    target.parent.mkdir()
    target.write_text(TEXT.replace("bounded", "secret"), encoding="utf-8")
    original = parent / "r.md"
    symlink_or_skip(target, original)

    def confine(value):
        resolved = str(original.resolve())
        return (resolved, "r.md") if tuple_result else resolved

    adapter = SimpleNamespace(confine_path=confine)
    document = AegisYAML.parse_file("r.md", adapter)
    assert document.id == "secret"
    assert document.source_path == str(target)
    original.unlink()
    original.write_text(TEXT, encoding="utf-8")
    document = AegisYAML.parse_file("r.md", adapter)
    assert document.id == "bounded"
    assert document.source_path == str(original)


@pytest.mark.parametrize("binding", ["workspace", "bound", "root-attribute"])
@pytest.mark.parametrize("outside", [False, True], ids=["inside", "outside"])
def test_root_aware_same_basename_symlink_is_refused(tmp_path, monkeypatch, binding, outside):
    root = make_store(tmp_path) / "rules"
    root.mkdir()
    target = (tmp_path / "outside" if outside else root / "selected") / "r.md"
    target.parent.mkdir()
    target.write_text(TEXT.replace("bounded", "secret"), encoding="utf-8")
    original = root / "r.md"
    original.write_text(TEXT, encoding="utf-8")
    adapter = root_aware_adapter(root, binding)
    assert AegisYAML.parse_file("r.md", adapter).id == "bounded"
    original.unlink()
    symlink_or_skip(target, original)
    monkeypatch.setattr(rule_inventory, "os", module_os(
        read=lambda *args: pytest.fail("rooted final symlink reached file read")))
    with pytest.raises(AegisYAMLError, match="Symlink parsing prohibited"):
        AegisYAML.parse_file("r.md", adapter)
    monkeypatch.setattr(rule_inventory, "os", os)
    original.unlink()
    original.write_text(TEXT, encoding="utf-8")
    assert AegisYAML.parse_file("r.md", adapter).id == "bounded"


@pytest.mark.parametrize("tuple_result", [False, True], ids=["string", "tuple"])
def test_opaque_returned_symlink_is_refused(tmp_path, tuple_result):
    root = tmp_path / "rules"
    root.mkdir()
    target = root / "target.md"
    target.write_text(TEXT, encoding="utf-8")
    returned = root / "r.md"
    symlink_or_skip(target, returned)
    queries = []

    def confine(value):
        queries.append(str(value))
        return (str(returned), "unused") if tuple_result else str(returned)

    adapter = SimpleNamespace(confine_path=confine)
    with pytest.raises(AegisYAMLError) as refused:
        AegisYAML.parse_file("r.md", adapter)
    assert str(refused.value) == f"Symlink parsing prohibited for security: {returned}"
    assert queries == ["r.md"]
    returned.unlink()
    returned.write_text(TEXT, encoding="utf-8")
    assert AegisYAML.parse_file("r.md", adapter).id == "bounded"


@pytest.mark.parametrize("tuple_result", [False, True], ids=["string", "tuple"])
@pytest.mark.parametrize("redundant", [False, True], ids=["plain", "redundant"])
def test_opaque_opens_exact_returned_path_once(tmp_path, monkeypatch, tuple_result, redundant):
    root = make_store(tmp_path)
    selected = root / "chosen/selected.md"
    selected.parent.mkdir()
    selected.write_text(TEXT, encoding="utf-8")
    returned = str(root) + "/chosen/./../chosen//selected.md" if redundant else str(selected)
    queries, opened, closed = [], [], []

    def confine(value):
        queries.append(str(value))
        return (returned, "unused") if tuple_result else returned

    def open_owned(name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        opened.append((name, kwargs.get("dir_fd"), fd))
        return fd

    def close_owned(fd):
        closed.append(fd)
        os.close(fd)

    monkeypatch.setattr(rule_inventory, "os", module_os(open=open_owned, close=close_owned))
    document = AegisYAML.parse_file("original.md", SimpleNamespace(confine_path=confine))
    assert document.id == "bounded"
    assert document.source_path == returned
    assert queries == ["original.md"]
    assert [(name, parent) for name, parent, fd in opened] == [(returned, None)]
    assert sorted(fd for name, parent, fd in opened) == sorted(closed)


@pytest.mark.parametrize("binding", ["workspace", "bound", "root-attribute"])
def test_exposed_root_never_downgrades_after_symlink_swap(tmp_path, monkeypatch, binding):
    root = make_store(tmp_path) / "rules"
    root.mkdir()
    (root / "r.md").write_text(TEXT, encoding="utf-8")
    adapter = root_aware_adapter(root, binding)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "r.md").write_text(TEXT.replace("bounded", "secret"), encoding="utf-8")
    root.rename(tmp_path / "old-rules")
    symlink_or_skip(outside, root, target_is_directory=True)
    monkeypatch.setattr(rule_inventory, "os", module_os(
        read=lambda *args: pytest.fail("root replacement reached file read")))
    with pytest.raises(AegisYAMLError, match="^Rule file read refused$") as refused:
        AegisYAML.parse_file("r.md", adapter)
    assert refused.value.code == "RULE_FILE_READ_REFUSED"


def test_frontmatter_zero_width_tables_agree():
    from aegis_core.yaml_engine.parser import ZERO_WIDTH_CHARS

    assert rule_inventory.ZERO_WIDTH_CHARS == ZERO_WIDTH_CHARS


@pytest.mark.parametrize("prefix", ["\ufeff", "\u200b", "\u200c", "\u200d"],
                         ids=["bom", "space", "non-joiner", "joiner"])
def test_frontmatter_zero_width_prefix_keeps_classification_and_content(prefix):
    content = prefix + TEXT
    assert rule_inventory.classification_prefix(content.encode("utf-8")) == (prefix + "---\nid: bounded\n---\n").encode("utf-8")
    assert rule_inventory.split_frontmatter(content) == ("ok", "id: bounded\n", "\nbody\n")
    assert parse_rule_frontmatter(content) == ({"id": "bounded"}, "body\n")
    assert AegisYAML.parse_text(content).id == "bounded"
