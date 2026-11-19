"""Rule path readers refuse unsafe inputs before reading or parsing them."""
from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import errno
import os
from pathlib import Path
import signal
from types import SimpleNamespace

import pytest

from aegis_core.errors import PathTraversalError, RuleNotFoundError, RuleParseError
from aegis_core.rule_inventory import MAX_RULE_BYTES
from aegis_core.workspace.base import Workspace
from aegis_core.yaml_engine.frontmatter import (
    AegisYAML, parse_rule_file, parse_rule_frontmatter,
)
from aegis_core.yaml_engine.parser import AegisYAMLError
from tests.conftest import symlink_or_skip
from aegis_core import rule_inventory


TEXT = "---\nid: bounded\n---\nbody\n"
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
        path=os.path, stat=os.stat, fstat=os.fstat,
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
        with pytest.raises(RuleInventoryError, match="^Rule file read refused$") as refused:
            read_rule_file(path, **kwargs)
        assert refused.value.code == ("RULE_FILE_NOT_FOUND" if kind == "missing" else "RULE_FILE_READ_REFUSED")


def test_facade_unsupported_probe_keeps_inventory_fallback(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import read_rule_file

    path = tmp_path / "rule.md"
    path.write_bytes(b"---\r\nid: bounded\r\n---\r\nbody\x1a\r\n")
    monkeypatch.setattr(rule_inventory, "descriptor_supported", lambda: False)
    assert read_rule_file(path, root=tmp_path) == path.read_bytes()


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
    with pytest.raises(RuleInventoryError, match="^Rule file read refused$"):
        read_rule_file(path)


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
    assert planned.skipped == [{"path": ".aegis/rules/traps/rule.md", "reason": "Rule file read refused"}]
    path.write_text(text, encoding="utf-8")
    retried = migrate.plan(tmp_path)
    assert not retried.skipped
    assert len(retried.strips) == 1


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
