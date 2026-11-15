"""No file under tests/ contains a credential-shaped literal.

Tests build scanner-shaped inputs at runtime from split parts. The only
permitted literal is the documented AWS example key in ALLOWLIST. Reports
name file:line, match length and a short hash. They never include the match.
"""
from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import pytest

from conftest import symlink_or_skip


# Documented AWS general-reference example. Not a live credential.
_AWS_EXAMPLE = b"AKIAIOSFODNN7EXAMPLE"
ALLOWLIST = frozenset((_AWS_EXAMPLE,))

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REPORT_CHARS = 160
_DIGEST_CHARS = 12
_PATTERN_PARTS = (
    ("google", ("AIza", r"[0-9A-Za-z_\-]{35}")),
    ("github", ("gh", r"[pousr]_", r"[0-9A-Za-z]{36}")),
    ("slack", ("xox", r"[abpr]-", r"[0-9A-Za-z\-]{10,}")),
    ("anthropic", ("sk-", "ant-", r"[0-9A-Za-z_\-]{20,}")),
    ("aws", ("AK", "IA", r"[0-9A-Z]{16}")),
    ("private-key", ("-----BEGIN ", r"[A-Z ]*PRIVATE KEY-----")),
)
PATTERNS = tuple(
    (name, re.compile("".join(parts).encode("ascii"))) for name, parts in _PATTERN_PARTS)
_KINDS = tuple(name for name, _pattern in PATTERNS)
REFUSALS = frozenset(("limit", "oversize", "unreadable", "symlink", "irregular", "multiline"))
_REDACTED = b"[REDACTED]"
REPO_TESTS = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    length: int
    digest: str

    def report(self) -> str:
        return "%s:%s %s len=%s sha256=%s" % (
            self.path, self.line, self.kind, self.length, self.digest)


@dataclass(frozen=True)
class ScanResult:
    refusal: Optional[str]
    findings: Tuple[Finding, ...]

    def public_text(self) -> str:
        if self.refusal is not None:
            return self.refusal if self.refusal in REFUSALS else "unreadable"
        lines = []
        for finding in self.findings:
            line = finding.report()
            if "\n" in line or "\r" in line or "\x00" in line:
                return "multiline"
            lines.append(line)
        return "\n".join(lines)


def _refusal(code: str) -> str:
    return code if code in REFUSALS else "unreadable"


def _redact(text: str) -> str:
    raw = text.encode("utf-8", "surrogateescape")
    for _name, pattern in PATTERNS:
        raw = pattern.sub(_REDACTED, raw)
    return raw.decode("utf-8", "surrogateescape")


def _public_path_text(text: str):
    """Canonicalize, then redact, then truncate. Multi-line text is refused."""
    canonical = unicodedata.normalize("NFC", text.replace("\\", "/"))
    if canonical.startswith("../") or canonical == ".." or canonical.startswith("/"):
        return None, "irregular"
    if "\n" in canonical or "\r" in canonical or "\x00" in canonical:
        return None, "multiline"
    redacted = _redact(canonical)
    if len(redacted) > MAX_REPORT_CHARS:
        redacted = redacted[:MAX_REPORT_CHARS]
    return redacted, None


def _public_path(root: str, path: str):
    try:
        relative = os.path.relpath(path, root)
    except ValueError:
        return None, "irregular"
    return _public_path_text(Path(relative).as_posix())


def _read_capped(path: str, max_bytes: int):
    if type(max_bytes) is not int or max_bytes < 1 or max_bytes > MAX_FILE_BYTES:
        return None, "limit"
    try:
        with open(path, "rb") as handle:
            return handle.read(max_bytes + 1), None
    except OSError:
        return None, "unreadable"


def _descriptor_opens_supported():
    """POSIX openat is available. Tests replace this module function, not os.open."""
    if os.name != "posix":
        return False
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
        return False
    supports = getattr(os, "supports_dir_fd", ())
    return os.open in supports and os.stat in supports


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        return None
    return None


def _open_refusal(exc):
    err = getattr(exc, "errno", None)
    if err == errno.ELOOP:
        return "symlink"
    if err in (errno.ENOTDIR, errno.ENXIO):
        return "irregular"
    return "unreadable"


def _directory_flags(nofollow):
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if nofollow:
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags():
    return (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))


def _collect(data, public, findings) -> Optional[str]:
    """One forward newline pass. Each match pays only for the gap since the previous one."""
    located = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(data):
            raw = match.group(0)
            if raw in ALLOWLIST:
                continue
            located.append((match.start(), kind, raw))
    located.sort()
    line = 1
    cursor = 0
    for start, kind, raw in located:
        while cursor < start:
            newline = data.find(b"\n", cursor, start)
            if newline < 0:
                cursor = start
                break
            line += 1
            cursor = newline + 1
        findings.append(Finding(
            public,
            line,
            kind,
            len(raw),
            hashlib.sha256(raw).hexdigest()[:_DIGEST_CHARS],
        ))
    return None


def _scan_file(path, root, max_bytes, read_file, stat_file, findings) -> Optional[str]:
    try:
        info = stat_file(path)
    except OSError:
        return "unreadable"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if not stat.S_ISREG(info.st_mode):
        return "irregular"
    if info.st_size > max_bytes:
        return "oversize"
    try:
        data, code = read_file(path, max_bytes)
    except OSError:
        return "unreadable"
    if code:
        return _refusal(code)
    if not isinstance(data, (bytes, bytearray)):
        return "unreadable"
    if len(data) > max_bytes:
        return "oversize"
    public, path_code = _public_path(root, path)
    if path_code:
        return path_code
    return _collect(data, public, findings)


def _scan_tree(directory, root, max_bytes, read_file, stat_file, findings) -> Optional[str]:
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return "unreadable"
    cache_dir = os.path.basename(os.fspath(directory)) == "__pycache__"
    for entry in entries:
        try:
            linked = entry.is_symlink()
            is_dir = entry.is_dir(follow_symlinks=False)
            is_file = entry.is_file(follow_symlinks=False)
        except OSError:
            return "unreadable"
        if linked:
            return "symlink"
        if is_dir:
            code = _scan_tree(entry.path, root, max_bytes, read_file, stat_file, findings)
            if code:
                return code
            continue
        if not is_file:
            return "irregular"
        if cache_dir and entry.name.endswith(".pyc"):
            continue
        code = _scan_file(entry.path, root, max_bytes, read_file, stat_file, findings)
        if code:
            return code
    return None


def _read_at(dir_fd, name, max_bytes):
    """Open name relative to dir_fd. O_NOFOLLOW refuses a swapped symlink; O_NONBLOCK refuses a FIFO."""
    try:
        fd = os.open(name, _file_flags(), dir_fd=dir_fd)
    except OSError as exc:
        return None, _open_refusal(exc)
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            return None, "unreadable"
        if stat.S_ISLNK(info.st_mode):
            return None, "symlink"
        if not stat.S_ISREG(info.st_mode):
            return None, "irregular"
        if info.st_size > max_bytes:
            return None, "oversize"
        try:
            os.set_blocking(fd, True)
        except OSError:
            return None, "unreadable"
        try:
            handle = os.fdopen(fd, "rb", closefd=False)
        except Exception:
            return None, "unreadable"
        try:
            try:
                data = handle.read(max_bytes + 1)
            except OSError:
                return None, "unreadable"
        finally:
            handle.close()
        if not isinstance(data, (bytes, bytearray)) or len(data) > max_bytes:
            return None, "oversize" if isinstance(data, (bytes, bytearray)) else "unreadable"
        return data, None
    finally:
        _close(fd)


def _open_directory(name, parent_fd):
    try:
        if parent_fd is None:
            fd = os.open(name, _directory_flags(True))
        else:
            fd = os.open(name, _directory_flags(True), dir_fd=parent_fd)
    except OSError as exc:
        return None, _open_refusal(exc)
    try:
        info = os.fstat(fd)
    except OSError:
        _close(fd)
        return None, "unreadable"
    if stat.S_ISLNK(info.st_mode):
        _close(fd)
        return None, "symlink"
    if not stat.S_ISDIR(info.st_mode):
        _close(fd)
        return None, "irregular"
    return fd, None


def _scan_directory(dir_fd, relative, in_cache, max_bytes, findings) -> Optional[str]:
    try:
        iterator = os.scandir(dir_fd)
    except OSError:
        return "unreadable"
    try:
        try:
            entries = list(iterator)
        except OSError:
            return "unreadable"
    finally:
        iterator.close()
    for entry in entries:
        name = entry.name
        if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
            return "irregular"
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return "unreadable"
        if stat.S_ISLNK(info.st_mode):
            return "symlink"
        if "\n" in name or "\r" in name:
            return "multiline"
        child = name if not relative else relative + "/" + name
        if stat.S_ISDIR(info.st_mode):
            nested, code = _open_directory(name, dir_fd)
            if code:
                return code
            try:
                code = _scan_directory(nested, child, name == "__pycache__", max_bytes, findings)
            finally:
                _close(nested)
            if code:
                return code
            continue
        if not stat.S_ISREG(info.st_mode):
            return "irregular"
        if in_cache and name.endswith(".pyc"):
            continue
        if info.st_size > max_bytes:
            return "oversize"
        public, path_code = _public_path_text(child)
        if path_code:
            return path_code
        data, code = _read_at(dir_fd, name, max_bytes)
        if code:
            return code
        code = _collect(data, public, findings)
        if code:
            return code
    return None


def _scan_anchored(root, max_bytes) -> ScanResult:
    """Walk from a directory descriptor. Child opens are relative and no-follow."""
    path = os.fspath(root)
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    while len(path) > 1 and path.endswith(("/", "\\")):
        path = path[:-1]
    parent, name = os.path.split(path)
    parent_fd = None
    root_fd = None
    try:
        if not parent:
            parent_fd = None
        else:
            try:
                parent_fd = os.open(parent if parent else ".", _directory_flags(False))
            except OSError:
                return ScanResult("unreadable", ())
        try:
            if parent_fd is None:
                info = os.lstat(path)
            else:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return ScanResult("unreadable", ())
        if stat.S_ISLNK(info.st_mode):
            return ScanResult("symlink", ())
        findings = []
        if stat.S_ISDIR(info.st_mode):
            root_fd, code = _open_directory(path if parent_fd is None else name, parent_fd)
            if code:
                return ScanResult(code, ())
            code = _scan_directory(
                root_fd, "", os.path.basename(path) == "__pycache__", max_bytes, findings)
        elif stat.S_ISREG(info.st_mode):
            if info.st_size > max_bytes:
                return ScanResult("oversize", ())
            public, path_code = _public_path_text(name)
            if path_code:
                return ScanResult(path_code, ())
            if parent_fd is None:
                return ScanResult("unreadable", ())
            data, code = _read_at(parent_fd, name, max_bytes)
            if code:
                return ScanResult(code, ())
            code = _collect(data, public, findings)
        else:
            code = "irregular"
        if code:
            return ScanResult(_refusal(code), ())
        findings.sort(key=lambda item: (item.path, item.line, item.kind, item.digest, item.length))
        return ScanResult(None, tuple(findings))
    except OSError:
        return ScanResult("unreadable", ())
    finally:
        if root_fd is not None:
            _close(root_fd)
        if parent_fd is not None:
            _close(parent_fd)


def scan(root, max_bytes=MAX_FILE_BYTES, read_file=None, stat_file=None) -> ScanResult:
    """Scan source bytes under root. A refusal is a code, never an exception."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FILE_BYTES:
        return ScanResult("limit", ())
    if read_file is None and stat_file is None and _descriptor_opens_supported():
        return _scan_anchored(root, max_bytes)
    reader = _read_capped if read_file is None else read_file
    stater = os.lstat if stat_file is None else stat_file
    try:
        info = stater(os.fspath(root))
    except OSError:
        return ScanResult("unreadable", ())
    if stat.S_ISLNK(info.st_mode):
        return ScanResult("symlink", ())
    findings = []
    target = os.fspath(root)
    if stat.S_ISREG(info.st_mode):
        code = _scan_file(target, os.path.dirname(target) or ".", max_bytes, reader, stater, findings)
    elif stat.S_ISDIR(info.st_mode):
        code = _scan_tree(target, target, max_bytes, reader, stater, findings)
    else:
        code = "irregular"
    if code:
        return ScanResult(_refusal(code), ())
    findings.sort(key=lambda item: (item.path, item.line, item.kind, item.digest, item.length))
    return ScanResult(None, tuple(findings))


def _planted(kind: str) -> str:
    if kind == "google":
        return "AIza" + "Sy" + "x" * 33
    if kind == "github":
        return "gh" + "p_" + "b" * 36
    if kind == "slack":
        return "xox" + "b-" + "c" * 10
    if kind == "anthropic":
        return "sk-" + "ant-" + "d" * 20
    if kind == "aws":
        return "AK" + "IA" + "E" * 16
    if kind == "private-key":
        return "-----BEGIN " + "PRIVATE KEY-----"
    raise AssertionError(kind)


def _composed_source(kind: str) -> str:
    parts = {
        "google": '"AIza" + "Sy" + "x" * 33',
        "github": '"gh" + "p_" + "b" * 36',
        "slack": '"xox" + "b-" + "c" * 10',
        "anthropic": '"sk-" + "ant-" + "d" * 20',
        "aws": '"AK" + "IA" + "E" * 16',
        "private-key": '"-----BEGIN " + "PRIVATE KEY-----"',
    }
    return parts[kind] + "\n"


def _assert_hidden(text: str, secret: str) -> None:
    leaked = secret in text
    assert leaked is False


@pytest.mark.parametrize("kind", _KINDS)
def test_planted_pattern_is_detected_without_echoing_the_value(tmp_path, kind):
    secret = _planted(kind)
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))
    result = scan(tmp_path)
    assert result.refusal is None
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.kind == kind
    assert finding.path == "plant.txt"
    assert finding.line == 1
    assert finding.length == len(secret.encode("ascii"))
    assert finding.digest == hashlib.sha256(secret.encode("ascii")).hexdigest()[:_DIGEST_CHARS]
    _assert_hidden(result.public_text(), secret)
    _assert_hidden(repr(result), secret)


@pytest.mark.parametrize("kind", _KINDS)
def test_runtime_composition_is_not_detected(tmp_path, kind):
    composed = tmp_path / "composed"
    composed.mkdir()
    (composed / "parts.py").write_text(_composed_source(kind), encoding="utf-8")
    hidden = scan(composed)
    assert hidden.refusal is None and hidden.findings == ()
    secret = _planted(kind)
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "plant.txt").write_bytes(secret.encode("ascii"))
    found = scan(raw)
    assert len(found.findings) == 1 and found.findings[0].kind == kind
    _assert_hidden(found.public_text(), secret)


def test_allowlisted_aws_example_is_not_detected(tmp_path):
    example = _AWS_EXAMPLE.decode("ascii")
    (tmp_path / "example.txt").write_bytes(_AWS_EXAMPLE + b"\n")
    result = scan(tmp_path)
    assert result.refusal is None and result.findings == ()
    _assert_hidden(result.public_text(), example)
    other = tmp_path / "other"
    other.mkdir()
    shaped = "AK" + "IA" + "E" * 16
    (other / "plant.txt").write_bytes(shaped.encode("ascii"))
    detected = scan(other)
    assert len(detected.findings) == 1 and detected.findings[0].kind == "aws"
    _assert_hidden(detected.public_text(), shaped)


def _require_clean(result) -> None:
    assert result.refusal is None
    report = result.public_text()
    if report:
        pytest.fail(report)


def test_tests_tree_has_no_credential_literals():
    _require_clean(scan(REPO_TESTS))


def test_oversize_refuses_before_read(tmp_path):
    secret = _planted("github")
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))
    opened = []

    def reader(path, max_bytes):
        opened.append(path)
        return secret.encode("ascii"), None

    result = scan(tmp_path, max_bytes=4, read_file=reader)
    assert result.refusal == "oversize"
    assert opened == []
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_growth_past_the_cap_is_not_parsed(tmp_path):
    secret = _planted("google")
    (tmp_path / "plant.txt").write_bytes(b"ok")

    def reader(path, max_bytes):
        return secret.encode("ascii") + b"X", None

    result = scan(tmp_path, max_bytes=len(secret.encode("ascii")), read_file=reader)
    assert result.refusal == "oversize"
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_bad_limit_refuses_before_the_tree_is_touched(tmp_path):
    missing = tmp_path / "missing"
    for bad in (0, -1, MAX_FILE_BYTES + 1, True, False):
        result = scan(missing, max_bytes=bad)
        assert result.refusal == "limit"
        assert result.findings == ()
        assert result.public_text() == "limit"


def test_stat_failure_returns_unreadable_without_echoing_the_error(tmp_path):
    secret = _planted("slack")
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))

    def broken(path):
        raise OSError(13, "Permission denied", secret)

    result = scan(tmp_path, stat_file=broken)
    assert result.refusal == "unreadable"
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_reader_text_is_not_echoed(tmp_path):
    secret = _planted("anthropic")
    (tmp_path / "plant.txt").write_bytes(b"x")

    def reader(path, max_bytes):
        return secret.encode("ascii"), secret

    result = scan(tmp_path, read_file=reader)
    assert result.refusal == "unreadable"
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_reader_error_returns_unreadable(tmp_path):
    (tmp_path / "plant.txt").write_bytes(b"x")

    def reader(path, max_bytes):
        raise OSError(5, "Input/output error")

    result = scan(tmp_path, read_file=reader)
    assert result.refusal == "unreadable"
    assert result.public_text() == "unreadable"


def test_missing_path_returns_unreadable(tmp_path):
    result = scan(tmp_path / "missing.txt")
    assert result.refusal == "unreadable"
    assert result.findings == ()
    assert result.public_text() == "unreadable"


def test_symlink_probe_refuses_before_open(tmp_path):
    secret = _planted("private-key")
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))
    opened = []

    def reader(path, max_bytes):
        opened.append(True)
        return secret.encode("ascii"), None

    def link_stat(path):
        if str(path).endswith("plant.txt"):
            return os.stat_result((stat.S_IFLNK, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        return os.lstat(path)

    result = scan(tmp_path, read_file=reader, stat_file=link_stat)
    assert result.refusal == "symlink"
    assert opened == []
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_real_symlink_is_not_followed(tmp_path):
    secret = _planted("google")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(secret.encode("ascii"))
    linked = tmp_path / "linked"
    linked.mkdir()
    symlink_or_skip(outside / "secret.txt", linked / secret)
    result = scan(linked)
    assert result.refusal == "symlink"
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def test_multiline_path_is_refused_not_joined():
    secret = _planted("slack")
    text, code = _public_path_text("dir/" + secret + "\nnext")
    assert code == "multiline"
    assert text is None
    rendered = "multiline"
    joined = "dir/" + secret + " next"
    assert rendered == "multiline"
    leaked = secret in rendered or joined in rendered
    assert leaked is False


def test_report_path_is_canonicalized_then_redacted_then_truncated():
    secret = _planted("google")
    raw = "cafe\u0301/" + ("n" * 145) + secret + "/tail"
    text, code = _public_path_text(raw)
    assert code is None
    assert text.startswith("caf\u00e9/")
    assert text.endswith("[REDACTED]")
    assert len(text) == MAX_REPORT_CHARS
    leaked = secret[:10] in text
    assert leaked is False


def test_rescan_and_concurrent_scans_agree(tmp_path):
    secret = _planted("aws")
    path = tmp_path / "plant.txt"
    path.write_bytes(secret.encode("ascii"))
    first = scan(tmp_path)
    assert first.refusal is None and len(first.findings) == 1
    assert scan(tmp_path) == first
    path.write_bytes(b"clean\n")
    cleared = scan(tmp_path)
    assert cleared.refusal is None and cleared.findings == ()
    path.write_bytes(secret.encode("ascii"))
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _index: scan(tmp_path), range(3)))
    assert results == [first, first, first]
    _assert_hidden(first.public_text(), secret)


def test_read_of_a_missing_file_returns_unreadable_without_raising(tmp_path):
    data, code = _read_capped(os.fspath(tmp_path / "gone.txt"), MAX_FILE_BYTES)
    assert data is None and code == "unreadable"


def test_non_regular_probe_refuses_before_open(tmp_path):
    secret = _planted("github")
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))
    opened = []

    def reader(path, max_bytes):
        opened.append(True)
        return secret.encode("ascii"), None

    def fifo_stat(path):
        if str(path).endswith("plant.txt"):
            return os.stat_result((stat.S_IFIFO, 0, 0, 1, 0, 0, 1, 0, 0, 0))
        return os.lstat(path)

    result = scan(tmp_path, read_file=reader, stat_file=fifo_stat)
    assert result.refusal == "irregular"
    assert opened == []
    _assert_hidden(result.public_text(), secret)


def test_pycache_sources_are_scanned_and_bytecode_is_skipped(tmp_path):
    secret = _planted("github")
    payload = secret.encode("ascii")
    nested = tmp_path / "data" / "__pycache__"
    nested.mkdir(parents=True)
    (nested / "fixture.txt").write_bytes(payload)
    (nested / "mod.pyc").write_bytes(payload)
    (tmp_path / "__pycache__").write_bytes(payload)
    result = scan(tmp_path)
    assert result.refusal is None
    paths = {item.path for item in result.findings}
    assert paths == {"data/__pycache__/fixture.txt", "__pycache__"}
    assert all(item.line == 1 and item.kind == "github" for item in result.findings)
    _assert_hidden(result.public_text(), secret)


def test_line_numbers_advance_once_across_many_matches(tmp_path):
    token = ("AK" + "IA" + "E" * 16).encode("ascii")
    payload = (token + b"\n") * 800
    path = tmp_path / "many.txt"
    path.write_bytes(payload)
    examined = [0]

    class _Budget(bytes):
        def count(self, sub, start=None, end=None):
            lo = 0 if start is None else start
            hi = len(self) if end is None else end
            examined[0] += max(0, hi - lo)
            if start is None:
                return bytes.count(self, sub)
            if end is None:
                return bytes.count(self, sub, start)
            return bytes.count(self, sub, start, end)

        def find(self, sub, start=0, end=None):
            hi = len(self) if end is None else end
            examined[0] += max(0, hi - start)
            if end is None:
                return bytes.find(self, sub, start)
            return bytes.find(self, sub, start, end)

    def reader(file_path, max_bytes):
        return _Budget(payload), None

    result = scan(tmp_path, read_file=reader)
    assert result.refusal is None
    assert [item.line for item in result.findings] == list(range(1, 801))
    budget, width = examined[0], len(payload)
    assert 0 < budget <= width
    _assert_hidden(result.public_text(), token.decode("ascii"))


def test_gate_failure_names_every_planted_file_without_the_secret(tmp_path):
    first = _planted("aws")
    second = _planted("slack")
    (tmp_path / "a.txt").write_bytes(first.encode("ascii"))
    (tmp_path / "b.txt").write_bytes(second.encode("ascii"))
    with pytest.raises(pytest.fail.Exception) as caught:
        _require_clean(scan(tmp_path))
    message = str(caught.value)
    assert "a.txt:1" in message and "b.txt:1" in message
    assert "len=" in message and "sha256=" in message
    _assert_hidden(message, first)
    _assert_hidden(message, second)


def test_pycache_symlink_is_refused_before_any_name_skip(tmp_path):
    secret = _planted("github")
    payload = secret.encode("ascii")
    real = tmp_path / "real"
    real.mkdir()
    (real / "fixture.txt").write_bytes(payload)
    linked = tmp_path / "linked"
    linked.mkdir()
    symlink_or_skip(real, linked / "__pycache__", target_is_directory=True)
    named = scan(linked)
    assert named.refusal == "symlink"
    assert named.findings == ()
    _assert_hidden(named.public_text(), secret)
    package = tmp_path / "pkg"
    cache = package / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "fixture.txt").write_bytes(b"clean\n")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(payload)
    symlink_or_skip(outside, cache / "mod.pyc")
    bytecode = scan(package)
    assert bytecode.refusal == "symlink"
    assert bytecode.findings == ()
    _assert_hidden(bytecode.public_text(), secret)


def test_symlinked_directory_is_not_followed(tmp_path):
    secret = _planted("slack")
    real = tmp_path / "real"
    real.mkdir()
    (real / "secret.txt").write_bytes(secret.encode("ascii"))
    tree = tmp_path / "tree"
    tree.mkdir()
    symlink_or_skip(real, tree / "alias", target_is_directory=True)
    result = scan(tree)
    assert result.refusal == "symlink"
    assert result.findings == ()
    _assert_hidden(result.public_text(), secret)


def _scan_returned(root):
    found = []
    errors = []

    def run():
        try:
            found.append(scan(root))
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(5)
    blocked = worker.is_alive()
    assert blocked is False
    if errors:
        raise errors[0]
    assert len(found) == 1
    return found[0]


def test_fifo_leaf_is_refused_without_blocking(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is unavailable")
    secret = _planted("anthropic")
    folder = tmp_path / "folder"
    folder.mkdir()
    os.mkfifo(os.fspath(folder / "pipe"))
    result = _scan_returned(folder)
    assert result.refusal == "irregular"
    assert result.findings == ()
    assert result.public_text() == "irregular"
    _assert_hidden(result.public_text(), secret)
    _descriptors_unavailable.called = False
    monkeypatch.setattr(
        "tests.contract.test_no_credential_literals._descriptor_opens_supported",
        _descriptors_unavailable,
    )
    fallback = _scan_returned(folder)
    assert _descriptors_unavailable.called is True
    assert fallback.refusal == "irregular"
    assert fallback.findings == ()
    assert fallback.public_text() == "irregular"
    _assert_hidden(fallback.public_text(), secret)


def _descriptors_unavailable():
    _descriptors_unavailable.called = True
    return False


def test_pathname_fallback_classifies_when_descriptor_opens_are_unavailable(tmp_path, monkeypatch):
    _descriptors_unavailable.called = False
    monkeypatch.setattr(
        "tests.contract.test_no_credential_literals._descriptor_opens_supported",
        _descriptors_unavailable,
    )
    secret = _planted("aws")
    (tmp_path / "plant.txt").write_bytes(secret.encode("ascii"))
    found = scan(tmp_path)
    assert _descriptors_unavailable.called is True
    assert found.refusal is None and len(found.findings) == 1
    assert found.findings[0].path == "plant.txt"
    _assert_hidden(found.public_text(), secret)
    linked = tmp_path / "linked"
    linked.mkdir()
    symlink_or_skip(tmp_path / "plant.txt", linked / "alias.txt")
    refused = scan(linked)
    assert refused.refusal == "symlink"
    assert refused.findings == ()
    _assert_hidden(refused.public_text(), secret)


def test_descriptor_scan_closes_every_file_descriptor(tmp_path):
    if not os.path.isdir("/proc/self/fd") or not _descriptor_opens_supported():
        pytest.skip("descriptor accounting needs /proc/self/fd")
    nested = tmp_path / "data" / "__pycache__"
    nested.mkdir(parents=True)
    (nested / "fixture.txt").write_bytes(b"clean\n")
    (nested / "mod.pyc").write_bytes(b"\x00pyc")
    (tmp_path / "note.txt").write_bytes(b"clean\n")
    before = len(os.listdir("/proc/self/fd"))
    result = scan(tmp_path)
    after = len(os.listdir("/proc/self/fd"))
    assert result.refusal is None and result.findings == ()
    assert after == before
