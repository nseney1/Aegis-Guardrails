"""Model-free lane Git plumbing. No CLI, policy decisions, hooks or worktree writes.

The custodian supplies a trusted repository root and scratch parent (never a model
payload), and retains a GitStore until its objects have been consumed. Snapshots,
commits and planners write only into that store. Only cas_fast_forward publishes
objects and updates a ref; callers must journal that effect before calling it.
Unacknowledged writes are observed, never retried here. Qualification, lease and
identity authorization belong to the caller, not this low-level library.

Snapshots apply Git text conversions to descriptor-read bytes. External filters
(including LFS) refuse explicitly instead of executing configured programs. Unsupported descriptor platforms refuse snapshots, but can plan and
commit already supplied trees. Submodules and special files refuse explicitly.
All refusals have a stable code and a constant, input-free message. Conflict paths
are display-only, canonicalized, redacted, then truncated; never use them as paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
import errno
import codecs
import hashlib
import os
from pathlib import Path
import re
import stat
import zlib
from threading import Lock
from typing import Optional, Sequence, Tuple, Union

from aegis_core import gitsafe, gitsafe_run
from aegis_core.errors import AegisError
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.workspace.git_objects import object_id

__all__ = ["CommitIdentity", "GitRefusal", "GitStore", "Plan", "cas_fast_forward", "commit_tested",
           "descriptor_support", "plan_merge", "plan_pick", "plan_revert", "snapshot_tree"]

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_MESSAGE_BYTES = 64 * 1024
MAX_PATH_BYTES = 4096
MAX_PATHS = 10000
MAX_PICKS = 256
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_OBJECTS = 20000
MAX_RESPONSE_BYTES = MAX_PATHS * (MAX_PATH_BYTES + 1)
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DATE = re.compile(r"[0-9]{1,12} [+-](?:[01][0-9]|2[0-3])[0-5][0-9]\Z")
_FORBIDDEN = re.compile(r"^\s*Aegis-(?:Approve(?:-Insight)?|Exempt-Test)\s*:", re.I | re.M)
class GitRefusal(gitsafe.GitError):
    """Stable library refusal. code is the machine-readable refusal, never stderr."""

    def __init__(self, code: str, *, next_action=None) -> None:
        actions = {"index_flags_unsupported": "Clear assume-unchanged and skip-worktree flags, then retry.",
                   "index_stat_unprovable": "Run `git update-index --refresh` in the worktree, then retry."}
        super().__init__("Lane Git operation refused: " + code, code=code, next_action=actions.get(code, next_action))


def _error_code(exc, default="git_failed"):
    code = getattr(exc, "code", "ERR_AEGIS")
    return code if (isinstance(code, str) and code != "ERR_AEGIS" and len(code) <= 64
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", code)) else default


def _owner_root(value, code):
    """Lexical identity before any metadata operation on a supplied service root."""
    if not isinstance(value, (str, Path)) or len(str(value)) > 16384 or "\0" in str(value):
        raise GitRefusal(code)
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise GitRefusal(code)
    return path


@dataclass(frozen=True)
class CommitIdentity:
    """Fixed author and committer identity/date, supplied by the trusted custodian."""

    name: str
    email: str
    date: str


@dataclass(frozen=True)
class Plan:
    status: str
    tree: Optional[str] = None
    commits: Tuple[str, ...] = ()
    conflicts: Tuple[str, ...] = ()


def descriptor_support() -> bool:
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.readlink in os.supports_dir_fd)


def _oid(value: str) -> str:
    if not isinstance(value, str) or len(value) not in (40, 64) or not _OID.fullmatch(value):
        raise GitRefusal("invalid_oid")
    return value


def _message(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > MAX_MESSAGE_BYTES:
        raise GitRefusal("invalid_message")
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        raise GitRefusal("invalid_message") from None
    if not data or len(data) > MAX_MESSAGE_BYTES or b"\0" in data or _FORBIDDEN.search(value):
        raise GitRefusal("invalid_message")
    return data


def _identity(value: CommitIdentity) -> dict:
    if not isinstance(value, CommitIdentity):
        raise GitRefusal("invalid_identity")
    for field in (value.name, value.email, value.date):
        if (not isinstance(field, str) or not field or len(field) > 256
                or any(ord(c) < 32 or 127 <= ord(c) < 160 or c in "\u2028\u2029" for c in field)
                or "<" in field or ">" in field):
            raise GitRefusal("invalid_identity")
    if not _DATE.fullmatch(value.date):
        raise GitRefusal("invalid_identity")
    try:
        (value.name + value.email).encode("utf-8")
    except UnicodeError:
        raise GitRefusal("invalid_identity") from None
    return {"GIT_AUTHOR_NAME": value.name, "GIT_AUTHOR_EMAIL": value.email,
            "GIT_COMMITTER_NAME": value.name, "GIT_COMMITTER_EMAIL": value.email,
            "GIT_AUTHOR_DATE": value.date, "GIT_COMMITTER_DATE": value.date}


def _display(raw: bytes) -> str:
    canonical = sanitize_display(os.fsdecode(raw), max_len=None)
    redacted = redact_insight_text(canonical, max_len=max(len(canonical), 1))
    return sanitize_display(redacted, max_len=240)


def _lane_operation(function):
    """Inject a transferable runner; callers cannot supply their own capability."""
    @wraps(function)
    def wrapped(store, *args, **kwargs):
        if not isinstance(store, GitStore):
            raise GitRefusal("store_closed")
        if function.__name__ != "__enter__":
            _require_active(store)
        if "_runner" in kwargs:
            raise GitRefusal("lane_runner_required")
        try:
            runner = store._lane if store._temp is not None else gitsafe.lane_runner(store.repo, store.scratch)
            return function(store, *args, _runner=runner, **kwargs)
        except AegisError as exc:
            raise GitRefusal(_error_code(exc), next_action=getattr(exc, "next_action", None)) from None
    return wrapped


def _require_runner(runner):
    if not isinstance(runner, gitsafe_run.LaneRunner):
        raise GitRefusal("lane_runner_required")


class GitStore:
    """Context-managed private index/objects, borrowing the trusted common store.

    repo must be the trusted worktree root. scratch is a fresh owner-controlled
    private directory outside the repository, with an empty objects/ subdirectory.
    Its provisioning and cleanup belong to the custody service. No model supplies
    either root. Methods are usable only inside the context.
    """

    def __init__(self, repo: Union[str, Path], scratch: Path) -> None:
        self.repo = _owner_root(repo, "invalid_repository")
        self.scratch = _owner_root(scratch, "unsafe_scratch")
        self._temp = None
        self._lane = None
        self.env = {}
        self._snapshot_lock = Lock()

    @_lane_operation
    def __enter__(self, *, _runner=None) -> GitStore:
        _require_runner(_runner)
        try:
            common, top, index_path = _runner.paths()
            if common is None or top is None or top.resolve() != self.repo.resolve():
                raise GitRefusal("invalid_repository")
            temp = self.scratch.resolve()
            if temp.is_relative_to(top.resolve()) or not temp.is_dir() or not (temp / "objects").is_dir():
                raise GitRefusal("unsafe_scratch")
            if os.name == "posix" and (temp.stat().st_mode & 0o077 or temp.stat().st_uid != os.getuid()):
                raise GitRefusal("unsafe_scratch")
            self._temp = temp
            self._lane = _runner
            self.index_path = _owner_root(index_path, "invalid_repository")
            self.env = _runner.environment()
            self._run(["read-tree", "--empty"])
            return self
        except OSError:
            self.__exit__(None, None, None)
            raise GitRefusal("git_failed") from None
        except (ValueError, RuntimeError):
            self.__exit__(None, None, None)
            raise GitRefusal("unsafe_scratch") from None
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args) -> None:
        self._temp = None
        self._lane = None
        self.env = {}

    @_lane_operation
    def _run(self, args: Sequence[str], *, stdin: Optional[bytes] = None,
            extra_env: Optional[dict] = None, allowed=(0,), stdout_limit=MAX_RESPONSE_BYTES, options=(), real_index=False, _runner=None):
        """Only the injected object's transport can reach Git."""
        _require_runner(_runner)
        result = _runner.run(args, self.repo, stdin=stdin, _env=extra_env,
                             stdout_limit=stdout_limit, options=options, real_index=real_index)
        if result.returncode not in allowed:
            raise GitRefusal("git_failed")
        return result

    @_lane_operation
    def object(self, oid: str, kind: str, *, max_bytes: Optional[int] = None, _runner=None) -> bytes:
        """Size before payload capture; only full validated ids reach cat-file."""
        _require_runner(_runner)
        oid = _oid(oid)
        if max_bytes is not None and (isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0):
            raise GitRefusal("invalid_object")
        limit = MAX_OBJECT_BYTES if max_bytes is None else min(MAX_OBJECT_BYTES, max_bytes)
        return _runner.read_private_object(self.repo, oid, kind=kind, max_bytes=limit)

    @_lane_operation
    def read_blob(self, tree: str, path: str, *, _runner=None) -> bytes:
        """Read an exact tree path from private objects, without filesystem opens."""
        _require_runner(_runner)
        _oid(tree)
        if not isinstance(path, str) or len(path) > MAX_PATH_BYTES or "\0" in path:
            raise GitRefusal("unsafe_path")
        try:
            path.encode("utf-8", "strict")
            _path_parts(os.fsencode(path))
        except UnicodeError:
            raise GitRefusal("unsafe_path") from None
        out = self._run(["ls-tree", "-z", tree, "--", ":(literal)" + path]).stdout
        meta, sep, found = out.partition(b"\t")
        if not sep or found != os.fsencode(path) + b"\0":
            raise GitRefusal("path_missing")
        fields = meta.split()
        if len(fields) != 3 or fields[1] != b"blob":
            raise GitRefusal("invalid_object")
        return self.object(fields[2].decode("ascii"), "blob")


def _require_active(store):
    if not isinstance(store, GitStore) or store._temp is None:
        raise GitRefusal("store_closed")


def _path_parts(raw: bytes) -> Tuple[str, ...]:
    if len(raw) > MAX_PATH_BYTES or not raw:
        raise GitRefusal("unsafe_path")
    parts = raw.split(b"/")
    if any(p in (b"", b".", b"..", b".git") or b"\0" in p
           or (os.name == "nt" and (b"\\" in p or b":" in p)) for p in parts):
        raise GitRefusal("unsafe_path")
    return tuple(os.fsdecode(p) for p in parts)


def _close_descriptors(descriptors):
    failed = False
    for fd in descriptors:
        try:
            os.close(fd)
        except OSError:
            failed = True
    if failed:
        raise GitRefusal("descriptor_cleanup_failed") from None


def _read_path(root_fd: int, raw: bytes, remaining: int):
    """Walk every parent by descriptor; never follow a symlink in any component."""
    parts = _path_parts(raw)
    opened = []
    current = root_fd
    observed = False
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            except OSError as exc:
                if exc.errno == errno.ENOTDIR:
                    parent = os.stat(part, dir_fd=current, follow_symlinks=False)
                    if stat.S_ISREG(parent.st_mode):
                        return None  # The old descendant was replaced by a file.
                raise
            current = child
            opened.append(current)
        before = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        observed = True
        if stat.S_ISDIR(before.st_mode):
            return None  # The old file is now a directory; its children are listed separately.
        if stat.S_ISLNK(before.st_mode):
            if before.st_size > min(MAX_PATH_BYTES, remaining):
                raise GitRefusal("size_limit")
            data = os.fsencode(os.readlink(parts[-1], dir_fd=current))
            after = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
                raise GitRefusal("worktree_changed")
            if len(data) > MAX_PATH_BYTES:
                raise GitRefusal("size_limit")
            return "120000", data, before
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        opened.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise GitRefusal("unsupported_file")
        limit = min(MAX_FILE_BYTES, remaining)
        if before.st_size > limit:
            raise GitRefusal("size_limit")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise GitRefusal("size_limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise GitRefusal("worktree_changed")
        mode = "100755" if before.st_mode & 0o100 else "100644"
        return mode, b"".join(chunks), before
    except FileNotFoundError:
        if observed:
            raise GitRefusal("worktree_changed") from None
        return None
    except OSError as exc:
        code = "unsafe_path" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "path_unreadable"
        raise GitRefusal(code) from None
    finally:
        _close_descriptors(reversed(opened))



_INDEX_STAT = re.compile(rb"  ctime: ([0-9]{1,20}):([0-9]{1,10})\n  mtime: ([0-9]{1,20}):([0-9]{1,10})\n"
    rb"  dev: ([0-9]{1,20})\tino: ([0-9]{1,20})\n  uid: ([0-9]{1,20})\tgid: ([0-9]{1,20})\n"
    rb"  size: ([0-9]{1,20})\tflags: ([0-9a-fA-F]{1,16})\n")


def _index_refuse(code="conversion_unavailable"):
    raise GitRefusal(code)


def _index_records(raw, *, max_paths, max_path_bytes, max_bytes):
    """Bound before parsing; select stage 0, otherwise Git's stage-2 baseline."""
    if type(raw) is not bytes or len(raw) > max_bytes or raw.count(b"\0") > max_paths * 3:
        _index_refuse("size_limit")
    grouped, position = {}, 0
    while position < len(raw):
        end = raw.find(b"\0", position, position + max_path_bytes + 84)
        if end < 0:
            _index_refuse("size_limit")
        meta, separator, path = raw[position:end].partition(b"\t")
        if not separator or len(meta) > 75 or not 1 <= len(path) <= max_path_bytes:
            _index_refuse()
        fields = meta.split(b" ")
        if (len(fields) != 3 or fields[0] not in (b"100644", b"100755", b"120000", b"160000")
                or _OID.fullmatch(fields[1].decode("ascii", "replace")) is None or fields[2] not in (b"0", b"1", b"2", b"3")):
            _index_refuse()
        stats = _INDEX_STAT.match(raw, end + 1, min(len(raw), end + 1 + 256))
        if stats is None:
            _index_refuse()
        cache = tuple(int(x) for x in stats.groups()[:-1]) + (int(stats.group(10), 16),)
        if any(x > 0xffffffff for x in cache) or cache[1] >= 1000000000 or cache[3] >= 1000000000:
            _index_refuse()
        stage = fields[2]
        flags = cache[9]
        if flags & ~0x6000f000 or flags & 0x3000 != int(stage) << 12:
            _index_refuse()
        if bool(flags & 0x4000) != bool(flags & 0x60000000) or flags & 0x20000000 and stage != b"0":
            _index_refuse()
        if flags & 0x40008000:
            _index_refuse("index_flags_unsupported")
        if path not in grouped and len(grouped) >= max_paths:
            _index_refuse("size_limit")
        stages = grouped.setdefault(path, {})
        if stage in stages:
            _index_refuse()
        stages[stage] = (fields[0].decode("ascii"), None if flags & 0x20000000 else fields[1].decode("ascii"), cache)
        position = stats.end()
    result = {}
    for path, stages in grouped.items():
        if b"0" in stages and len(stages) != 1:
            _index_refuse()
        if b"0" in stages:
            result[path] = stages[b"0"]
        else:
            mode = next(stages[s][0] for s in (b"2", b"1", b"3") if s in stages)
            result[path] = (mode, *stages.get(b"2", (None, None, None))[1:])
    return result


def _index_matches(cache, observed, settings, index_time):
    """Git's stat-clean shortcut, with racy mtimes treated as dirty."""
    if cache is None or index_time is None or cache[9] & 0x3000 or observed.st_mtime_ns >= index_time:
        return False
    ct, cn, mt, mn, dev, ino, uid, gid, size, _ = cache
    if mt != observed.st_mtime_ns // 1000000000 or size != observed.st_size:
        return False
    minimal = settings["checkstat"] == b"minimal"
    if not minimal and (ino, uid, gid) != tuple(x & 0xffffffff for x in
                            (observed.st_ino, observed.st_uid, observed.st_gid)):
        return False
    if not minimal and settings["trustctime"] != b"false" and ct != observed.st_ctime_ns // 1000000000:
        return False
    # USE_NSEC and USE_STDEV are build options Git does not expose. A mismatch
    # in these fields alone cannot prove whether Git would re-clean the bytes.
    if (observed.st_mtime_ns // 1000000000 == index_time // 1000000000 or not minimal and
            (mn != observed.st_mtime_ns % 1000000000 or dev != observed.st_dev & 0xffffffff
             or settings["trustctime"] != b"false" and cn != observed.st_ctime_ns % 1000000000)):
        return None
    return True


def _index_stamp(store):
    # This is the custodian-bound Git service index, not a model-selected path.
    # No content is opened here; worktree payloads still use the descriptor walk.
    try:
        observed = os.stat(store.index_path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(observed.st_mode):
        raise GitRefusal("unsafe_index")
    return (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)


_CONFIG_QUERY = r"^core\.(autocrlf|safecrlf|filemode|symlinks|eol|trustctime|checkstat)$"


def _eol_rule(values, settings):
    text = values["crlf"] if values["text"] == b"unspecified" else values["text"]
    if text not in (b"set", b"unset", b"auto", b"input", b"unspecified"):
        raise GitRefusal("conversion_unavailable")
    eol = values["eol"]
    if eol not in (b"lf", b"crlf", b"set", b"unset", b"unspecified"):
        raise GitRefusal("conversion_unavailable")
    action = "binary" if text == b"unset" else ("auto" if text == b"auto" else "text")
    if text == b"unspecified" and eol not in (b"lf", b"crlf"):
        action = "auto" if settings["autocrlf"] in (b"true", b"input") else "binary"
    output_crlf = settings["autocrlf"] == b"true" or (
        settings["autocrlf"] != b"input" and (settings["eol"] == b"crlf" or
        settings["eol"] in (b"", b"native") and os.name == "nt"))
    output_crlf = {b"lf": False, b"crlf": True}.get(eol, text != b"input" and output_crlf)
    encoding = values["working-tree-encoding"]
    return action, output_crlf, values["ident"] == b"set", encoding if encoding not in (b"unset", b"unspecified") else None


def _snapshot_rules(store, paths):
    for path in paths:
        _path_parts(path)
    names = ("filter", "text", "eol", "ident", "working-tree-encoding", "crlf")
    out = store._run(["check-attr", "-z", "--stdin", *names],
        real_index=True,
        stdin=b"".join(path + b"\0" for path in paths)).stdout
    if out.count(b"\0") != 3 * len(paths) * len(names) or (out and not out.endswith(b"\0")):
        raise GitRefusal("conversion_unavailable")
    attrs, rules = out.split(b"\0"), {}
    raw = store._run(["config", "--null", "--get-regexp", _CONFIG_QUERY], allowed=(0, 1), stdout_limit=4096).stdout
    settings = _conversion_settings(raw)
    for index, path in enumerate(paths):
        values = {}
        for offset, name in enumerate(names):
            position = (index * len(names) + offset) * 3
            found, attribute, value = attrs[position:position + 3]
            if found != path or attribute != name.encode():
                raise GitRefusal("conversion_unavailable")
            values[name] = value
        if values["filter"] not in (b"unspecified", b"unset"):
            raise GitRefusal("conversion_unavailable")
        rules[path] = _eol_rule(values, settings)
    length = 64 if store._run(["rev-parse", "--show-object-format"]).stdout.strip() == b"sha256" else 40
    return settings, rules, length


def _conversion_settings(raw):
    """Parse one bounded, NUL-framed config observation; no lenient bool coercion."""
    defaults = dict(autocrlf=b"false", safecrlf=b"false", filemode=b"true", symlinks=b"true",
                    eol=b"", trustctime=b"true", checkstat=b"default")
    if type(raw) is not bytes:
        _index_refuse()
    if len(raw) > 4096 or raw.count(b"\0") > 64 or raw and not raw.endswith(b"\0"):
        _index_refuse()
    for record in raw.split(b"\0")[:-1]:
        key, sep, value = record.partition(b"\n")
        if not key.startswith(b"core.") or len(value) > 32:
            _index_refuse()
        name = key[5:].decode("ascii", "replace").lower()
        if name not in defaults:
            _index_refuse()
        boolean = name in ("filemode", "symlinks", "trustctime", "autocrlf", "safecrlf")
        if not sep and not boolean and name != "eol":
            _index_refuse()
        value = value.lower() if sep else b"true" if boolean else b""
        if name == "eol" and value not in (b"lf", b"crlf", b"native"):
            value = b""
        if name in ("filemode", "symlinks", "trustctime", "autocrlf", "safecrlf") and value not in (b"input", b"warn"):
            if value in (b"true", b"yes", b"on"):
                value = b"true"
            elif value in (b"false", b"no", b"off", b""):
                value = b"false"
            elif re.fullmatch(rb"[+-]?[0-9]{1,16}", value):
                if not -2147483648 <= int(value) <= 2147483647:
                    _index_refuse()
                value = b"true" if int(value) else b"false"
            else:
                _index_refuse()
        allowed = ((b"false", b"true", b"input") if name == "autocrlf" else
                   (b"false", b"true", b"warn") if name == "safecrlf" else
                   (b"", b"lf", b"crlf", b"native") if name == "eol" else
                   (b"default", b"minimal") if name == "checkstat" else (b"true", b"false"))
        if value not in allowed:
            _index_refuse()
        defaults[name] = value
    return defaults


def _binary_text(data):
    """Git convert.c's byte statistics, including bare CR and terminal DOS EOF."""
    crlf = data.count(b"\r\n")
    if b"\0" in data or data.count(b"\r") != crlf:
        return True
    nonprintable = sum(data.count(bytes((c,))) for c in (*range(8), 11, *range(14, 27), *range(28, 32), 127))
    printable = len(data) - nonprintable - data.count(b"\r") - data.count(b"\n")
    nonprintable -= data.endswith(b"\x1a")
    return (printable >> 7) < nonprintable


def _clean_eol(data, rule, preserve, safe):
    action, output_crlf, _, _ = rule
    if action == "binary" or not data:
        return data
    crlf, lone_lf = data.count(b"\r\n"), data.count(b"\n") - data.count(b"\r\n")
    automatic = action == "auto"
    if automatic and _binary_text(data):
        return data
    convert = bool(crlf) and not (automatic and preserve)
    # Simulate the round trip exactly where git add would refuse core.safecrlf.
    checkout_crlf = output_crlf and not (automatic and not convert and crlf)
    if safe == b"true" and ((crlf and convert and not output_crlf) or (lone_lf and checkout_crlf)):
        raise GitRefusal("conversion_unavailable")
    return data.replace(b"\r\n", b"\n") if convert else data


def _clean_bytes(data, rule, preserve, safe):
    data = _clean_eol(data, rule, preserve, safe)
    return re.sub(rb"\$Id:[^\n$]*\$", b"$Id$", data) if rule[2] else data


def _decode_worktree(data, rule, limit):
    """Decode the resolved index/worktree rule, without re-resolving attributes."""
    encodings = {b"UTF-8": "utf-8", b"UTF-16": "utf-16", b"UTF-16LE": "utf-16-le",
              b"UTF-16BE": "utf-16-be", b"UTF-32": "utf-32", b"UTF-32LE": "utf-32-le",
              b"UTF-32BE": "utf-32-be", b"ASCII": "ascii", b"ISO-8859-1": "latin-1",
              b"LATIN1": "latin-1", b"SHIFT_JIS": "shift_jis", b"CP1252": "cp1252"}
    if len(rule[3]) > 32 or rule[3].upper() not in encodings:
        raise GitRefusal("conversion_unavailable")
    encoding = rule[3].upper()
    if (encoding in (b"UTF-16LE", b"UTF-16BE") and data.startswith((b"\xff\xfe", b"\xfe\xff"))
        or encoding in (b"UTF-32LE", b"UTF-32BE") and data.startswith((b"\xff\xfe\0\0", b"\0\0\xfe\xff"))):
        raise GitRefusal("conversion_unavailable")
    decoder = codecs.getincrementaldecoder(encodings[encoding])()
    encoder = codecs.getincrementalencoder("shift_jis")() if encoding == b"SHIFT_JIS" else None
    chunks, size, offset = [], 0, 0
    try:
        for start in range(0, max(1, len(data)), 65536):
            final = start + 65536 >= len(data)
            text = decoder.decode(data[start:start + 65536], final=final)
            if encoder is not None:
                text = text.replace("\\", "\u00a5").replace("~", "\u203e")
                raw = encoder.encode(text, final=final)
                if raw != data[offset:offset + len(raw)]:
                    raise GitRefusal("conversion_unavailable")
                offset += len(raw)
            count = sum(1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4 for c in text)
            if count > limit - size:
                raise GitRefusal("size_limit")
            chunks.append(text.encode("utf-8"))
            size += count
    except UnicodeError:
        raise GitRefusal("conversion_unavailable") from None
    return b"".join(chunks)


def _index_clean(mode, data, observed, prior, settings, oid_length, index_time):
    prior_mode, prior_oid, cache = prior
    if cache and cache[8] == 0 and prior_oid != object_id(b"", oid_length):
        return False
    same_mode = (mode == prior_mode or mode in ("100644", "100755") and
        (prior_mode == "120000" and settings["symlinks"] == b"false"
         or prior_mode in ("100644", "100755") and settings["filemode"] == b"false"))
    return _index_matches(cache, observed, settings, index_time) if prior_oid and same_mode else False


def _snapshot_contents(store, root_fd, paths, baseline, rules, settings, oid_length, index_time):
    contents, total = [], 0
    for path in paths:
        if baseline.get(path, ("100644", None, None))[0] == "160000":
            raise GitRefusal("unsupported_file")
        entry = _read_path(root_fd, path, MAX_SNAPSHOT_BYTES - total)
        if entry is None:
            continue
        mode, data, observed = entry
        original_size = len(data)
        if mode != "120000" and rules[path][3]:
            prior = baseline.get(path, ("100644", None, None))
            if not _index_clean(mode, data, observed, prior, settings, oid_length, index_time):
                data = _decode_worktree(data, rules[path], min(MAX_FILE_BYTES, MAX_SNAPSHOT_BYTES - total))
        total += max(original_size, len(data))
        if total > MAX_SNAPSHOT_BYTES:
            raise GitRefusal("size_limit")
        contents.append((path, mode, data, observed))
    return contents


def _snapshot_baselines(store, contents, baseline, rules, runner):
    _require_runner(runner)
    wanted = [baseline[path][1] for path, mode, data, _ in contents if mode != "120000"
              and b"\r\n" in data and rules[path][0] == "auto" and path in baseline and baseline[path][1]]
    objects = runner.read_private_objects(store.repo, wanted, max_bytes=MAX_SNAPSHOT_BYTES,
        max_object_bytes=MAX_OBJECT_BYTES)
    if any(kind != "blob" for kind, _ in objects.values()):
        raise GitRefusal("invalid_object")
    return {p for p, (_, oid, _) in baseline.items() if oid in objects
            and b"\r\n" in objects[oid][1] and not _binary_text(objects[oid][1])}


def _snapshot_entries(contents, settings, baseline, rules, preserved, oid_length, index_time):
    entries = []
    for path, mode, data, observed in contents:
        prior = baseline.get(path, ("100644", None, None))
        prior_mode = prior[0]
        unchanged = _index_clean(mode, data, observed, prior, settings, oid_length, index_time)
        if unchanged:
            entries.append((path, prior_mode, prior[1], None))
            continue
        if mode != "120000" and not unchanged:
            data = _clean_bytes(data, rules[path], path in preserved, settings["safecrlf"])
        if mode != "120000":
            if prior_mode == "120000" and settings["symlinks"] == b"false":
                mode = "120000"
            elif settings["filemode"] == b"false":
                mode = prior_mode if prior_mode in ("100644", "100755") else "100644"
        oid = object_id(data, oid_length)
        if unchanged is None and oid != prior[1]:
            raise GitRefusal("index_stat_unprovable")
        entries.append((path, mode, oid, data))
    return entries


def _blob_pack(blobs, oid_length):
    """One bounded, non-delta pack; Git alone writes the private object paths."""
    pack = bytearray(b"PACK" + (2).to_bytes(4, "big") + len(blobs).to_bytes(4, "big"))
    for data in blobs.values():
        size = len(data)
        bound = size + (size >> 12) + (size >> 14) + (size >> 25) + 13
        if len(pack) + 10 + bound + oid_length // 2 > MAX_SNAPSHOT_BYTES:
            raise GitRefusal("size_limit")
        header = bytearray()
        value = 0x30 | (size & 15)
        size >>= 4
        while size:
            header.append(value | 0x80)
            value, size = size & 127, size >> 7
        header.append(value)
        pack.extend(header)
        pack.extend(zlib.compress(data))
    digest = (hashlib.sha256 if oid_length == 64 else hashlib.sha1)(pack).digest()
    pack.extend(digest)
    return bytes(pack)


def _write_snapshot(store, entries, runner):
    _require_runner(runner)
    known = runner.private_object_headers(store.repo, [oid for _, _, oid, data in entries])
    records, missing = [], {}
    for path, mode, oid, data in entries:
        if data is None and (known[oid] is None or known[oid][0] != "blob" or known[oid][1] > MAX_OBJECT_BYTES):
            raise GitRefusal("invalid_object")
        if data is not None:
            info = known[oid]
            if info is not None and info != ("blob", len(data)):
                raise GitRefusal("invalid_object")
            if info is None:
                missing[oid] = data
        records.append(mode.encode() + b" " + oid.encode() + b"\t" + path + b"\0")
    if missing:
        pack = _blob_pack(missing, len(next(iter(missing))))
        store._run(["unpack-objects", "-q", "--strict"], stdin=pack)
    store._run(["update-index", "-z", "--index-info"], stdin=b"".join(records))
    return _oid(store._run(["write-tree"]).stdout.decode().strip())


@_lane_operation
def snapshot_tree(store: GitStore, *, _runner=None) -> str:
    """Snapshot tracked and nonignored paths, preserving the real index and refs.

    Missing files are deletions. A replacement symlink in a parent is refused;
    a symlink leaf records its link text, never the target's bytes. Fresh private
    index reconstruction makes retry independent of prior failures or staging.
    """
    _require_runner(_runner)
    if not descriptor_support():
        raise GitRefusal("unsupported_platform")
    if not store._snapshot_lock.acquire(blocking=False):
        raise GitRefusal("store_busy")
    root_fd = None
    try:
        root_fd = os.open(store.repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        index_stamp = _index_stamp(store)
        listing = store._run(["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                             real_index=True).stdout
        tracked = store._run(["ls-files", "--stage", "--debug", "-z"],
                             real_index=True)
        if tracked.returncode:
            raise GitRefusal("git_failed")
        baseline = _index_records(tracked.stdout, max_paths=MAX_PATHS, max_path_bytes=MAX_PATH_BYTES,
                                  max_bytes=MAX_RESPONSE_BYTES)
        for path in baseline:
            _path_parts(path)
        tracked = b"".join(path + b"\0" for path in baseline)
        paths = set()
        for source in (listing, tracked):
            if len(source) > MAX_RESPONSE_BYTES or source.count(b"\0") > MAX_PATHS:
                raise GitRefusal("size_limit")
            for path in source.split(b"\0"):
                if path and path not in paths:
                    if len(paths) >= MAX_PATHS:
                        raise GitRefusal("size_limit")
                    paths.add(path)
        paths = sorted(paths)
        settings, rules, length = _snapshot_rules(store, paths)
        contents = _snapshot_contents(store, root_fd, paths, baseline, rules, settings, length,
                                      index_stamp[3] if index_stamp else None)
        preserved = _snapshot_baselines(store, contents, baseline, rules, _runner)
        entries = _snapshot_entries(contents, settings, baseline, rules, preserved, length,
                                    index_stamp[3] if index_stamp else None)
        if _index_stamp(store) != index_stamp:
            raise GitRefusal("worktree_changed")
        store._run(["read-tree", "--empty"])
        return _write_snapshot(store, entries, _runner)
    except OSError:
        raise GitRefusal("path_unreadable") from None
    finally:
        try:
            if root_fd is not None:
                _close_descriptors((root_fd,))
        finally:
            store._snapshot_lock.release()


@_lane_operation
def commit_tested(store: GitStore, tree: str, parent: Union[str, Sequence[str]],
                  message: str, identity: CommitIdentity, *, _runner=None) -> str:
    """Unsigned deterministic commit of exactly tree; no index refresh or ref move."""
    _require_runner(_runner)
    data, env = _message(message), _identity(identity)
    tree = _oid(tree)
    parents = (parent,) if isinstance(parent, str) else parent
    if not isinstance(parents, (tuple, list)) or not 1 <= len(parents) <= 8:
        raise GitRefusal("invalid_parent")
    args = ["commit-tree", tree]
    for oid in parents:
        args.extend(("-p", _oid(oid)))
    store.object(tree, "tree")
    for oid in parents:
        store.object(oid, "commit")
    return _oid(store._run(args, stdin=data, extra_env=env).stdout.decode().strip())


def _check_ref(store: GitStore, ref: str) -> None:
    if (not isinstance(ref, str) or len(ref) > 240 or not ref.startswith(("refs/heads/lane/", "refs/aegis/"))
            or any(ord(c) < 33 or ord(c) > 126 for c in ref)):
        raise GitRefusal("ref_not_allowed")
    if (any(c in ref for c in "~^:?*[\\") or ".." in ref or "@{" in ref
            or any(not p or p.startswith(".") or p.endswith((".", ".lock")) for p in ref.split("/"))):
        raise GitRefusal("ref_not_allowed")
    if store._run(["check-ref-format", ref], allowed=(0, 1)).returncode:
        raise GitRefusal("ref_not_allowed")


def _current(store: GitStore, ref: str, runner) -> Optional[str]:
    _require_runner(runner)
    try:
        return runner.read_ref(store.repo, ref)
    except AegisError as exc:
        raise GitRefusal(_error_code(exc, "ref_unreadable"), next_action=getattr(exc, "next_action", None)) from None


def _publish(store: GitStore, new: str, runner) -> None:
    """Copy private reachable objects through Git only; never walk writable paths."""
    _require_runner(runner)
    listing = store._run(["rev-list", "--objects", "--no-object-names", new, "--not", "--all"]).stdout
    if len(listing) > MAX_OBJECTS * 65 or listing.count(b"\n") > MAX_OBJECTS:
        raise GitRefusal("size_limit")
    objects = [_oid(raw.decode("ascii")) for raw in listing.splitlines()]
    runner.read_private_objects(store.repo, objects, max_bytes=MAX_SNAPSHOT_BYTES,
        max_object_bytes=MAX_OBJECT_BYTES)
    if not objects:
        return
    request = ("\n".join(objects) + "\n").encode("ascii")
    pack = runner.run(["pack-objects", "--stdout"], store.repo, stdin=request,
                      stdout_limit=MAX_SNAPSHOT_BYTES)
    if pack.returncode:
        raise GitRefusal("git_failed")
    result = runner.publish(pack.stdout, shared=True)
    if result.returncode:
        raise GitRefusal("git_failed")


@_lane_operation
def cas_fast_forward(store: GitStore, ref: str, expected: Optional[str], new: str, *, _runner=None) -> str:
    """Sole ref writer: allowlist + expected OID + ancestry, then atomic CAS.

    None is create-only. Returns updated or already (including lost acknowledgments
    observed at new). Mismatch/non-fast-forward refusals publish no objects. A race
    after validation can leave unreachable objects, but can never overwrite a winner.
    Other failures include cas_mismatch, ref_unreadable, ref_update_failed or ref_update_unknown;
    the latter requires observation by the caller, never a blind retry.
    """
    _require_runner(_runner)
    _check_ref(store, ref)
    new = _oid(new)
    if expected is not None:
        _oid(expected)
    current = _current(store, ref, _runner)
    if current != expected and current != new:
        raise GitRefusal("cas_mismatch")
    store.object(new, "commit")
    if expected is not None:
        store.object(expected, "commit")
        if store._run(["merge-base", "--is-ancestor", expected, new], allowed=(0, 1)).returncode:
            raise GitRefusal("not_fast_forward")
    if current == new:
        return "already"
    _publish(store, new, _runner)
    try:
        status = _runner.cas(ref, new, expected)
        if status == "already":
            return "already"
    except AegisError as exc:
        code = _error_code(exc)
        if code not in ("git_failed", "git_timeout", "ref_update_unknown", "ref_update_failed",
                        "git_cleanup_failed", "git_output_limit"):
            raise GitRefusal(_error_code(exc), next_action=getattr(exc, "next_action", None)) from None
        observed = _current(store, ref, _runner)
        if observed == new:
            return "already"
        if observed != expected:
            raise GitRefusal("cas_mismatch") from None
        if code == "ref_update_failed" or (code == "git_failed" and getattr(exc, "process_started", None) is False):
            raise GitRefusal("ref_update_failed") from None
        raise GitRefusal("ref_update_unknown") from None
    return "updated"


def _merge_flags(store: GitStore) -> tuple:
    """Version gate only; the runner owns the external-program checks."""
    raw = store._run(["version"], stdout_limit=256).stdout
    version = re.match(rb"git version ([0-9]{1,6})\.([0-9]{1,6})(?:\.|\s|$)", raw)
    if version is None or tuple(map(int, version.groups())) < gitsafe.MERGE_TREE_MIN_VERSION[:2]:
        raise GitRefusal("merge_unavailable")
    return ()


def _merge(store: GitStore, tip: str, head: str, base: Optional[str] = None) -> Plan:
    _oid(tip)
    _oid(head)
    if base is not None:
        _oid(base)
    flags = _merge_flags(store)
    args = ["merge-tree", "--write-tree", "--name-only", "-z"]
    if base is not None:
        args.append("--merge-base=" + base)
    args.extend((tip, head))
    result = store._run(args, options=flags, allowed=(0, 1, 129))
    if result.returncode == 129:
        raise GitRefusal("merge_unavailable")
    if len(result.stdout) > MAX_PATHS * (MAX_PATH_BYTES + 1):
        raise GitRefusal("size_limit")
    fields = result.stdout.split(b"\0")
    if not fields:
        raise GitRefusal("invalid_object")
    tree = _oid(fields[0].decode("ascii"))
    if result.returncode == 0:
        return Plan("clean", tree)
    paths = []
    for path in fields[1:]:
        if not path:
            break
        if len(paths) >= MAX_PATHS or len(path) > MAX_PATH_BYTES:
            raise GitRefusal("size_limit")
        paths.append(_display(path))
    return Plan("conflict", conflicts=tuple(paths))


@_lane_operation
def plan_merge(store: GitStore, tip: str, head: str, *, _runner=None) -> Plan:
    """Plan the merge without updating refs, index or worktree."""
    _require_runner(_runner)
    return _merge(store, tip, head)


def _parents(store: GitStore, commit: str) -> Tuple[str, ...]:
    data = store.object(_oid(commit), "commit")
    end = data.find(b"\n\n", 0, MAX_MESSAGE_BYTES + 1)
    if end < 0:
        raise GitRefusal("invalid_object")
    try:
        return tuple(_oid(line[7:].decode("ascii")) for line in data[:end].splitlines() if line.startswith(b"parent "))
    except UnicodeError:
        raise GitRefusal("invalid_object") from None


def _pick_sources(store: GitStore, sources: Sequence[str]) -> Tuple[str, ...]:
    if not isinstance(sources, (tuple, list)) or not 1 <= len(sources) <= MAX_PICKS:
        raise GitRefusal("invalid_picks")
    expanded = []
    for source in sources:
        parents = _parents(store, source)
        if len(parents) > 2 or not parents:
            raise GitRefusal("invalid_picks")
        if len(parents) == 2:
            result = store._run(["rev-list", "--reverse", "--topo-order", "--no-merges",
                                parents[0] + ".." + parents[1]]).stdout
            if len(result) > MAX_PICKS * 65:
                raise GitRefusal("size_limit")
            expanded.extend(_oid(line.decode("ascii")) for line in result.splitlines())
        else:
            expanded.append(source)
        if len(expanded) > MAX_PICKS:
            raise GitRefusal("size_limit")
    if not expanded:
        raise GitRefusal("invalid_picks")
    return tuple(expanded)


@_lane_operation
def plan_pick(store: GitStore, tip: str, sources: Sequence[str], identity: CommitIdentity, *, _runner=None) -> Plan:
    """Apply sources oldest first, with fresh parentage and provenance trailers.

    Merge sources expand to M^1..M^2 without merges. The first conflict returns
    paths and no commits. All intermediate objects remain private, even on failure.
    """
    _require_runner(_runner)
    _oid(tip)
    _identity(identity)
    commits = []
    for source in _pick_sources(store, sources):
        parents = _parents(store, source)
        if len(parents) != 1:
            raise GitRefusal("invalid_picks")
        plan = _merge(store, tip, source, base=parents[0])
        if plan.status == "conflict":
            return plan
        data = store.object(source, "commit")
        start = data.find(b"\n\n", 0, MAX_MESSAGE_BYTES + 1) + 2
        trailer = "\n\n(cherry picked from commit " + source + ")\n"
        if start < 2 or len(data) - start > MAX_MESSAGE_BYTES - len(trailer):
            raise GitRefusal("invalid_message")
        try:
            message = data[start:].decode("utf-8")
        except UnicodeError:
            raise GitRefusal("invalid_message") from None
        message = message.rstrip("\n") + trailer
        tip = commit_tested(store, plan.tree, tip, message, identity)
        if tip == source:
            raise GitRefusal("pick_not_fresh")
        commits.append(tip)
    return Plan("clean", plan.tree, tuple(commits))


@_lane_operation
def plan_revert(store: GitStore, tip: str, merge: str, *, _runner=None) -> Plan:
    """Mainline-1 revert: merge-tree --merge-base=M tip M^1, without ref writes."""
    _require_runner(_runner)
    parents = _parents(store, merge)
    if len(parents) != 2:
        raise GitRefusal("not_merge")
    return _merge(store, tip, parents[0], base=merge)
