"""Model-free lane Git plumbing. No CLI, policy decisions, hooks or worktree writes.

The custodian supplies a trusted repository root and scratch parent (never a model
payload), and retains a GitStore until its objects have been consumed. Snapshots,
commits and planners write only into that store. Only cas_fast_forward publishes
objects and updates a ref; callers must journal that effect before calling it.
Unacknowledged writes are observed, never retried here. Qualification, lease and
identity authorization belong to the caller, not this low-level library.

Snapshots resolve attributes from captured source bytes in a private Git tree,
then apply Git text conversions to descriptor-read bytes. Filter attributes
(including LFS) are inert only with zero configured drivers; otherwise filter
states and attribute-source tokens refuse. Unsupported descriptor platforms refuse snapshots, but can plan and
commit already supplied trees. Submodules and special files refuse explicitly.
All refusals have a stable code and a constant, input-free message. Conflict labels
are canonicalized, redacted, then truncated; exact path bytes stay beside them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
import errno
import os
from pathlib import Path
import re
import stat
from sys import exc_info
from threading import Lock
from types import MappingProxyType
from typing import Optional, Sequence, Tuple, Union

from aegis_core import gitsafe, gitsafe_policy, gitsafe_run, team_git_snapshot
from aegis_core.errors import AegisError
from aegis_core.team_git_snapshot import (
    GitRefusal, conversion_settings as _conversion_settings, decode_worktree as _decode_worktree,
    index_clean as _index_clean, index_records as _index_records, snapshot_entries as _snapshot_entries,
)
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text

__all__ = ["CommitIdentity", "GitRefusal", "GitStore", "Plan", "UNKNOWN_OUTCOME_CODES",
           "cas_fast_forward", "commit_tested",
           "descriptor_support", "ref_oid", "plan_merge", "plan_pick", "plan_revert", "snapshot_tree",
           "validate_oid", "validate_message", "object_read_argv", "object_read_env",
           "MAX_OBJECT_READ_ENV_ENTRIES",
           # Export the internal runner-transfer surface for the lane guard's accounting.
           "_current", "_publish", "_require_runner", "_snapshot_baselines", "_snapshot_fallback_objects", "_write_snapshot"]

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_MESSAGE_BYTES = 64 * 1024
MAX_PATH_BYTES = 4096
MAX_PATHS = 10000
MAX_PICKS = 256
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_OBJECTS = 20000
MAX_RESPONSE_BYTES = MAX_PATHS * (MAX_PATH_BYTES + 1)
MAX_OBJECT_READ_ENV_ENTRIES = 512
_WINDOWS_OBJECT_READ_ENV = (
    "SYSTEMROOT",  # Windows process startup, including side-by-side assemblies.
    "WINDIR",      # Windows system-directory lookup at process startup.
    "TEMP",        # Windows temporary-directory selection.
    "TMP",         # Alternate Windows temporary-directory selection.
)
# One indeterminate-outcome set. Custody imports this object and never retries these codes.
UNKNOWN_OUTCOME_CODES = frozenset(("ref_update_unknown", "git_cleanup_failed", "git_timeout", "git_output_limit"))
_OID = team_git_snapshot.OID_PATTERN
_DATE = re.compile(r"[0-9]{1,12} [+-](?:[01][0-9]|2[0-3])[0-5][0-9]\Z")
_FORBIDDEN = re.compile(r"^\s*Aegis-(?:Approve(?:-Insight)?|Exempt-Test)\s*:", re.I | re.M)


def object_read_argv(*arguments):
    """Return arguments without the program for gitsafe.run; caller owns bounds."""
    return ["--no-optional-locks", "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-c", "protocol.allow=never", *arguments]


def object_read_env(overrides=None, *, inherit_config=False, environ=None):
    """Build a fixed read policy with only the platform's startup keys from input."""
    action = "Supply bounded string environment entries, then retry the object read."
    if type(inherit_config) is not bool:
        raise GitRefusal("invalid_environment", next_action=action)
    startup = _WINDOWS_OBJECT_READ_ENV if os.name == "nt" else ()
    source = {}
    try:
        for values in (os.environ if environ is None else environ, overrides):
            if values is None:
                continue
            if (type(values) not in (dict, MappingProxyType, gitsafe_policy.ENVIRON_TYPE)
                    or len(values) > MAX_OBJECT_READ_ENV_ENTRIES):
                raise GitRefusal("invalid_environment", next_action=action)
            # os.environ already canonicalizes Windows names. Avoid its whole-map key snapshot.
            keys = (key for key in startup if key in values) if type(values) is gitsafe_policy.ENVIRON_TYPE else values
            for count, key in enumerate(keys, 1):
                if (count > MAX_OBJECT_READ_ENV_ENTRIES or type(key) is not str or not key
                        or len(key) > 256 or "=" in key or "\0" in key):
                    raise GitRefusal("invalid_environment", next_action=action)
                value = values[key]
                if type(value) is not str or len(value) > 65536 or "\0" in value:
                    raise GitRefusal("invalid_environment", next_action=action)
                name = key.upper() if startup and key.isascii() else key
                if name in startup:
                    source[name] = value
            if len(values) > MAX_OBJECT_READ_ENV_ENTRIES:
                raise GitRefusal("invalid_environment", next_action=action)
    except (KeyError, RuntimeError):
        raise GitRefusal("invalid_environment", next_action=action) from None
    fixed = {**gitsafe_policy.BASE_ENV, "GIT_PROTOCOL_FROM_USER": "0"}
    if not inherit_config:
        fixed.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    source.update(fixed)
    return source


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
    paths: Tuple[bytes, ...] = field(default=(), repr=False)
    origin: str = "absent"
    certainty: str = "unknown"
    errno: Optional[int] = None
    exit_status: Optional[int] = None


def descriptor_support() -> bool:
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.readlink in os.supports_dir_fd)


def validate_oid(value: str) -> str:
    """Return one full object id or raise GitRefusal('invalid_oid'); no I/O."""
    if not isinstance(value, str) or len(value) not in (40, 64) or not _OID.fullmatch(value):
        raise GitRefusal("invalid_oid")
    return value


def validate_message(value: str) -> bytes:
    """Encode a bounded unsigned commit message or raise GitRefusal('invalid_message')."""
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


def _lane_operation(function=None, *, effect_aware=False, requires_active=True):
    """Declare runner policy; undeclared effects refuse as effect_runner_refused.

    Only store entry opts out of the active-store check. Callers cannot supply
    their own runner capability; effect-aware operations borrow descriptors.
    """
    if function is None:
        return lambda target: _lane_operation(target, effect_aware=effect_aware, requires_active=requires_active)
    @wraps(function)
    def wrapped(store, *args, **kwargs):
        if not isinstance(store, GitStore):
            raise GitRefusal("store_closed")
        if requires_active:
            _require_active(store)
        if "_runner" in kwargs:
            raise GitRefusal("lane_runner_required")
        if "effect_fds" in kwargs and not effect_aware:
            raise GitRefusal("effect_runner_refused")
        ambient = exc_info()[1]
        try:
            effect_fds = kwargs.get("effect_fds") if effect_aware else None
            runner = store._lane if store._temp is not None and effect_fds is None else gitsafe.lane_runner(
                store.repo, store.scratch, effect_fds=effect_fds, worktree_root=store.repo)
            return function(store, *args, _runner=runner, **kwargs)
        except AegisError as exc:
            raise GitRefusal(_error_code(exc), next_action=getattr(exc, "next_action", None),
                             **team_git_snapshot.failure_cause(exc, ambient)) from None
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

    @_lane_operation(requires_active=False)
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
        except OSError as exc:
            self.__exit__(None, None, None)
            raise GitRefusal("git_failed", errno=exc.errno) from None
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
            raise GitRefusal("git_failed", exit_status=result.returncode)
        return result

    @_lane_operation
    def object(self, oid: str, kind: str, *, max_bytes: Optional[int] = None, _runner=None) -> bytes:
        """Size before payload capture; only full validated ids reach cat-file."""
        _require_runner(_runner)
        oid = validate_oid(oid)
        if max_bytes is not None and (isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0):
            raise GitRefusal("invalid_object")
        limit = MAX_OBJECT_BYTES if max_bytes is None else min(MAX_OBJECT_BYTES, max_bytes)
        return _runner.read_private_object(self.repo, oid, kind=kind, max_bytes=limit)

    @_lane_operation
    def read_blob(self, tree: str, path: str, *, _runner=None) -> bytes:
        """Read an exact tree path from private objects, without filesystem opens."""
        _require_runner(_runner)
        validate_oid(tree)
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
    failure = None
    for fd in descriptors:
        try:
            os.close(fd)
        except OSError as exc:
            if failure is None or failure.errno is None:
                failure = exc
    if failure is not None:
        raise GitRefusal("descriptor_cleanup_failed", errno=failure.errno) from None


def _attribute_stamp(observed):
    return (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns)


def _read_path(root_fd: int, raw: bytes, remaining: int, *, attribute=False, attribute_charges=None,
               prior=None, settings=None, oid_length=40, index_time=None):
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
        if attribute and not stat.S_ISREG(before.st_mode):
            raise GitRefusal("conversion_unavailable")
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
            raise GitRefusal("conversion_unavailable" if attribute else "unsupported_file")
        # Metadata deduplicates the budget charge, never the descriptor read.
        charged = attribute and attribute_charges is not None and _attribute_stamp(before) in attribute_charges
        limit = min(MAX_FILE_BYTES, before.st_size if charged else remaining)
        if before.st_size > limit:
            raise GitRefusal("size_limit")
        mode = "100755" if before.st_mode & 0o100 else "100644"
        clean = prior is not None and _index_clean(mode, None, before, prior, settings, oid_length, index_time) is True
        chunks, total = [], 0
        while not clean:
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
        return mode, team_git_snapshot.STAT_CLEAN if clean else b"".join(chunks), before
    except FileNotFoundError as exc:
        if observed:
            code = "conversion_unavailable" if attribute else "worktree_changed"
            raise GitRefusal(code, errno=exc.errno) from None
        return None
    except OSError as exc:
        if attribute:
            if exc.errno == errno.ENOTDIR:
                return None
            raise GitRefusal("conversion_unavailable", errno=exc.errno) from None
        code = "unsafe_path" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "path_unreadable"
        raise GitRefusal(code, errno=exc.errno) from None
    finally:
        _close_descriptors(reversed(opened))



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


def _conversion_run(store, argv, **kw):
    """Map conversion-observation transport failures to the stable refusal."""
    ambient = exc_info()[1]
    try:
        return store._run(argv, **kw)
    except OSError as exc:
        raise GitRefusal("conversion_unavailable", errno=exc.errno) from None
    except AegisError as exc:
        if _error_code(exc) not in ("git_failed", "git_timeout", "git_output_limit", "git_cleanup_failed"):
            raise
        raise GitRefusal("conversion_unavailable", **team_git_snapshot.failure_cause(exc, ambient)) from None


def _snapshot_filters(store):
    result = _conversion_run(store, ["config", "--null", "--name-only", "--get-regexp", r"^filter\."],
                             allowed=(0, 1), stdout_limit=65536)
    return team_git_snapshot.filter_drivers(result.stdout, result.returncode)


def _snapshot_config(store):
    team_git_snapshot.attribute_version(_conversion_run(store, ["version"], stdout_limit=256).stdout)
    raw = store._run(["config", "--null", "--get-regexp", _CONFIG_QUERY], allowed=(0, 1), stdout_limit=4096).stdout
    settings = _conversion_settings(raw)
    filters = _snapshot_filters(store)
    length = 64 if store._run(["rev-parse", "--show-object-format"]).stdout.strip() == b"sha256" else 40
    return settings, length, filters


def _snapshot_rules(store, paths, tree, settings, filters):
    out = _conversion_run(store, [*gitsafe_policy.SNAPSHOT_SOURCE_PREFIX, tree, *gitsafe_policy.SNAPSHOT_ATTRIBUTES],
                          stdin=b"".join(path + b"\0" for path in paths)).stdout
    attrs = team_git_snapshot.snapshot_attributes(out, paths)
    return team_git_snapshot.snapshot_rules(paths, attrs, settings, native_crlf=os.name == "nt",
                                            configured_filters=filters)


def _snapshot_attribute_candidates(root_fd, paths):
    """Walk candidate directories once; only byte-budget charges may be reused."""
    name = b".gitattributes"
    captured, groups = {}, {}
    remaining, attribute_charges = MAX_SNAPSHOT_BYTES, {}
    directories, context_bytes = set(), 0
    frame = len(b"100644 ") + 64 + len(b"\t\0")
    for path in [b""] + paths:
        directory = path.rpartition(b"/")[0]
        if team_git_snapshot.is_attribute_path(path):
            groups.setdefault(directory, []).append(path)
        while directory not in directories:
            if len(directory) + bool(directory) + len(name) > MAX_PATH_BYTES:
                raise GitRefusal("conversion_unavailable")
            # Bound candidate metadata before storing each prefix. The frame
            # reserves a full SHA-256 index-info record, even for absent files.
            context_bytes += len(directory) + bool(directory) + len(name) + frame
            if context_bytes > MAX_RESPONSE_BYTES:
                raise GitRefusal("size_limit")
            directories.add(directory)
            if not directory:
                break
            directory = directory.rpartition(b"/")[0]
    # Trailing separators keep subtrees contiguous without allocating split
    # component keys for every prefix. Retain only the active chain,
    # rather than reopening every ancestor or retaining one fd per directory.
    opened, components, absent = [], (), None
    try:
        for directory in sorted(directories, key=lambda value: value + b"/"):
            parts = tuple(os.fsdecode(part) for part in directory.split(b"/")) if directory else ()
            common = 0
            while common < min(len(parts), len(components)) and parts[common] == components[common]:
                common += 1
            while len(opened) > common:
                _close_descriptors((opened.pop(),))
            components = components[:common]
            if absent is not None and (directory == absent or directory.startswith(absent + b"/")):
                continue
            absent = None
            for part in parts[common:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=opened[-1] if opened else root_fd)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                        absent = directory
                        break
                    raise GitRefusal("conversion_unavailable", errno=exc.errno) from None
                opened.append(child)
                components += (part,)
            if absent is not None:
                continue
            candidate = (directory + b"/" if directory else b"") + name
            for candidate in dict.fromkeys([*groups.get(directory, ()), candidate]):
                entry = _read_path(opened[-1] if opened else root_fd, candidate.rpartition(b"/")[2], remaining,
                    attribute=True, attribute_charges=attribute_charges)
                if entry is not None:
                    stamp = _attribute_stamp(entry[2])
                    previous = attribute_charges.get(stamp)
                    if previous is not None and previous != entry[1]:
                        raise GitRefusal("conversion_unavailable")
                    if previous is None:
                        remaining -= len(entry[1])
                    # Read every alias, then share equal immutable bytes. A
                    # reused budget charge must not retain another payload copy.
                    data = attribute_charges.setdefault(stamp, entry[1])
                    captured[candidate] = (entry[0], data, entry[2])
    finally:
        _close_descriptors(reversed(opened))
    return captured, remaining


def _snapshot_attribute_entries(captured, fallbacks, objects, remaining, length):
    sources = {path: entry[1] for path, entry in captured.items() if path.rpartition(b"/")[2] == b".gitattributes"}
    for path, oid in fallbacks.items():
        entry = objects.get(oid)
        if entry is None or entry[0] != "blob":
            raise GitRefusal("invalid_object")
        data = entry[1]
        if len(data) > min(MAX_FILE_BYTES, remaining):
            raise GitRefusal("size_limit")
        sources[path] = data
        remaining -= len(data)
    return team_git_snapshot.attribute_entries(sources, length), remaining


def _snapshot_fallback_objects(store, fallbacks, remaining, runner):
    """Fetch fallback attributes once, preserving object and aggregate budgets."""
    _require_runner(runner)
    if not fallbacks:
        return {}
    try:
        return runner.read_private_objects(store.repo, list(dict.fromkeys(fallbacks.values())),
            max_bytes=remaining, max_object_bytes=min(MAX_FILE_BYTES, MAX_OBJECT_BYTES))
    except AegisError as exc:
        if _error_code(exc) != "git_object_limit":
            raise
        raise GitRefusal("size_limit") from None


@_lane_operation
def _snapshot_rule_context(store, paths, entries, fallbacks, baseline, settings, filters, *, _runner=None):
    _require_runner(_runner)
    store._run(["read-tree", "--empty"])
    tree = _write_snapshot(store, entries, _runner)
    rules = _snapshot_rules(store, paths, tree, settings, filters)
    if not fallbacks:
        return rules
    # Native add can consult the old index before deleting an attribute entry.
    # Compare captured-only rules and admit only contexts whose order is proven.
    store._run(["read-tree", "--empty"])
    tree = _write_snapshot(store, [entry for entry in entries if entry[0] not in fallbacks], _runner)
    captured_rules = _snapshot_rules(store, paths, tree, settings, filters)
    return team_git_snapshot.deleted_attribute_rules(paths, baseline, fallbacks, rules, captured_rules)


def _snapshot_contents(store, root_fd, paths, baseline, rules, settings, oid_length, index_time, *, captured, remaining):
    contents, total = [], MAX_SNAPSHOT_BYTES - remaining
    for path in paths:
        if baseline.get(path, ("100644", None, None))[0] == "160000":
            raise GitRefusal("unsupported_file")
        is_attribute = team_git_snapshot.is_attribute_path(path)
        # Auto rules need current bytes to select baselines and preserve batch refusals.
        reuse = not is_attribute and rules[path][0] != "auto"
        entry = captured.get(path) if is_attribute else _read_path(root_fd, path, MAX_SNAPSHOT_BYTES - total,
            prior=baseline.get(path) if reuse else None, settings=settings, oid_length=oid_length, index_time=index_time)
        if entry is None:
            continue
        mode, data, observed = entry
        skipped = data is team_git_snapshot.STAT_CLEAN
        original_size = observed.st_size if skipped else len(data)
        if not skipped and mode != "120000" and rules[path][3]:
            prior = baseline.get(path, ("100644", None, None))
            if not _index_clean(mode, data, observed, prior, settings, oid_length, index_time):
                limit = MAX_SNAPSHOT_BYTES - total + (original_size if is_attribute else 0)
                data = _decode_worktree(data, rules[path], min(MAX_FILE_BYTES, limit))
        total += max(original_size, len(data) if not skipped else 0) - (original_size if is_attribute else 0)
        if total > MAX_SNAPSHOT_BYTES:
            raise GitRefusal("size_limit")
        contents.append((path, mode, data, observed))
    return contents


def _snapshot_baselines(store, contents, baseline, rules, runner, *, filters, attributes, prefetched=None):
    _require_runner(runner)
    prefetched = prefetched or {}
    wanted = team_git_snapshot.baseline_requests(contents, baseline, rules, configured_filters=filters)
    wanted = [oid for oid in wanted if oid not in prefetched]
    remaining = MAX_SNAPSHOT_BYTES - sum(len(data) for _, data in prefetched.values())
    objects = runner.read_private_objects(store.repo, wanted, max_bytes=remaining,
        max_object_bytes=MAX_OBJECT_BYTES) if wanted or not prefetched else {}
    objects = {**prefetched, **objects}
    if any(kind != "blob" for kind, _ in objects.values()):
        raise GitRefusal("invalid_object")
    team_git_snapshot.check_filter_sources(attributes, baseline, objects, configured_filters=filters)
    return team_git_snapshot.preserved_paths(baseline, objects)


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
        pack = team_git_snapshot.blob_pack(missing, len(next(iter(missing))), max_bytes=MAX_SNAPSHOT_BYTES)
        store._run(["unpack-objects", "-q", "--strict"], stdin=pack)
    if records:
        store._run(["update-index", "-z", "--index-info"], stdin=b"".join(records))
    return validate_oid(store._run(["write-tree"]).stdout.decode("ascii", "replace").strip())


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
        for path in paths:
            _path_parts(path)
        settings, length, filters = _snapshot_config(store)
        captured, remaining = _snapshot_attribute_candidates(root_fd, paths)
        if filters:
            for entry in captured.values():
                team_git_snapshot.check_filter_bytes(entry[1])
        fallbacks = team_git_snapshot.attribute_fallbacks(captured, baseline)
        fallback_objects = _snapshot_fallback_objects(store, fallbacks, remaining, _runner)
        if _index_stamp(store) != index_stamp:
            raise GitRefusal("worktree_changed")
        attribute_entries, remaining = _snapshot_attribute_entries(captured, fallbacks, fallback_objects, remaining, length)
        rules = _snapshot_rule_context(store, paths, attribute_entries, fallbacks, baseline, settings, filters)
        contents = _snapshot_contents(store, root_fd, paths, baseline, rules, settings, length,
            index_stamp[3] if index_stamp else None, captured=captured, remaining=remaining)
        attributes = [entry[1] for entry in captured.values()]
        preserved = _snapshot_baselines(store, contents, baseline, rules, _runner,
            filters=filters, attributes=attributes, prefetched=fallback_objects)
        entries = _snapshot_entries(contents, settings, baseline, rules, preserved, length,
                                    index_stamp[3] if index_stamp else None)
        if _index_stamp(store) != index_stamp:
            raise GitRefusal("worktree_changed")
        if _snapshot_filters(store) != filters:
            raise GitRefusal("conversion_unavailable")
        store._run(["read-tree", "--empty"])
        return _write_snapshot(store, entries, _runner)
    except OSError as exc:
        raise GitRefusal("path_unreadable", errno=exc.errno) from None
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
    data, env = validate_message(message), _identity(identity)
    tree = validate_oid(tree)
    parents = (parent,) if isinstance(parent, str) else parent
    if not isinstance(parents, (tuple, list)) or not 1 <= len(parents) <= 8:
        raise GitRefusal("invalid_parent")
    args = ["commit-tree", tree]
    for oid in parents:
        args.extend(("-p", validate_oid(oid)))
    store.object(tree, "tree")
    for oid in parents:
        store.object(oid, "commit")
    return validate_oid(store._run(args, stdin=data, extra_env=env).stdout.decode().strip())


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
    ambient = exc_info()[1]
    try:
        return runner.read_ref(store.repo, ref)
    except AegisError as exc:
        raise GitRefusal(_error_code(exc, "ref_unreadable"), next_action=getattr(exc, "next_action", None),
                         **team_git_snapshot.failure_cause(exc, ambient)) from None


@_lane_operation
def ref_oid(store: GitStore, ref: str, *, _runner=None) -> Optional[str]:
    """Read one exact fully-qualified ref, or None when it is absent.

    The active store binds executable, repository and capture limits. Git read
    failures retain GitRefusal codes; interpreting the object belongs to callers.
    """
    _require_runner(_runner)
    try:
        return _current(store, ref, _runner)
    except OSError as exc:
        raise GitRefusal("ref_unreadable", errno=exc.errno) from None


def _publish(store: GitStore, new: str, runner) -> None:
    """Copy private reachable objects through Git only; never walk writable paths."""
    _require_runner(runner)
    listing = store._run(["rev-list", "--objects", "--no-object-names", new, "--not", "--all"]).stdout
    if len(listing) > MAX_OBJECTS * 65 or listing.count(b"\n") > MAX_OBJECTS:
        raise GitRefusal("size_limit")
    objects = [validate_oid(raw.decode("ascii")) for raw in listing.splitlines()]
    runner.read_private_objects(store.repo, objects, max_bytes=MAX_SNAPSHOT_BYTES,
        max_object_bytes=MAX_OBJECT_BYTES)
    if not objects:
        return
    request = ("\n".join(objects) + "\n").encode("ascii")
    pack = runner.run(["pack-objects", "--stdout"], store.repo, stdin=request,
                      stdout_limit=MAX_SNAPSHOT_BYTES)
    if pack.returncode:
        raise GitRefusal("git_failed", exit_status=pack.returncode)
    result = runner.publish(pack.stdout, shared=True)
    if result.returncode:
        raise GitRefusal("git_failed", exit_status=result.returncode)


@_lane_operation(effect_aware=True)
def cas_fast_forward(store: GitStore, ref: str, expected: Optional[str], new: str, *, effect_fds=None, _runner=None) -> str:
    """Sole ref writer: allowlist + expected OID + ancestry, then atomic CAS.

    None is create-only. Returns updated or already (including lost acknowledgments
    observed at new). Mismatch/non-fast-forward refusals publish no objects. A race
    after validation can leave unreachable objects, but can never overwrite a winner.
    Other failures include cas_mismatch, ref_unreadable, ref_update_failed or ref_update_unknown;
    the latter requires observation by the caller, never a blind retry.
    effect_fds borrows an active receipt's exported descriptors for this operation
    only. Its custody holders retain the lock until all effect descendants exit;
    the caller still owns and closes the receipt. None preserves ordinary calls.
    With effect_fds, visible indeterminate capture failures stay unknown even if
    a ref observation could match new; the caller must reconcile under a fresh lock.
    """
    _require_runner(_runner)
    _check_ref(store, ref)
    new = validate_oid(new)
    if expected is not None:
        validate_oid(expected)
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
    ambient = exc_info()[1]
    try:
        status = _runner.cas(ref, new, expected)
        if status == "already":
            return "already"
    except AegisError as exc:
        code = _error_code(exc)
        cause = team_git_snapshot.failure_cause(exc, ambient)
        if code not in UNKNOWN_OUTCOME_CODES and code not in ("git_failed", "ref_update_failed"):
            raise GitRefusal(code, next_action=getattr(exc, "next_action", None), **cause) from None
        if (effect_fds is not None
                and (code in UNKNOWN_OUTCOME_CODES
                     or code == "git_failed" and getattr(exc, "process_started", None) is True)):
            raise GitRefusal("ref_update_unknown", **cause) from None
        observed = _current(store, ref, _runner)
        if observed == new:
            return "already"
        if observed != expected:
            raise GitRefusal("cas_mismatch") from None
        if code == "ref_update_failed" or (code == "git_failed" and getattr(exc, "process_started", None) is False):
            raise GitRefusal("ref_update_failed", **cause) from None
        raise GitRefusal("ref_update_unknown", **cause) from None
    return "updated"


def _merge_flags(store: GitStore) -> tuple:
    """Version gate only; the runner owns the external-program checks."""
    raw = store._run(["version"], stdout_limit=256).stdout
    version = re.match(rb"git version ([0-9]{1,6})\.([0-9]{1,6})(?:\.|\s|$)", raw)
    if version is None or tuple(map(int, version.groups())) < gitsafe.MERGE_TREE_MIN_VERSION[:2]:
        raise GitRefusal("merge_unavailable")
    return ()


def _merge(store: GitStore, tip: str, head: str, base: Optional[str] = None) -> Plan:
    validate_oid(tip)
    validate_oid(head)
    if base is not None:
        validate_oid(base)
    flags = _merge_flags(store)
    args = ["merge-tree", "--write-tree", "--name-only", "-z"]
    if base is not None:
        args.append("--merge-base=" + base)
    args.extend((tip, head))
    result = store._run(args, options=flags, allowed=(0, 1, 129))
    if result.returncode == 129:
        raise GitRefusal("merge_unavailable", exit_status=result.returncode)
    if len(result.stdout) > MAX_RESPONSE_BYTES:
        raise GitRefusal("size_limit")
    oid, start = team_git_snapshot.merge_tree_oid(result.stdout)
    tree = validate_oid(oid)
    if result.returncode == 0:
        return Plan("clean", tree)
    labels, exact = team_git_snapshot.conflict_paths(result.stdout, start, _display, MAX_PATHS, MAX_PATH_BYTES)
    return Plan("conflict", conflicts=labels, paths=exact, origin="conflict", certainty="confirmed")


@_lane_operation
def plan_merge(store: GitStore, tip: str, head: str, *, _runner=None) -> Plan:
    """Plan the merge without updating refs, index or worktree."""
    _require_runner(_runner)
    return _merge(store, tip, head)


def _parents(store: GitStore, commit: str, *, records=None) -> Tuple[str, ...]:
    commit = validate_oid(commit)
    if records is not None and commit in records:
        return records[commit][0]
    data = store.object(commit, "commit")
    end = data.find(b"\n\n", 0, MAX_MESSAGE_BYTES + 1)
    if end < 0:
        raise GitRefusal("invalid_object")
    try:
        parents = tuple(validate_oid(line[7:].decode("ascii")) for line in data[:end].splitlines() if line.startswith(b"parent "))
    except UnicodeError:
        raise GitRefusal("invalid_object") from None
    if records is not None:
        # Keep only bounded message bytes; refusal remains after the merge/conflict.
        limit = MAX_MESSAGE_BYTES - len("\n\n(cherry picked from commit " + commit + ")\n")
        records[commit] = (parents, data[end + 2:] if len(data) - end - 2 <= limit else None)
    return parents


def _pick_sources(store: GitStore, sources: Sequence[str], records) -> Tuple[str, ...]:
    if not isinstance(sources, (tuple, list)) or not 1 <= len(sources) <= MAX_PICKS:
        raise GitRefusal("invalid_picks")
    expanded = []
    for source in sources:
        parents = _parents(store, source, records=records)
        if len(parents) > 2 or not parents:
            raise GitRefusal("invalid_picks")
        if len(parents) == 2:
            result = store._run(["rev-list", "--reverse", "--topo-order", "--no-merges",
                                parents[0] + ".." + parents[1]]).stdout
            if len(result) > MAX_PICKS * 65:
                raise GitRefusal("size_limit")
            expanded.extend(validate_oid(line.decode("ascii")) for line in result.splitlines())
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
    validate_oid(tip)
    _identity(identity)
    commits, records = [], {}
    for source in _pick_sources(store, sources, records):
        parents = _parents(store, source, records=records)
        if len(parents) != 1:
            raise GitRefusal("invalid_picks")
        plan = _merge(store, tip, source, base=parents[0])
        if plan.status == "conflict":
            return plan
        data = records[source][1]
        trailer = "\n\n(cherry picked from commit " + source + ")\n"
        if data is None:
            raise GitRefusal("invalid_message")
        try:
            message = data.decode("utf-8")
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
